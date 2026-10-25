"""
FSV Module — DNS & Email-Authentication Security
────────────────────────────────────────────────
What this looks at, and why it is more than "is there an SPF record":

  SPF    10-lookup limit (PermError ⇒ SPF silently fails for ALL mail), multiple
         records, +all / ?all / missing all, and — the one that is almost never
         noticed — `include:` / `redirect=` domains that NO LONGER EXIST. Whoever
         registers that expired domain can publish their own SPF and become an
         authorised sender for yours.
  DMARC  p=none without reporting, subdomain policy (sp=) weaker than p=,
         pct<100, duplicate records.
  DKIM   common selectors; RSA key length (≤768-bit keys can be factored with
         modest hardware), testing mode (t=y).
  MTA-STS  policy published and reachable, mode.
  NS/MX  delegated nameservers / mail exchangers that do not resolve.
  CAA / DNSSEC  presence.

Everything is read-only DNS plus (for MTA-STS) one HTTPS GET to the domain's own
mta-sts host. Detection only.
"""

from __future__ import annotations
import asyncio
import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Callable
from urllib.parse import urlparse

from fsv.core import dnsutil
from fsv.core.dnsutil import Answer
from fsv.core.models import Finding, Severity, Confidence
from fsv.core.netsafety import registrable_domain
from fsv.core.scanner import BaseScanner


# ── SPF ───────────────────────────────────────────────────────────────────────

_SPF_LOOKUP_MECHS = ("include", "a", "mx", "ptr", "exists")


@dataclass
class SPFReport:
    records:      list[str] = field(default_factory=list)   # v=spf1 TXT at the apex
    lookups:      int = 0
    dangling:     list[tuple[str, str]] = field(default_factory=list)  # (via, domain) NXDOMAIN
    no_spf:       list[tuple[str, str]] = field(default_factory=list)  # (via, domain) exists, no SPF
    all_qualifier: str | None = None       # '+', '-', '~', '?' ; None = no `all`
    uses_ptr:     bool = False
    truncated:    bool = False             # recursion cap hit — counts are a lower bound


def _spf_records(ans: Answer) -> list[str]:
    return [t.strip() for t in ans.records if t.lower().lstrip().startswith("v=spf1")]


def analyze_spf(domain: str, txt: Callable[[str], Answer], max_depth: int = 8) -> SPFReport:
    """
    Walk an SPF record the way a receiving MTA does, counting DNS-querying terms
    (RFC 7208 §4.6.4: more than 10 ⇒ PermError) and recording include/redirect
    targets that do not exist.
    """
    rep = SPFReport()
    seen: set[str] = set()

    def walk(dom: str, depth: int, top: bool, via: str) -> str | None:
        """Returns the `all` qualifier of this record (or of its redirect target)."""
        if depth > max_depth:
            rep.truncated = True
            return None
        key = dom.lower()
        if key in seen:                       # include loop → PermError in real MTAs
            return None
        seen.add(key)

        ans = txt(dom)
        if ans.nxdomain:
            rep.dangling.append((via, dom))
            return None
        recs = _spf_records(ans)
        if top:
            rep.records = recs
        if not recs:
            if not top and ans.status in ("ok", "nodata"):
                rep.no_spf.append((via, dom))
            return None
        record = recs[0]

        qualifier: str | None = None
        redirect: str | None = None
        for term in record.split()[1:]:
            t = term.lower()
            if t.startswith("redirect="):
                redirect = term.split("=", 1)[1]
                continue
            if "=" in t.split(":")[0] and not t.startswith(("+", "-", "~", "?")):
                continue                                      # other modifiers (exp=…)
            q = "+"
            if t[0] in "+-~?":
                q, t = t[0], t[1:]
            name = t.split(":", 1)[0].split("/", 1)[0]
            if name == "all":
                qualifier = q
            elif name in _SPF_LOOKUP_MECHS:
                rep.lookups += 1
                if name == "ptr":
                    rep.uses_ptr = True
                if name == "include" and ":" in t:
                    walk(term.split(":", 1)[1].lstrip("+-~?"), depth + 1, False, f"include:{dom}")
        if redirect and qualifier is None:
            rep.lookups += 1
            return walk(redirect, depth + 1, False, f"redirect:{dom}")
        return qualifier

    rep.all_qualifier = walk(domain, 0, True, "apex")
    return rep


# ── DMARC / DKIM parsing ──────────────────────────────────────────────────────

def parse_tags(record: str) -> dict[str, str]:
    """'v=DMARC1; p=reject; rua=mailto:x' → {'v': 'DMARC1', 'p': 'reject', …}"""
    out: dict[str, str] = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            out[k.strip().lower()] = v.strip()
    return out


def rsa_bits_from_dkim(p_value: str) -> int | None:
    """Key size in bits from a DKIM `p=` value (base64 SubjectPublicKeyInfo)."""
    try:
        from cryptography.hazmat.primitives.serialization import load_der_public_key
        der = base64.b64decode("".join(p_value.split()), validate=False)
        return getattr(load_der_public_key(der), "key_size", None)
    except Exception:
        return None


# Selectors used by common providers / defaults. DKIM selectors are arbitrary, so
# "not found" is only ever a hint — never a finding above INFO.
DKIM_SELECTORS = [
    "default", "dkim", "mail", "email", "selector1", "selector2",      # generic, Microsoft 365
    "google", "s1", "s2", "k1", "k2", "k3", "smtp", "mandrill",        # Google, Sendgrid/Mailchimp
    "mxvault", "everlytickey1", "dkim1", "20230601", "20221208",
]


# ── the module ────────────────────────────────────────────────────────────────

class DNSSecurityScanner(BaseScanner):
    name        = "dns_security"
    category    = "passive"
    scope       = "site"
    description = "DNS & email authentication: SPF (10-lookup limit, dead includes), DMARC, DKIM key strength, MTA-STS, NS/MX health, CAA"

    async def scan(self, url: str) -> list[Finding]:
        host = urlparse(url).hostname or ""
        domain = registrable_domain(host)
        if not domain or not dnsutil.HAVE_DNS:
            return []
        # Sanity gate: if the domain itself does not resolve, every "missing SPF/DMARC/…"
        # result would be an artefact of a broken resolver or a typo'd target, not a finding.
        apex = await asyncio.to_thread(dnsutil.exists, domain, 4.0)
        if apex.status in ("nxdomain", "error"):
            if apex.status == "error":
                return []                              # flaky resolver: say nothing rather than guess
            return [self._f(
                domain, f"DNS Checks Skipped: {domain} Does Not Resolve", Severity.INFO,
                f"The resolver reports that `{domain}` does not exist (NXDOMAIN), so SPF, DMARC, DKIM, "
                "MTA-STS, NS and CAA checks were skipped instead of reporting everything as missing. "
                "Either the target is mistyped, the domain is unregistered, or this machine's DNS "
                "resolver cannot reach the Internet.",
                "Check the target name, then run `fsv doctor` to test DNS from this host.",
                conf=Confidence.CERTAIN, cwe="CWE-1059")]
        findings = await asyncio.to_thread(self._check, domain)
        findings += await self._mta_sts(domain)
        return findings

    # ── helpers ──────────────────────────────────────────────────────────

    def _f(self, domain, title, sev, desc, rec, *, cwe="CWE-290", evidence="",
           conf=Confidence.FIRM, refs=None, name=None, extra=None) -> Finding:
        return Finding(
            title=title, severity=sev, confidence=conf, url=f"dns://{name or domain}",
            module=self.name, description=desc, recommendation=rec, evidence=evidence,
            cwe=cwe, references=refs or [], extra=extra or {},
        )

    # ── DNS checks (blocking; run in a thread) ───────────────────────────

    def _check(self, domain: str) -> list[Finding]:
        out: list[Finding] = []
        txt = lambda n: dnsutil.resolve(n, "TXT", 4.0)

        mx = dnsutil.resolve(domain, "MX", 4.0)
        mx_hosts = []
        null_mx = False
        for rec in mx.records:
            pref, _, host = rec.partition(" ")
            if host in ("", "."):
                null_mx = True
            else:
                mx_hosts.append(host)
        sends_mail = bool(mx_hosts)

        out += self._spf(domain, txt, sends_mail)
        out += self._dmarc(domain, txt, sends_mail)
        out += self._dkim(domain, txt, sends_mail)
        out += self._mx(domain, mx_hosts)
        out += self._ns(domain)
        out += self._caa_dnssec(domain)
        return out

    def _spf(self, domain, txt, sends_mail) -> list[Finding]:
        out: list[Finding] = []
        rep = analyze_spf(domain, txt)
        sev_missing = Severity.MEDIUM if sends_mail else Severity.LOW
        refs = ["https://datatracker.ietf.org/doc/html/rfc7208"]

        if not rep.records:
            out.append(self._f(
                domain, "Missing SPF Record", sev_missing,
                "No SPF record is published. Anyone can send mail that claims to come from this "
                "domain and receivers have nothing to check it against."
                + ("" if sends_mail else " This domain has no MX, so it should say so explicitly "
                   "— attackers spoof non-mail domains too."),
                'Publish an SPF record, e.g. "v=spf1 include:_spf.provider.com -all" '
                '(or "v=spf1 -all" for a domain that sends no mail).',
                evidence=f"No v=spf1 TXT record on {domain}", refs=refs))
            return out

        if len(rep.records) > 1:
            out.append(self._f(
                domain, "Multiple SPF Records (PermError)", Severity.MEDIUM,
                f"{len(rep.records)} SPF records are published. RFC 7208 says a domain must have "
                "exactly one; receivers treat several as a PermError, i.e. SPF fails for all mail.",
                "Merge them into a single v=spf1 record.",
                evidence="\n".join(r[:200] for r in rep.records), refs=refs))

        q = rep.all_qualifier
        if q == "+":
            out.append(self._f(
                domain, "SPF Allows Any Sender (+all)", Severity.HIGH,
                "The SPF record ends in '+all' (or bare 'all'), which authorises every server on "
                "the Internet to send mail as this domain — it is worse than having no SPF.",
                'End the record with "-all" (or "~all" while rolling out DMARC).',
                evidence=rep.records[0][:300], refs=refs))
        elif q == "?":
            out.append(self._f(
                domain, "SPF Neutral Policy (?all)", Severity.MEDIUM,
                "'?all' tells receivers not to judge mail that fails SPF, so it provides no protection.",
                'Use "-all" (or "~all" at minimum).', evidence=rep.records[0][:300], refs=refs))
        elif q is None and not rep.truncated:
            out.append(self._f(
                domain, "SPF Record Has No 'all' Mechanism", Severity.LOW,
                "Without a terminating 'all' (or redirect=), mail from unlisted servers gets a "
                "neutral result — the same as '?all'.",
                'Append "-all".', evidence=rep.records[0][:300], refs=refs))

        if rep.lookups > 10:
            out.append(self._f(
                domain, f"SPF Exceeds the 10-DNS-Lookup Limit ({rep.lookups})", Severity.MEDIUM,
                f"Evaluating this SPF record needs {rep.lookups} DNS-querying terms (include/a/mx/"
                "ptr/exists/redirect). RFC 7208 allows 10; beyond that receivers return PermError "
                "and your SPF stops working — typically after someone adds one more SaaS include. "
                "DMARC then falls back to DKIM alone.",
                "Remove unused includes, replace includes with ip4:/ip6: ranges, or use an SPF "
                "flattening service. Re-count after every change.",
                evidence=f"{rep.lookups} lookups\n{rep.records[0][:300]}", refs=refs,
                extra={"lookups": rep.lookups}))
        if rep.uses_ptr:
            out.append(self._f(
                domain, "SPF Uses the Deprecated 'ptr' Mechanism", Severity.LOW,
                "'ptr' is slow, unreliable and discouraged by RFC 7208 §5.5.",
                "Replace it with explicit ip4:/ip6:/include: terms.",
                evidence=rep.records[0][:300], refs=refs))

        for via, dom in rep.dangling:
            out.append(self._f(
                domain, f"SPF References a Non-Existent Domain: {dom}", Severity.HIGH,
                f"The SPF record pulls in `{dom}` (via {via}), but that domain does not exist "
                "(NXDOMAIN). If it was a former provider or an expired domain, anyone can now "
                "register it, publish their own SPF record there, and thereby become an "
                "authorised sender for this domain — bypassing SPF for spoofed mail.",
                f"Remove the `{dom}` reference from your SPF record. Audit all other includes for "
                "providers you no longer use.",
                evidence=f"{via} → {dom}: NXDOMAIN", cwe="CWE-1390",
                conf=Confidence.CERTAIN, refs=refs, extra={"dangling_domain": dom}))
        for via, dom in rep.no_spf:
            out.append(self._f(
                domain, f"SPF Include Has No SPF Record: {dom}", Severity.MEDIUM,
                f"`{dom}` (via {via}) exists but publishes no SPF record, so evaluating this "
                "include is a PermError and SPF fails for all mail.",
                f"Remove the include or fix the provider's record.",
                evidence=f"{via} → {dom}: no v=spf1", refs=refs))
        return out

    def _dmarc(self, domain, txt, sends_mail) -> list[Finding]:
        out: list[Finding] = []
        refs = ["https://datatracker.ietf.org/doc/html/rfc7489"]
        ans = txt(f"_dmarc.{domain}")
        recs = [t for t in ans.records if t.lower().lstrip().startswith("v=dmarc1")]
        name = f"_dmarc.{domain}"
        if not recs:
            if ans.status == "error":
                return out                                     # don't guess on a flaky lookup
            out.append(self._f(
                domain, "Missing DMARC Record",
                Severity.MEDIUM if sends_mail else Severity.LOW,
                "No DMARC record found. DMARC tells receivers what to do with mail that fails "
                "SPF/DKIM and gives you reports about who is sending as you; without it, "
                "phishing that spoofs your domain is delivered normally.",
                'Publish e.g. "v=DMARC1; p=quarantine; rua=mailto:dmarc@your-domain", then '
                "tighten to p=reject.",
                evidence=f"No v=DMARC1 TXT on {name}", refs=refs, name=name))
            return out

        if len(recs) > 1:
            out.append(self._f(
                domain, "Multiple DMARC Records", Severity.MEDIUM,
                "More than one DMARC record is published; receivers ignore DMARC when they find "
                "several.", "Keep exactly one v=DMARC1 record.",
                evidence="\n".join(r[:200] for r in recs), refs=refs, name=name))
        tags = parse_tags(recs[0])
        p = tags.get("p", "").lower()
        sp = tags.get("sp", "").lower()
        has_rua = bool(tags.get("rua"))
        ev = recs[0][:300]

        if p == "none":
            out.append(self._f(
                domain, "DMARC Policy Set to 'none'",
                Severity.LOW if has_rua else Severity.MEDIUM,
                "DMARC is in monitor-only mode: spoofed mail is still delivered."
                + ("" if has_rua else " There is also no rua= address, so nobody is even "
                   "receiving the reports — the record currently does nothing."),
                "Review the aggregate reports, then move to p=quarantine and p=reject.",
                evidence=ev, refs=refs, name=name))
        elif p in ("quarantine", "reject"):
            if sp == "none":
                out.append(self._f(
                    domain, "DMARC Subdomain Policy Is 'none'", Severity.MEDIUM,
                    f"p={p} protects the apex, but sp=none leaves every subdomain "
                    "(mail.example.com, billing.example.com, …) spoofable.",
                    "Remove sp= (subdomains inherit p=) or set sp=reject.",
                    evidence=ev, refs=refs, name=name))
            pct = tags.get("pct", "100")
            if pct.isdigit() and int(pct) < 100:
                out.append(self._f(
                    domain, f"DMARC Applies to Only {pct}% of Mail", Severity.LOW,
                    f"pct={pct} means {100 - int(pct)}% of failing mail is delivered regardless of policy.",
                    "Raise pct to 100 once reports look clean.", evidence=ev, refs=refs, name=name))
        if p and not has_rua and p != "none":
            out.append(self._f(
                domain, "DMARC Has No Aggregate Reporting (rua)", Severity.INFO,
                "Without rua= you will not learn about spoofing attempts or legitimate senders "
                "that fail authentication.", "Add rua=mailto:… .",
                evidence=ev, refs=refs, name=name, conf=Confidence.CERTAIN))
        return out

    def _dkim(self, domain, txt, sends_mail) -> list[Finding]:
        out: list[Finding] = []
        refs = ["https://datatracker.ietf.org/doc/html/rfc6376", "https://datatracker.ietf.org/doc/html/rfc8301"]

        def probe(sel: str):
            return sel, txt(f"{sel}._domainkey.{domain}")
        with ThreadPoolExecutor(max_workers=8) as pool:
            results = list(pool.map(probe, DKIM_SELECTORS))

        found = 0
        for sel, ans in results:
            keyrec = next((r for r in ans.records if "p=" in r.lower()), None)
            if keyrec is None:
                continue
            found += 1
            tags = parse_tags(keyrec)
            name = f"{sel}._domainkey.{domain}"
            bits = rsa_bits_from_dkim(tags.get("p", "")) if tags.get("p") else None
            if bits is not None and bits < 1024:
                out.append(self._f(
                    domain, f"DKIM Key Too Short ({bits}-bit): selector '{sel}'", Severity.HIGH,
                    f"The DKIM signing key for selector `{sel}` is only {bits} bits, far below the "
                    "2048-bit recommendation (RFC 8301 forbids signing with <1024). 512-bit RSA can be "
                    "factored in hours on rented cloud hardware and 768-bit keys have been factored in "
                    "academic work; whoever recovers the private key can forge validly-signed mail "
                    "from this domain.",
                    "Rotate to a 2048-bit RSA key (or Ed25519) and delete the old record.",
                    evidence=f"{name}: RSA {bits}-bit", cwe="CWE-326", refs=refs, name=name,
                    conf=Confidence.CERTAIN, extra={"selector": sel, "bits": bits}))
            elif bits == 1024:
                out.append(self._f(
                    domain, f"DKIM Key Is 1024-bit: selector '{sel}'", Severity.LOW,
                    "1024-bit RSA is below current guidance (RFC 8301 requires verifiers to "
                    "accept 1024 but recommends 2048).",
                    "Rotate to a 2048-bit key at the next opportunity.",
                    evidence=f"{name}: RSA 1024-bit", cwe="CWE-326", refs=refs, name=name,
                    extra={"selector": sel, "bits": bits}))
            if "y" in tags.get("t", "").lower().split(":"):
                out.append(self._f(
                    domain, f"DKIM Selector '{sel}' Is in Testing Mode (t=y)", Severity.LOW,
                    "t=y tells verifiers to treat signature failures as if the message were unsigned, "
                    "so forged signatures are not penalised.",
                    "Remove t=y once the key is in production use.",
                    evidence=keyrec[:200], refs=refs, name=name))
        if found == 0 and sends_mail:
            out.append(self._f(
                domain, "No DKIM Key Found at Common Selectors", Severity.INFO,
                "None of the common DKIM selectors resolve. DKIM selectors are arbitrary so this may "
                "be a false alarm — but if mail really is unsigned, DMARC can only rely on SPF.",
                "Confirm your provider's DKIM selector is published (check a real message's "
                "DKIM-Signature header).", conf=Confidence.TENTATIVE, refs=refs))
        return out

    def _mx(self, domain, mx_hosts) -> list[Finding]:
        out = []
        for h in mx_hosts:
            if dnsutil.exists(h, 3.0).nxdomain:
                out.append(self._f(
                    domain, f"MX Points to a Non-Existent Host: {h}", Severity.MEDIUM,
                    f"The mail exchanger `{h}` does not resolve. Mail for this domain is delayed or "
                    "lost, and if that host name sits in a domain that can be registered, someone "
                    "else can receive your mail.",
                    "Remove or correct the MX record.", evidence=f"{h}: NXDOMAIN",
                    cwe="CWE-1390", conf=Confidence.CERTAIN, extra={"host": h}))
        return out

    def _ns(self, domain) -> list[Finding]:
        out = []
        ns = dnsutil.resolve(domain, "NS", 4.0)
        hosts = list(ns.records)
        if not hosts:
            return out
        for h in hosts:
            if dnsutil.exists(h, 3.0).nxdomain:
                out.append(self._f(
                    domain, f"Delegated Nameserver Does Not Exist: {h}", Severity.HIGH,
                    f"`{h}` is listed as an authoritative nameserver but does not resolve. Queries "
                    "that reach it fail, and if its domain is registrable an attacker can stand up "
                    "that nameserver and answer for this domain (full DNS takeover).",
                    "Remove the stale NS record at the registrar/parent zone.",
                    evidence=f"{h}: NXDOMAIN", cwe="CWE-1390", conf=Confidence.CERTAIN,
                    extra={"host": h}))
        if len(hosts) < 2:
            out.append(self._f(
                domain, "Only One Authoritative Nameserver", Severity.LOW,
                "RFC 2182 requires at least two nameservers on separate networks; with one, an "
                "outage of that server takes the domain (web and mail) offline.",
                "Add a second nameserver in a different network/provider.",
                evidence=hosts[0], cwe="CWE-1059"))
        return out

    def _caa_dnssec(self, domain) -> list[Finding]:
        out = []
        caa = dnsutil.resolve(domain, "CAA", 4.0)
        if caa.status in ("nodata", "nxdomain"):
            out.append(self._f(
                domain, "No CAA Record", Severity.LOW,
                "No CAA record: any certificate authority may issue certificates for this domain, "
                "which widens the impact of a mis-issuance or a validation bypass at any CA.",
                'Add a CAA record, e.g.  0 issue "letsencrypt.org"  (and an iodef contact).',
                evidence=f"No CAA record on {domain}", cwe="CWE-295",
                refs=["https://datatracker.ietf.org/doc/html/rfc8659"]))
        dk = dnsutil.resolve(domain, "DNSKEY", 4.0)
        if dk.status == "nodata":
            out.append(self._f(
                domain, "DNSSEC Not Enabled", Severity.INFO,
                "The zone is unsigned, so DNS answers cannot be cryptographically validated.",
                "Enable DNSSEC at the DNS provider and publish the DS record at the registrar.",
                cwe="CWE-350", conf=Confidence.FIRM,
                refs=["https://datatracker.ietf.org/doc/html/rfc4033"]))
        return out

    # ── MTA-STS (one HTTPS GET to the domain's own mta-sts host) ─────────

    async def _mta_sts(self, domain: str) -> list[Finding]:
        mx = await dnsutil.aresolve(domain, "MX", 4.0)
        if not any(r.partition(" ")[2] not in ("", ".") for r in mx.records):
            return []
        refs = ["https://datatracker.ietf.org/doc/html/rfc8461"]
        rec = await dnsutil.aresolve(f"_mta-sts.{domain}", "TXT", 4.0)
        has_txt = any(t.lower().lstrip().startswith("v=stsv1") for t in rec.records)
        if not has_txt:
            if rec.status == "error":
                return []
            return [self._f(
                domain, "MTA-STS Not Configured", Severity.INFO,
                "Without MTA-STS, mail delivered to this domain can be downgraded to plaintext by "
                "an on-path attacker (STARTTLS stripping).",
                "Publish _mta-sts TXT and a policy at https://mta-sts.<domain>/.well-known/mta-sts.txt "
                "(start with mode: testing).", cwe="CWE-319", refs=refs,
                name=f"_mta-sts.{domain}", conf=Confidence.CERTAIN)]
        r = await self.http.request(f"https://mta-sts.{domain}/.well-known/mta-sts.txt")
        if not r.ok or r.status != 200 or "version" not in r.body.lower():
            return [self._f(
                domain, "MTA-STS Record Published but Policy Is Unreachable", Severity.MEDIUM,
                "The _mta-sts TXT record exists but the policy file cannot be fetched "
                f"(status {r.status}). Senders cannot validate it, so protection is not in effect "
                "and some senders may defer or bounce mail.",
                "Serve the policy over HTTPS with a valid certificate at "
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt.",
                evidence=f"GET https://mta-sts.{domain}/.well-known/mta-sts.txt → {r.status}",
                cwe="CWE-319", refs=refs, name=f"mta-sts.{domain}")]
        mode = ""
        for line in r.body.splitlines():
            if line.lower().startswith("mode:"):
                mode = line.split(":", 1)[1].strip().lower()
        if mode == "testing":
            return [self._f(
                domain, "MTA-STS in Testing Mode", Severity.LOW,
                "mode: testing reports failures but does not stop downgrades.",
                "Move to mode: enforce once TLS-RPT reports are clean.", cwe="CWE-319",
                refs=refs, name=f"mta-sts.{domain}", conf=Confidence.CERTAIN)]
        if mode == "none":
            return [self._f(
                domain, "MTA-STS Policy Mode Is 'none'", Severity.LOW,
                "mode: none disables MTA-STS protection.", "Use mode: enforce.",
                cwe="CWE-319", refs=refs, name=f"mta-sts.{domain}", conf=Confidence.CERTAIN)]
        return []
