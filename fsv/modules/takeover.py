"""
FSV Module — Subdomain Takeover & Dangling DNS
──────────────────────────────────────────────
A subdomain is "taken over" when its DNS still points at a third-party resource
that nobody owns any more (a deleted GitHub Pages site, a released Azure app
name, an unregistered domain) — the next person to claim that name controls
content served from YOUR subdomain, can often read cookies scoped to the parent
domain, and can pass OAuth/CSP/CORS allow-lists that trust `*.yourdomain.com`.

It happens to large, well-run organisations constantly, because the DNS record
outlives the project that created it and nobody owns the clean-up.

How this finds them (detection only — nothing is ever claimed or registered):
  1. candidate hostnames: wordlist + hosts linked from the page (+ CT logs, opt-in)
  2. explicit CNAME lookup (an A lookup hides dangling aliases: it just fails)
  3. follow the chain; if the final name is NXDOMAIN → dangling
       · target domain itself unregistered       → High (anyone can register it)
       · provider where released names are free  → High
       · anything else                           → Medium
  4. if the target is a known provider that still resolves, fetch the host once
     and look for that provider's "no such site" page → High (firm)
"""

from __future__ import annotations
import asyncio
import re
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from urllib.parse import urlparse

from bs4 import BeautifulSoup

from fsv.core import dnsutil
from fsv.core.ct import fetch_ct_hosts
from fsv.core.models import Finding, Severity, Confidence
from fsv.core.netsafety import registrable_domain
from fsv.core.scanner import BaseScanner
from fsv.modules.subdomain import WORDLIST


@dataclass(frozen=True)
class Provider:
    name:         str
    suffixes:     tuple[str, ...]                 # CNAME target ends with one of these
    fingerprints: tuple[str, ...] = ()            # body text of the "unclaimed" page
    nxdomain_free: bool = False                   # a released name resolves NXDOMAIN and can be re-claimed
    pattern:      str | None = None               # alternative: regex on the target


PROVIDERS: tuple[Provider, ...] = (
    Provider("GitHub Pages", ("github.io",),
             ("There isn't a GitHub Pages site here.",)),
    Provider("Heroku", ("herokuapp.com", "herokudns.com", "herokussl.com"),
             ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    Provider("AWS S3 website", (), ("NoSuchBucket", "The specified bucket does not exist"),
             pattern=r"\.s3[.-]"),
    Provider("Shopify", ("myshopify.com",),
             ("Sorry, this shop is currently unavailable.",)),
    Provider("Fastly", ("fastly.net",), ("Fastly error: unknown domain",)),
    Provider("Bitbucket", ("bitbucket.io",), ("Repository not found",)),
    Provider("Pantheon", ("pantheonsite.io",),
             ("The gods are wise, but do not know of the site which you seek.",)),
    Provider("Ghost", ("ghost.io",),
             ("The thing you were looking for is no longer here, or never was",)),
    Provider("Surge", ("surge.sh",), ("project not found",)),
    Provider("Tumblr", ("domains.tumblr.com",),
             ("Whatever you were looking for doesn't currently exist at this address.",)),
    Provider("Zendesk", ("zendesk.com",), ("Help Center Closed",)),
    # Azure / Beanstalk: when the resource is deleted the target name stops
    # resolving, and the name can be re-registered by anyone
    Provider("Azure App Service", ("azurewebsites.net",), nxdomain_free=True),
    Provider("Azure Cloud Service", ("cloudapp.net", "cloudapp.azure.com"), nxdomain_free=True),
    Provider("Azure Traffic Manager", ("trafficmanager.net",), nxdomain_free=True),
    Provider("Azure Blob Storage", ("blob.core.windows.net",), nxdomain_free=True),
    Provider("Azure CDN", ("azureedge.net",), nxdomain_free=True),
    Provider("AWS Elastic Beanstalk", ("elasticbeanstalk.com",), nxdomain_free=True),
)

# extra prefixes that tend to point at SaaS (marketing, support, status pages…)
EXTRA_PREFIXES = [
    "help", "support", "careers", "jobs", "go", "links", "click", "email", "e", "info", "news",
    "press", "learn", "community", "forum", "feedback", "survey", "events", "webinar", "partners",
    "developers", "developer", "sandbox", "preview", "uat", "qa", "stg", "prod", "old-www",
    "cdn1", "files", "download", "downloads", "upload", "video", "videos", "web", "web2",
    "lists", "newsletter", "marketing", "promo", "campaign", "land", "pages", "sites",
    "chat", "meet", "calendar", "crm", "erp", "hr", "billing", "pay", "payments", "checkout",
]

MAX_CANDIDATES = 400


def match_provider(chain: list[str]) -> Provider | None:
    for name in chain:
        for p in PROVIDERS:
            if any(name == s or name.endswith("." + s) for s in p.suffixes):
                return p
            if p.pattern and re.search(p.pattern, name):
                return p
    return None


def _hosts_in_html(html: str, base_url: str, domain: str) -> set[str]:
    """Hostnames under `domain` referenced by links/scripts/forms on the page."""
    out: set[str] = set()
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return out
    for tag in soup.find_all(["a", "link", "script", "img", "form", "iframe", "source"]):
        ref = tag.get("href") or tag.get("src") or tag.get("action") or ""
        host = (urlparse(ref).hostname or "").lower()
        if host and (host == domain or host.endswith("." + domain)):
            out.add(host)
    return out


class TakeoverScanner(BaseScanner):
    name        = "takeover"
    category    = "passive"
    scope       = "site"
    external    = True       # resolves/fetches hostnames other than the target itself
    description = "Subdomain takeover & dangling DNS: CNAMEs to unclaimed SaaS resources or unregistered domains"

    async def scan(self, url: str) -> list[Finding]:
        if not dnsutil.HAVE_DNS:
            return []
        host = (urlparse(url).hostname or "").lower()
        domain = registrable_domain(host)
        if not domain:
            return []

        candidates = {f"{p}.{domain}" for p in (*WORDLIST, *EXTRA_PREFIXES)}
        candidates.add(host)
        r = await self.http.request(url)
        if r.ok:
            candidates |= _hosts_in_html(r.body, url, domain)
        if getattr(self.scan_config, "use_ct_logs", False):
            candidates |= set(await fetch_ct_hosts(self.http, domain))
        hosts = sorted(candidates)[:MAX_CANDIDATES]

        aliases = await asyncio.to_thread(self._resolve_all, hosts)
        findings: list[Finding] = []
        third_party: list[str] = []

        for a in aliases:
            prov = match_provider(a["chain"])
            if not a["chain"]:
                continue
            final = a["chain"][-1]
            if not final.endswith("." + domain) and final != domain:
                third_party.append(f"{a['host']} → {final}" + (f"  [{prov.name}]" if prov else ""))

            if a["final_status"] == "nxdomain":
                findings.append(self._dangling(a, prov, domain))
            elif prov and prov.fingerprints:
                hit = await self._fingerprint(a["host"], prov)
                if hit:
                    findings.append(self._claimable(a, prov, hit))

        if third_party:
            findings.append(Finding(
                title=f"Hosts Aliased to Third-Party Services ({len(third_party)})",
                severity=Severity.INFO, confidence=Confidence.CERTAIN,
                url=f"dns://{domain}", module=self.name,
                description=(
                    "These names are CNAMEs to services outside your own domain. Each one is a "
                    "trust relationship that must be removed when the project ends; they are the "
                    "records that turn into takeovers."),
                evidence="\n".join(third_party[:60]),
                recommendation=("Keep an owner and an expiry for every third-party alias, and "
                                "review this list whenever a SaaS contract ends."),
                cwe="CWE-1059", extra={"aliases": third_party}))
        return findings

    # ── DNS phase (blocking, threaded) ───────────────────────────────────

    def _resolve_all(self, hosts: list[str]) -> list[dict]:
        def one(h: str) -> dict:
            chain: list[str] = []
            cur = h
            for _ in range(6):
                a = dnsutil.resolve(cur, "CNAME", 2.5)
                if not a.ok:
                    break
                cur = a.records[0]
                if cur in chain:
                    break
                chain.append(cur)
            if not chain:
                return {"host": h, "chain": [], "final_status": None}
            final = dnsutil.exists(chain[-1], 3.0)
            reg_unregistered = False
            if final.nxdomain:
                rd = registrable_domain(chain[-1])
                if rd and dnsutil.nxdomain_is_meaningful():
                    reg_unregistered = dnsutil.resolve(rd, "NS", 3.0).nxdomain
            return {"host": h, "chain": chain, "final_status": final.status,
                    "target_domain_unregistered": reg_unregistered}
        with ThreadPoolExecutor(max_workers=24) as pool:
            return [r for r in pool.map(one, hosts) if r["chain"]]

    # ── finding builders ─────────────────────────────────────────────────

    def _chain_text(self, a: dict) -> str:
        return a["host"] + " → " + " → ".join(a["chain"])

    def _dangling(self, a: dict, prov: Provider | None, domain: str) -> Finding:
        host, target = a["host"], a["chain"][-1]
        unreg = a.get("target_domain_unregistered")
        if unreg:
            sev, conf = Severity.HIGH, Confidence.CERTAIN
            why = (f"`{target}` does not exist and its registrable domain appears to be "
                   "UNREGISTERED — anyone can register it, point it at a server they control, "
                   f"and instantly serve their content from `{host}`.")
        elif prov and prov.nxdomain_free:
            sev, conf = Severity.HIGH, Confidence.FIRM
            why = (f"`{target}` ({prov.name}) no longer resolves. On this platform a released "
                   "resource name can be claimed by anyone, which gives them control of "
                   f"`{host}`.")
        else:
            sev, conf = Severity.MEDIUM, Confidence.FIRM
            why = (f"`{host}` is an alias for `{target}`, which does not exist (NXDOMAIN). The "
                   "record is dead weight at best; if the target can be re-registered or "
                   "re-claimed at that provider, it is a takeover.")
        return Finding(
            title=f"Dangling DNS Record (Takeover Risk): {host}",
            severity=sev, confidence=conf, url=f"dns://{host}", module=self.name,
            description=why + " Because the host sits under your domain it inherits trust: "
                        "cookies scoped to the parent domain, CORS/CSP/OAuth allow-lists, "
                        "and user expectations.",
            evidence=f"{self._chain_text(a)}\n{target}: NXDOMAIN",
            recommendation=(f"Delete the DNS record for `{host}` (or re-create the resource at "
                            "the provider so you own it again). Then audit the rest of the zone — "
                            "this rarely happens to just one record."),
            references=["https://owasp.org/www-project-web-security-testing-guide/v42/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/10-Test_for_Subdomain_Takeover",
                        "https://github.com/EdOverflow/can-i-take-over-xyz"],
            cwe="CWE-1390",
            extra={"host": host, "target": target, "provider": prov.name if prov else None,
                   "kind": "dangling"})

    def _claimable(self, a: dict, prov: Provider, hit: str) -> Finding:
        host = a["host"]
        return Finding(
            title=f"Subdomain Takeover Likely: {host} ({prov.name})",
            severity=Severity.HIGH, confidence=Confidence.FIRM, url=f"dns://{host}",
            module=self.name,
            description=(
                f"`{host}` is aliased to {prov.name}, and that service is answering with its "
                "\"nothing is hosted here\" page. The resource behind the alias has been deleted "
                "or was never created, so another customer of the same platform can claim the "
                f"name and serve their own content from `{host}`."),
            evidence=f"{self._chain_text(a)}\nPage contains: “{hit}”",
            recommendation=(f"Remove the CNAME for `{host}`, or re-create/claim the resource at "
                            f"{prov.name}. Check logs for signs it was already claimed."),
            references=["https://github.com/EdOverflow/can-i-take-over-xyz"],
            cwe="CWE-1390",
            extra={"host": host, "provider": prov.name, "kind": "claimable"})

    async def _fingerprint(self, host: str, prov: Provider) -> str | None:
        for scheme in ("http", "https"):
            r = await self.http.request(f"{scheme}://{host}/")
            if r.ok:
                for fp in prov.fingerprints:
                    if fp in r.body:
                        return fp
        return None
