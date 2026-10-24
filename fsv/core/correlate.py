"""
FSV — Finding correlation ("attack paths")
──────────────────────────────────────────
Real compromises are rarely one bug. They are two or three individually
"medium" problems that line up:

    XSS                    +  session cookie without HttpOnly   →  account takeover
    no HSTS                +  session cookie without Secure     →  hijack on any hostile network
    dangling subdomain     +  session cookie scoped to the parent domain → session theft
    dangling SPF include   +  DMARC not enforcing               →  perfectly authenticated phishing

Scanners that report findings one by one rate each in isolation, so the combination
is invisible until someone writes it up in an incident report. This module reads
the findings FSV already produced (it sends no requests) and, where a chain is
actually present, adds one more finding that names the chain, rates the combined
impact and says which single fix breaks it.

Rules are deliberately few and conservative: every link must be backed by an actual
finding on this scan, never assumed.
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Callable, Iterable

from fsv.core.models import (
    Confidence, Finding, FindingStatus, Severity, SEVERITY_ORDER,
)

MODULE = "correlation"

_CONF_RANK = {Confidence.TENTATIVE: 1, Confidence.FIRM: 2, Confidence.CERTAIN: 3}


# ── predicates over findings ──────────────────────────────────────────────────

def _t(f: Finding) -> str:
    return f.title.lower()


def is_xss(f: Finding) -> bool:
    return f.module == "xss"


def is_session_cookie_flag(f: Finding, flag: str) -> bool:
    return f.module == "cookies" and f.extra.get("flag") == flag and bool(f.extra.get("session_like"))


def is_missing_hsts(f: Finding) -> bool:
    return f.module == "headers" and "strict-transport-security" in _t(f) and "missing" in _t(f)


def is_no_https(f: Finding) -> bool:
    return f.module == "ssl" and f.title == "Site Not Using HTTPS"


def is_takeover(f: Finding) -> bool:
    return f.module == "takeover" and f.extra.get("kind") in ("dangling", "claimable") \
        and SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[Severity.HIGH]


def is_dangling_spf(f: Finding) -> bool:
    return f.module == "dns_security" and f.title.startswith("SPF References a Non-Existent Domain")


def is_spf_open(f: Finding) -> bool:
    return f.module == "dns_security" and (
        f.title.startswith("SPF Allows Any Sender") or f.title.startswith("SPF Neutral Policy")
        or f.title == "Missing SPF Record")


def is_dmarc_not_enforcing(f: Finding) -> bool:
    return f.module == "dns_security" and (
        f.title == "Missing DMARC Record" or f.title == "DMARC Policy Set to 'none'")


# ── rule plumbing ─────────────────────────────────────────────────────────────

@dataclass
class Chain:
    rule:     str
    title:    str
    severity: Severity
    summary:  str                 # one-sentence story
    steps:    list[str]           # numbered attacker steps
    fix:      str                 # the cheapest link to cut
    links:    list[Finding]       # the findings that make up the chain
    cwe:      str | None = None
    url:      str | None = None
    refs:     list[str] | None = None


def _first(fs: Iterable[Finding], pred: Callable[[Finding], bool]) -> list[Finding]:
    return [f for f in fs if pred(f)]


def _names(fs: list[Finding]) -> str:
    out = []
    for f in fs:
        n = f.extra.get("cookie") or f.parameter or f.title
        if n not in out:
            out.append(n)
    return ", ".join(f"`{n}`" for n in out[:4])


def rule_xss_session_hijack(fs: list[Finding]) -> list[Chain]:
    xss = _first(fs, is_xss)
    nohttp = _first(fs, lambda f: is_session_cookie_flag(f, "httponly"))
    if not (xss and nohttp):
        return []
    return [Chain(
        rule="xss-session-hijack",
        title="Attack Path: XSS → Session Hijack (cookie readable by script)",
        severity=Severity.CRITICAL,
        summary=("A script-injection bug on this site can read the session cookie because the "
                 "cookie is not HttpOnly, so one click on a crafted link is a full account takeover."),
        steps=[f"Attacker sends a victim a link that triggers the XSS in parameter {_names(xss)}.",
               f"The injected script reads document.cookie and obtains {_names(nohttp)}.",
               "The script sends the cookie to the attacker, who replays it to impersonate the user "
               "(no password or 2FA needed)."],
        fix=(f"Cheapest break: mark {_names(nohttp)} HttpOnly — one line, no code change, and "
             "the script can no longer read it. Then fix the XSS (context-aware output encoding) "
             "and add a CSP."),
        links=xss + nohttp, cwe="CWE-79", url=xss[0].url,
        refs=["https://owasp.org/www-community/HttpOnly",
              "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"])]


def rule_network_cookie_exposure(fs: list[Finding]) -> list[Chain]:
    nosecure = _first(fs, lambda f: is_session_cookie_flag(f, "secure"))
    weak_transport = _first(fs, lambda f: is_missing_hsts(f) or is_no_https(f))
    if not (nosecure and weak_transport):
        return []
    return [Chain(
        rule="network-cookie-exposure",
        title="Attack Path: Session Cookie Exposed to Network Attackers",
        severity=Severity.HIGH,
        summary=("Without HSTS the browser will happily make a plain-HTTP request, and a session "
                 "cookie without the Secure flag is sent along with it — readable by anyone on "
                 "the same Wi-Fi or network path."),
        steps=["Victim on a hostile network (café Wi-Fi, compromised router) opens the site or any "
               "link to it over http://.",
               f"The browser sends {_names(nosecure)} in clear text because it is not Secure and "
               "nothing forced HTTPS.",
               "The attacker reads the cookie from the wire and replays it."],
        fix=("Cheapest break: add the Secure flag to the session cookie. Also send "
             "Strict-Transport-Security (and redirect HTTP→HTTPS)."),
        links=nosecure + weak_transport, cwe="CWE-614", url=nosecure[0].url,
        refs=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"])]


def rule_takeover_cookie_scope(fs: list[Finding]) -> list[Chain]:
    tk = _first(fs, is_takeover)
    shared = _first(fs, lambda f: is_session_cookie_flag(f, "domain"))
    if not (tk and shared):
        return []
    hosts = ", ".join(f"`{f.extra.get('host')}`" for f in tk[:3])
    return [Chain(
        rule="takeover-cookie-scope",
        title="Attack Path: Subdomain Takeover → Session Theft or Fixation",
        severity=Severity.CRITICAL,
        summary=("A subdomain that anyone can claim sits under a domain whose session cookie is "
                 "scoped to all subdomains — so the person who claims it receives your users' "
                 "sessions."),
        steps=[f"Attacker claims the abandoned resource behind {hosts}.",
               f"They serve a page there and lure a logged-in user to it; the browser attaches "
               f"{_names(shared)} (Domain={shared[0].extra.get('domain')}) to the request.",
               "The attacker now holds the session, or can overwrite the cookie to fix a session "
               "they control."],
        fix=("Cheapest break: delete the dangling DNS record. Then make the session cookie "
             "host-only (drop the Domain attribute / use the __Host- prefix)."),
        links=tk + shared, cwe="CWE-1390", url=tk[0].url,
        refs=["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"])]


def rule_email_spoofing(fs: list[Finding]) -> list[Chain]:
    dmarc = _first(fs, is_dmarc_not_enforcing)
    if not dmarc:
        return []
    dangling = _first(fs, is_dangling_spf)
    if dangling:
        doms = ", ".join(f"`{f.extra.get('dangling_domain')}`" for f in dangling[:3])
        return [Chain(
            rule="spf-takeover-spoofing",
            title="Attack Path: Registrable SPF Include → Fully Authenticated Email Spoofing",
            severity=Severity.CRITICAL,
            summary=("Your SPF record trusts a domain nobody owns, and DMARC does not enforce — an "
                     "attacker can register it and send mail as you that passes every check."),
            steps=[f"Attacker registers {doms}, which your SPF record includes.",
                   "They publish their own SPF record there authorising their mail server.",
                   "Mail forged from your domain now passes SPF; with DMARC missing or p=none "
                   "receivers deliver it to the inbox as legitimate."],
            fix=("Cheapest break: remove the dead include from your SPF record. Then move DMARC "
                 "to p=quarantine/reject."),
            links=dangling + dmarc, cwe="CWE-1390", url=dangling[0].url,
            refs=["https://datatracker.ietf.org/doc/html/rfc7208"])]
    open_spf = _first(fs, is_spf_open)
    if open_spf:
        return [Chain(
            rule="email-spoofing",
            title="Attack Path: Domain Can Be Spoofed in Email",
            severity=Severity.HIGH,
            summary="Neither SPF nor DMARC restricts who may send as this domain, so forged mail is delivered normally.",
            steps=["Attacker sends mail with your domain in the From address.",
                   "SPF gives no meaningful verdict and DMARC does not instruct receivers to reject it.",
                   "The message reaches inboxes looking like it came from you (phishing, invoice fraud)."],
            fix=("Cheapest break: publish an SPF record ending in -all and a DMARC record with "
                 "p=quarantine (then reject)."),
            links=open_spf + dmarc, cwe="CWE-290", url=dmarc[0].url,
            refs=["https://datatracker.ietf.org/doc/html/rfc7489"])]
    return []


RULES: tuple[Callable[[list[Finding]], list[Chain]], ...] = (
    rule_xss_session_hijack,
    rule_network_cookie_exposure,
    rule_takeover_cookie_scope,
    rule_email_spoofing,
)


# ── public API ────────────────────────────────────────────────────────────────

def correlate(findings: list[Finding]) -> list[Finding]:
    """New "attack path" findings for chains present in `findings` (originals untouched)."""
    live = [f for f in findings if f.module != MODULE and f.status.counts_toward_risk]
    out: list[Finding] = []
    for rule in RULES:
        for ch in rule(live):
            conf = min((l.confidence for l in ch.links), key=lambda c: _CONF_RANK[c])
            urls: list[str] = []
            for l in ch.links:
                urls += l.affected_urls or [l.url]
            steps = "\n".join(f"{i}. {s}" for i, s in enumerate(ch.steps, 1))
            out.append(Finding(
                title=ch.title, severity=ch.severity, confidence=conf,
                url=ch.url or ch.links[0].url, module=MODULE,
                description=(f"{ch.summary}\n\nHow it plays out:\n{steps}\n\n"
                             "Each link below was found by FSV on this scan; this finding exists "
                             "because they appear together."),
                evidence="\n".join(f"• [{l.severity.value}] {l.title}" for l in ch.links[:12]),
                recommendation=ch.fix, references=ch.refs or [], cwe=ch.cwe,
                affected_urls=list(dict.fromkeys(urls))[:30],
                extra={"rule": ch.rule,
                       "because": sorted({l.fingerprint for l in ch.links}),
                       "links": [{"title": l.title, "fingerprint": l.fingerprint,
                                  "severity": l.severity.value} for l in ch.links[:12]]}))
    return out


def refresh_chains(findings: list[Finding]) -> None:
    """
    Keep attack-path findings consistent with triage. If any link of a chain has
    been triaged away (false positive / accepted / fixed), the chain no longer
    holds and is marked SUPERSEDED; if the link is re-opened, the chain returns.
    A chain the user triaged *directly* (any other status) is left alone.
    """
    by_fp = {f.fingerprint: f for f in findings if f.module != MODULE}
    for f in findings:
        if f.module != MODULE or f.status not in (FindingStatus.OPEN, FindingStatus.SUPERSEDED):
            continue
        links = [by_fp.get(fp) for fp in f.extra.get("because", [])]
        broken = any(l is not None and not l.status.counts_toward_risk for l in links)
        f.status = FindingStatus.SUPERSEDED if broken else FindingStatus.OPEN
        f.triage_note = "a link in this chain was triaged away" if broken else ""
