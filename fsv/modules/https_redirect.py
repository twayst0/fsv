"""
FSV Module — HTTP → HTTPS upgrade path and HSTS reach

HTTPS everywhere is only as strong as the first request. Someone typing `example.com` hits port 80 first; what happens
there decides whether an attacker on the network can read or rewrite that first exchange:

  • port 80 serves the site instead of redirecting → SSL-stripping works
  • the redirect goes to another host *over HTTP* first (http://example.com → http://www.example.com → https://…)
  • the chain never reaches HTTPS
  • HSTS present but without includeSubDomains (cookies can be planted from a sibling subdomain)

Read-only: a handful of GETs with redirects followed manually, one hop at a time.
"""

from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

MAX_HOPS = 6


def _first_slash(url: str) -> str:
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc}/"


class HTTPSRedirectScanner(BaseScanner):
    name        = "https_redirect"
    category    = "passive"
    scope       = "site"
    description = "HTTP→HTTPS upgrade (does port 80 redirect, how, via which hosts) and HSTS includeSubDomains"

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        if p.scheme != "https" or (p.port not in (None, 443)):
            return []                                         # a custom port has no "port 80 twin"; plain-HTTP targets are the ssl module's finding
        out: list[Finding] = []
        start = f"http://{p.hostname}/"
        hops: list[tuple[int, str]] = []
        cur = start
        final: tuple[int, str, str] | None = None
        for _ in range(MAX_HOPS):
            r = await self.http.request(cur, allow_redirects=False)
            if not r.ok:
                if not hops:
                    return await self._hsts(url, out)                # nothing listens on port 80: fine
                break
            loc = next((v for k, v in r.headers.items() if k.lower() == "location"), "")
            if 300 <= r.status < 400 and loc:
                nxt = urljoin(cur, loc)
                hops.append((r.status, nxt))
                cur = nxt
                if urlparse(nxt).scheme == "https":
                    final = (r.status, nxt, "https")
                    break
                continue
            final = (r.status, cur, urlparse(cur).scheme)
            break

        chain = " → ".join([start] + [h for _, h in hops])
        if final and final[2] != "https":
            if not hops:
                out.append(Finding(
                    title="HTTP Version of the Site Does Not Redirect to HTTPS", severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                    url=start, module=self.name,
                    description=(f"Port 80 answers HTTP {final[0]} with content instead of redirecting to HTTPS. Anyone who types the bare domain, follows an old "
                                 "http:// link or sits on a hostile network gets the plain-HTTP site — and an attacker can keep them there (SSL stripping)."),
                    evidence=f"GET {start} → HTTP {final[0]} (no redirect)",
                    recommendation="Answer every port-80 request with a 301 to the https:// URL, and send an HSTS header on the HTTPS site.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"], cwe="CWE-319"))
            else:
                out.append(Finding(
                    title="HTTP Redirect Chain Never Reaches HTTPS", severity=Severity.MEDIUM, confidence=Confidence.FIRM, url=start, module=self.name,
                    description="The redirects from port 80 stay on HTTP and end on a plain-HTTP page.", evidence=chain,
                    recommendation="Redirect straight to the final https:// URL.", cwe="CWE-319"))
        elif hops:
            first_host = urlparse(hops[0][1]).hostname
            if urlparse(hops[0][1]).scheme == "http" and first_host != p.hostname:
                out.append(Finding(
                    title="HTTP Redirect Passes Through Another Host Before HTTPS", severity=Severity.LOW, confidence=Confidence.FIRM, url=start,
                    module=self.name,
                    description=(f"The first redirect sends the browser to {first_host} over plain HTTP, and only that host upgrades to HTTPS. "
                                 "The request for the original name was exposed, and the unencrypted hop is a place to intercept."),
                    evidence=chain, recommendation="Redirect to https:// on the first hop (`http://a` → `https://b`), not via an HTTP intermediate.",
                    cwe="CWE-319"))
            if hops[0][0] in (302, 303, 307):
                out.append(Finding(
                    title="HTTP→HTTPS Redirect Is Temporary", severity=Severity.INFO, confidence=Confidence.FIRM, url=start, module=self.name,
                    description=f"The upgrade uses HTTP {hops[0][0]}; a permanent 301/308 lets browsers and search engines remember it.",
                    evidence=chain, recommendation="Use 301 (or 308) for the HTTP→HTTPS redirect.", cwe="CWE-319"))
        return await self._hsts(url, out)

    async def _hsts(self, url: str, out: list[Finding]) -> list[Finding]:
        r = await self.http.request(_first_slash(url))
        value = next((v for k, v in r.headers.items() if k.lower() == "strict-transport-security"), "") if r.ok else ""
        if value and not re.search(r"(?i)includesubdomains", value):
            out.append(Finding(
                title="HSTS Does Not Cover Subdomains", severity=Severity.INFO, confidence=Confidence.CERTAIN, url=_first_slash(url), module=self.name,
                description=("Strict-Transport-Security has no `includeSubDomains`, so browsers still allow plain HTTP to subdomains — and a network attacker can "
                             "plant cookies for the parent domain from an HTTP subdomain."),
                evidence=f"Strict-Transport-Security: {value}",
                recommendation="Add `includeSubDomains` once every subdomain serves HTTPS (then consider `preload`).", cwe="CWE-319"))
        return out
