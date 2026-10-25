"""FSV Module — Third-party script supply chain"""

from __future__ import annotations
import asyncio
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from fsv.core import dnsutil
from fsv.core.content import is_html, same_site, script_refs
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.netsafety import registrable_domain
from fsv.core.scanner import BaseScanner

# Domains whose owner changed hands and then served malware to every site embedding them,
# or CDNs that shut down (whoever registers the name next runs code on your pages).
# (domain, severity, what happened) — dated facts, not guesses.
KNOWN_BAD: dict[str, tuple[Severity, str]] = {
    "polyfill.io": (Severity.CRITICAL,
                    "polyfill.io was sold in 2024 and its CDN began injecting malicious redirects into "
                    "the scripts it served to over 100,000 sites."),
    "bootcss.com": (Severity.CRITICAL,
                    "bootcss.com is run by the same operator as the 2024 polyfill.io attack and was "
                    "reported serving the same malicious code."),
    "bootcdn.net": (Severity.CRITICAL,
                    "bootcdn.net is run by the same operator as the 2024 polyfill.io attack and was "
                    "reported serving the same malicious code."),
    "staticfile.org": (Severity.CRITICAL,
                       "staticfile.org is run by the same operator as the 2024 polyfill.io attack and "
                       "was reported serving the same malicious code."),
    "staticfile.net": (Severity.CRITICAL,
                       "staticfile.net is run by the same operator as the 2024 polyfill.io attack and "
                       "was reported serving the same malicious code."),
    "rawgit.com": (Severity.HIGH,
                   "RawGit shut down in 2019. Scripts from it no longer load, and the domain's future "
                   "owner would control what your pages execute."),
}
MAX_HOSTS = 40


def third_party_resources(html: str, page_url: str) -> list[tuple[str, str]]:
    """(url, kind) for scripts and stylesheets loaded from another site."""
    scripts, _ = script_refs(html, page_url)
    out = [(u, "script") for u in scripts]
    try:
        soup = BeautifulSoup(html, "lxml")
        for link in soup.find_all("link", href=True):
            rel = " ".join(link.get("rel") or []).lower()
            if "stylesheet" in rel or "preload" in rel or "modulepreload" in rel:
                full = urljoin(page_url, link["href"].strip())
                if urlparse(full).scheme in ("http", "https"):
                    out.append((full, "stylesheet" if "stylesheet" in rel else "preload"))
    except Exception:
        pass
    return [(u, k) for u, k in dict.fromkeys(out) if not same_site(u, page_url)]


class SupplyChainScanner(BaseScanner):
    name = "supply_chain"
    category    = "passive"
    scope       = "url"
    external    = True       # DNS lookups of third-party script hosts (no HTTP to them)
    description = "Scripts from compromised/abandoned CDNs or from domains anyone can register"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._checked: set[str] = set()

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not is_html(r.headers, r.body):
            return []
        out: list[Finding] = []
        for res, kind in third_party_resources(r.body, r.url or url):
            host = (urlparse(res).hostname or "").lower()
            rd = registrable_domain(host)
            if not rd or rd in self._checked or len(self._checked) >= MAX_HOSTS:
                continue
            self._checked.add(rd)
            f = self._known_bad(rd, res, kind, url) or await self._unregistered(rd, host, res, kind, url)
            if f:
                out.append(f)
        return out

    def _known_bad(self, rd: str, res: str, kind: str, page: str) -> Finding | None:
        if rd not in KNOWN_BAD:
            return None
        sev, what = KNOWN_BAD[rd]
        return Finding(
            title=f"{kind.capitalize()} Loaded From Compromised or Abandoned CDN: {rd}",
            severity=sev, url=page, module=self.name, confidence=Confidence.CERTAIN, cwe="CWE-829",
            description=(f"This page loads `{res}`. {what} Code from a third party runs with full access "
                         "to your page: sessions, forms, and everything the user types."),
            evidence=f"<{'script src' if kind == 'script' else 'link href'}=\"{res[:200]}\">",
            recommendation=("Remove the reference. Self-host the file (or use a reputable CDN such as "
                            "cdnjs/jsDelivr) and pin it with Subresource Integrity (integrity=\"sha384-…\"). "
                            "For polyfill.io, modern browsers need no polyfill at all."),
            references=["https://sansec.io/research/polyfill-supply-chain-attack",
                        "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity"],
            extra={"domain": rd, "resource": res, "kind": kind})

    async def _unregistered(self, rd: str, host: str, res: str, kind: str, page: str) -> Finding | None:
        if not dnsutil.HAVE_DNS:
            return None
        if not await asyncio.to_thread(dnsutil.nxdomain_is_meaningful):
            return None
        ns = await dnsutil.aresolve(rd, "NS", 3.0)
        if not ns.nxdomain:
            return None          # registered (or the resolver failed — never guess)
        soa = await dnsutil.aresolve(rd, "SOA", 3.0)
        if not soa.nxdomain:
            return None          # a second, independent "does not exist" before calling it claimable
        sev = Severity.CRITICAL if kind == "script" else Severity.HIGH
        return Finding(
            title=f"{kind.capitalize()} Loaded From an Unregistered Domain: {rd}",
            severity=sev, url=page, module=self.name, confidence=Confidence.FIRM, cwe="CWE-829",
            description=(f"This page loads `{res}`, but `{rd}` does not exist in DNS — it appears to have "
                         "expired. Anyone can register it today and serve "
                         + ("JavaScript that runs inside your site, with your users' sessions."
                            if kind == "script" else "content your page will apply (CSS can exfiltrate data).")),
            evidence=f"{host} → registrable domain {rd}: NXDOMAIN (NS and SOA)",
            recommendation=("Remove or replace the reference now; if the file is still needed, self-host it "
                            "with Subresource Integrity. Consider registering the domain yourself so nobody "
                            "else can."),
            references=["https://cwe.mitre.org/data/definitions/829.html"],
            extra={"domain": rd, "resource": res, "kind": kind})
