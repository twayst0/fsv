"""FSV Module — Subresource Integrity (SRI) on third-party scripts/styles"""

from __future__ import annotations
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


class SRIScanner(BaseScanner):
    name     = "sri"
    category = "passive"
    scope    = "url"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or "html" not in (self._header(headers, "Content-Type") or ""):
            return []

        page_host = urlparse(url).netloc.lower()
        soup = BeautifulSoup(body, "lxml")
        missing: list[str] = []

        for tag in soup.find_all("script", src=True):
            src = urljoin(url, tag["src"])
            if self._third_party(src, page_host) and not tag.get("integrity"):
                missing.append(src)
        for tag in soup.find_all("link", href=True):
            rel = " ".join(tag.get("rel") or []).lower()
            if "stylesheet" not in rel:
                continue
            href = urljoin(url, tag["href"])
            if self._third_party(href, page_host) and not tag.get("integrity"):
                missing.append(href)

        if not missing:
            return []
        missing = sorted(set(missing))
        return [Finding(
            title       = "Third-Party Resources Without Subresource Integrity",
            severity    = Severity.LOW,
            confidence  = Confidence.CERTAIN,
            url         = url,
            module      = self.name,
            description = (
                f"{len(missing)} script/stylesheet(s) are loaded from other origins without an "
                "`integrity` attribute. If that CDN or host is compromised, modified code runs "
                "with full access to this page."
            ),
            evidence    = "\n".join(missing[:15]) + ("\n…" if len(missing) > 15 else ""),
            recommendation = (
                "Add `integrity=\"sha384-…\"` and `crossorigin=\"anonymous\"` to each external "
                "<script>/<link>, or self-host the files. Tools such as srihash.org generate hashes."
            ),
            references  = [
                "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
                "https://cheatsheetseries.owasp.org/cheatsheets/Third_Party_Javascript_Management_Cheat_Sheet.html",
            ],
            cwe         = "CWE-353",
            extra       = {"resources": missing},
        )]

    @staticmethod
    def _third_party(resource: str, page_host: str) -> bool:
        p = urlparse(resource)
        return p.scheme in ("http", "https") and p.netloc.lower() != page_host
