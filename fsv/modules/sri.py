"""
FSV Module — Subresource Integrity (SRI)

Passive. Parses the page and flags third-party <script>/<link rel=stylesheet>
resources loaded without an `integrity` attribute. Missing SRI means a CDN or
on-path compromise of that resource silently runs in every visitor's browser
(a software-integrity / supply-chain risk).
"""

from __future__ import annotations
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


class SRIScanner(BaseScanner):
    name = "sri"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or not body:
            return []
        if "html" not in (self._header(headers, "Content-Type") or "").lower() \
           and "<html" not in body[:2000].lower():
            return []

        origin = urlparse(url).netloc
        soup = BeautifulSoup(body, "lxml")
        findings: list[Finding] = []
        offenders: list[str] = []

        def _external(src: str) -> bool:
            if not src:
                return False
            p = urlparse(urljoin(url, src))
            return bool(p.netloc) and p.netloc != origin

        for tag in soup.find_all("script"):
            src = tag.get("src") or ""
            if _external(src) and not tag.get("integrity"):
                offenders.append(f"<script src=\"{src}\">")

        for tag in soup.find_all("link"):
            rel = " ".join(tag.get("rel") or []).lower()
            href = tag.get("href") or ""
            if ("stylesheet" in rel or "preload" in rel) and _external(href) \
               and not tag.get("integrity"):
                offenders.append(f"<link href=\"{href}\">")

        if offenders:
            sample = "\n".join(offenders[:12])
            more = f"\n… and {len(offenders) - 12} more" if len(offenders) > 12 else ""
            findings.append(Finding(
                title       = "Third-Party Resources Without Subresource Integrity (SRI)",
                severity    = Severity.LOW,
                confidence  = Confidence.FIRM,
                url         = url,
                module      = self.name,
                description = (
                    f"{len(offenders)} cross-origin script/style resource(s) are loaded without "
                    "an `integrity` attribute. If the third-party host or CDN is compromised, or "
                    "traffic to it is tampered with, malicious code runs with full privileges in "
                    "the context of this site."
                ),
                evidence    = sample + more,
                recommendation = (
                    "Add an `integrity` (SHA-384 hash) and `crossorigin` attribute to every "
                    "third-party <script> and <link rel=stylesheet>. Pin exact versions so the "
                    "hash stays valid, or self-host the asset from your own origin."
                ),
                cwe         = "CWE-345",
                cvss_score  = 4.2,
                extra       = {"resources": offenders[:50]},
            ))

        return findings
