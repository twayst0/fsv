"""FSV Module — Clickjacking Protection Check"""

from __future__ import annotations
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


class ClickjackingScanner(BaseScanner):
    name = "clickjacking"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, _ = await self.fetch(url)
        if status == -1:
            return []

        xfo = self._header(headers, "X-Frame-Options")
        csp = self._header(headers, "Content-Security-Policy") or ""
        has_frame_ancestors = "frame-ancestors" in csp.lower()

        if xfo is None and not has_frame_ancestors:
            return [Finding(
                title       = "Clickjacking — No Frame Protection",
                severity    = Severity.MEDIUM,
                url         = url,
                module      = self.name,
                description = (
                    "The page can be embedded in an <iframe> on any site because it sets "
                    "neither `X-Frame-Options` nor a CSP `frame-ancestors` directive. "
                    "This enables clickjacking, where an attacker overlays the page invisibly "
                    "and tricks users into clicking hidden elements."
                ),
                evidence    = "No X-Frame-Options header and no CSP frame-ancestors directive found.",
                recommendation = (
                    "Add one of the following:\n"
                    "• Content-Security-Policy: frame-ancestors 'self'  (modern, preferred)\n"
                    "• X-Frame-Options: DENY  (or SAMEORIGIN if framing on your own site is needed)"
                ),
                references  = [
                    "https://owasp.org/www-community/attacks/Clickjacking",
                    "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
                ],
                cwe         = "CWE-1021",
                cvss_score  = 4.3,
            )]

        # Weak X-Frame-Options value
        if xfo and xfo.upper() not in ("DENY", "SAMEORIGIN") and not xfo.upper().startswith("ALLOW-FROM"):
            return [Finding(
                title       = "Clickjacking — Invalid X-Frame-Options Value",
                severity    = Severity.LOW,
                url         = url,
                module      = self.name,
                description = (
                    f"X-Frame-Options has a non-standard value (`{xfo}`) that browsers will ignore."
                ),
                evidence    = f"X-Frame-Options: {xfo}",
                recommendation = "Use a valid value: DENY or SAMEORIGIN.",
                references  = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"],
                cwe         = "CWE-1021",
            )]

        return []
