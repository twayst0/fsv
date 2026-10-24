"""FSV Module — security.txt / Responsible Disclosure (RFC 9116)"""

from __future__ import annotations
from urllib.parse import urlparse
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


class SecurityTxtScanner(BaseScanner):
    name     = "security_txt"
    category = "passive"
    scope    = "site"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"

        for path in ("/.well-known/security.txt", "/security.txt"):
            status, headers, body = await self.fetch(base + path)
            ctype = (self._header(headers, "Content-Type") or "").lower()
            if status == 200 and body and ("text/plain" in ctype or "contact:" in body.lower()):
                has_contact = "contact:" in body.lower()
                has_expires = "expires:" in body.lower()
                notes = []
                if not has_contact: notes.append("missing Contact field")
                if not has_expires: notes.append("missing Expires field (required by RFC 9116)")
                sev = Severity.LOW if notes else Severity.INFO
                return [Finding(
                    title       = "security.txt Present" + (" (incomplete)" if notes else ""),
                    severity    = sev,
                    url         = base + path,
                    module      = self.name,
                    confidence  = Confidence.CERTAIN,
                    description = (
                        "A security.txt file was found, giving researchers a disclosure channel."
                        + (f" However: {', '.join(notes)}." if notes else "")
                    ),
                    evidence    = body[:300],
                    recommendation = (
                        "Ensure security.txt includes Contact and Expires fields per RFC 9116."
                        if notes else "Keep the Expires field current."
                    ),
                    references  = ["https://www.rfc-editor.org/rfc/rfc9116"],
                )]

        return [Finding(
            title       = "No security.txt / Disclosure Policy",
            severity    = Severity.INFO,
            url         = base + "/.well-known/security.txt",
            module      = self.name,
            confidence  = Confidence.CERTAIN,
            description = (
                "No security.txt file was found. There is no standard channel for security "
                "researchers to report vulnerabilities responsibly."
            ),
            recommendation = (
                "Publish /.well-known/security.txt (RFC 9116) with a Contact and Expires field "
                "so researchers can report issues to you."
            ),
            references  = ["https://securitytxt.org/", "https://www.rfc-editor.org/rfc/rfc9116"],
        )]
