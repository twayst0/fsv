"""FSV Module — Host Header Injection"""

from __future__ import annotations
from urllib.parse import urlparse
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


EVIL = "fsv-injected.example.net"


class HostHeaderScanner(BaseScanner):
    name     = "host_header_injection"
    category = "active"
    scope    = "url"
    description = "Host header injection (redirect/cache poisoning)"

    async def scan(self, url: str) -> list[Finding]:
        # Send a spoofed Host header and see if the app trusts it
        status, headers, body = await self.fetch(
            url, headers={"Host": EVIL}, allow_redirects=False
        )
        if status == -1 or status >= 400:
            # The app rejected the forged Host (Django's DisallowedHost is a 400). A debug error page
            # may still echo it, but nothing was trusted — that is the debug_mode module's finding.
            return []

        findings: list[Finding] = []

        # 1) reflected in Location (redirect poisoning)
        location = self._header(headers, "Location") or ""
        if EVIL in location:
            findings.append(Finding(
                title       = "Host Header Injection — Reflected in Redirect",
                severity    = Severity.MEDIUM,
                url         = url,
                module      = self.name,
                confidence  = Confidence.FIRM,
                description = (
                    "The application reflects the attacker-controlled Host header into the "
                    "Location redirect. This can poison password-reset links and enable "
                    "web-cache poisoning or redirect-based phishing."
                ),
                evidence    = f"Sent Host: {EVIL}\nLocation: {location}",
                recommendation = (
                    "Do not build absolute URLs from the Host header. Validate Host against an "
                    "allowlist of expected domains and use a configured canonical base URL."
                ),
                references  = [
                    "https://portswigger.net/web-security/host-header",
                    "https://cwe.mitre.org/data/definitions/644.html",
                ],
                cwe         = "CWE-644",
            ))

        # 2) reflected in body (links/absolute URLs)
        elif body and EVIL in body:
            findings.append(Finding(
                title       = "Host Header Injection — Reflected in Response Body",
                severity    = Severity.LOW,
                url         = url,
                module      = self.name,
                confidence  = Confidence.TENTATIVE,
                description = (
                    "The attacker-controlled Host header is reflected in the response body "
                    "(e.g. in generated links). Depending on where it is used this may enable "
                    "cache poisoning or link hijacking."
                ),
                evidence    = f"Sent Host: {EVIL} — value reflected in response body.",
                recommendation = (
                    "Use a configured canonical hostname when generating links; never trust "
                    "the Host header. Validate it against an allowlist."
                ),
                references  = ["https://portswigger.net/web-security/host-header"],
                cwe         = "CWE-644",
            ))

        return findings
