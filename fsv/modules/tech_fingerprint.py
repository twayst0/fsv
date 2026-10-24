"""FSV Module — Technology Stack Fingerprinting"""

from __future__ import annotations
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import TECH_SIGNATURES


class TechScanner(BaseScanner):
    name = "tech"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1:
            return []

        detected: list[str] = []
        all_text = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_text.lower():
                    if tech not in detected:
                        detected.append(tech)
                    break

        if not detected:
            return []

        # Check for outdated versions (simple heuristic)
        outdated_warnings = []
        body_lower = body.lower()
        headers_str = " ".join(f"{k}:{v}" for k, v in headers.items()).lower()
        combined = body_lower + " " + headers_str

        # WordPress version detection
        if "WordPress" in detected:
            import re
            wp_match = re.search(r'wordpress[/\s]+(\d+\.\d+[\.\d]*)', combined)
            if wp_match:
                outdated_warnings.append(f"WordPress {wp_match.group(1)} detected — verify it's up to date.")

        # PHP version
        php_val = self._header(headers, "X-Powered-By") or ""
        php_match = None
        if "PHP" in detected and "php/" in php_val.lower():
            import re
            php_match = re.search(r'php/(\d+\.\d+)', php_val, re.IGNORECASE)
            if php_match:
                ver = php_match.group(1)
                major, minor = map(int, ver.split(".")[:2])
                if major < 8:
                    outdated_warnings.append(
                        f"PHP {ver} detected — PHP 7.x reached end-of-life. Upgrade to PHP 8.x."
                    )

        findings: list[Finding] = [
            Finding(
                title       = "Technology Stack Identified",
                severity    = Severity.INFO,
                url         = url,
                module      = self.name,
                description = (
                    f"The following technologies were identified: {', '.join(detected)}. "
                    "This information helps attackers target known CVEs and default configurations."
                ),
                evidence    = f"Detected: {', '.join(detected)}",
                recommendation = (
                    "Keep all software up to date. Remove version disclosures from HTTP headers "
                    "and HTML source. Disable default error pages."
                ),
                references  = [],
                extra       = {"technologies": detected},
            )
        ]

        for warn in outdated_warnings:
            findings.append(Finding(
                title       = "Potentially Outdated Software Detected",
                severity    = Severity.MEDIUM,
                url         = url,
                module      = self.name,
                description = warn,
                evidence    = warn,
                recommendation = "Update to the latest stable version immediately.",
                references  = ["https://endoflife.date/"],
                cwe         = "CWE-1104",
            ))

        return findings
