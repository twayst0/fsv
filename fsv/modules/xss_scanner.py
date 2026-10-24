"""FSV Module — Reflected XSS Detection"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import XSS_PAYLOADS


class XSSScanner(BaseScanner):
    name = "xss"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        findings: list[Finding] = []

        for param in params:
            for payload in XSS_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                new_query  = urlencode(test_params)
                test_url   = urlunparse(parsed._replace(query=new_query))
                status, headers, body = await self.fetch(test_url)

                if status == -1 or not body:
                    continue

                # Check if payload is reflected unencoded
                if payload in body:
                    findings.append(Finding(
                        title       = "Reflected Cross-Site Scripting (XSS)",
                        severity    = Severity.HIGH,
                        url         = url,
                        module      = self.name,
                        parameter   = param,
                        description = (
                            f"A reflected XSS vulnerability was detected in the `{param}` parameter. "
                            "Attacker-controlled input is reflected in the HTML response without proper "
                            "encoding, allowing malicious scripts to execute in a victim's browser."
                        ),
                        evidence    = (
                            f"Parameter: {param}\n"
                            f"Payload injected: {payload}\n"
                            f"Payload reflected in response: YES\n"
                            f"Test URL: {test_url[:200]}"
                        ),
                        recommendation = (
                            "1. Encode all user input before rendering in HTML (HTML entity encoding).\n"
                            "2. Implement a strict Content-Security-Policy header.\n"
                            "3. Use a modern framework that auto-escapes output (React, Angular, Django templates).\n"
                            "4. Apply input validation to reject unexpected characters."
                        ),
                        references  = [
                            "https://owasp.org/www-community/attacks/xss/",
                            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/79.html",
                        ],
                        cwe         = "CWE-79",
                        cvss_score  = 6.1,
                        extra       = {"payload": payload},
                    ))
                    break  # One finding per parameter is enough

        return findings
