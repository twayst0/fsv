"""FSV Module — SQL Injection Detection (error-based)"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES


class SQLiScanner(BaseScanner):
    name = "sqli"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        findings: list[Finding] = []

        for param in params:
            for payload in SQLI_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = test_params[param] + payload
                new_query  = urlencode(test_params)
                test_url   = urlunparse(parsed._replace(query=new_query))
                status, headers, body = await self.fetch(test_url)

                if status == -1 or not body:
                    continue

                body_lower = body.lower()
                for sig in SQLI_ERROR_SIGNATURES:
                    if sig in body_lower:
                        findings.append(Finding(
                            title       = "SQL Injection (Error-Based)",
                            severity    = Severity.CRITICAL,
                            url         = url,
                            module      = self.name,
                            parameter   = param,
                            description = (
                                f"A SQL injection vulnerability was detected in the `{param}` parameter. "
                                "The server returned a database error message when a SQL metacharacter "
                                "was injected. This indicates the application is passing unsanitised "
                                "user input directly to a SQL query."
                            ),
                            evidence    = (
                                f"Parameter: {param}\n"
                                f"Payload: {payload}\n"
                                f"DB error signature matched: '{sig}'\n"
                                f"Test URL: {test_url[:200]}"
                            ),
                            recommendation = (
                                "1. Use parameterised queries / prepared statements — NEVER concatenate "
                                "user input into SQL strings.\n"
                                "2. Use an ORM (SQLAlchemy, Django ORM, Hibernate).\n"
                                "3. Apply least-privilege database accounts.\n"
                                "4. Disable verbose error messages in production.\n"
                                "5. Implement input validation and an application WAF."
                            ),
                            references  = [
                                "https://owasp.org/www-community/attacks/SQL_Injection",
                                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
                                "https://cwe.mitre.org/data/definitions/89.html",
                            ],
                            cwe         = "CWE-89",
                            cvss_score  = 9.8,
                            extra       = {"payload": payload, "db_error": sig},
                        ))
                        break  # One finding per parameter

                if any(f.parameter == param for f in findings):
                    break  # Already found SQLi in this param

        return findings
