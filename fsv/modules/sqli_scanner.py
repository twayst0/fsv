"""
FSV Module — SQL Injection Detection (error-based)

A database error that appears *only after* a metacharacter was injected — pages that always print "SQLSTATE"
(a tutorial, an error-handling doc) are not reported. Deep profile: also tries the parameter names
SQL-backed pages usually read (`id`, `cat`, `sort`…) even when no link mentions them.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES

# "ora-" alone matches "flora-", "decora-"; Oracle errors are ORA- plus a 4-5 digit code
_ORA = re.compile(r"\bora-\d{4,5}\b")
DEEP_NAMES = ("id", "page", "p", "cat", "category", "item", "product", "pid", "uid", "user", "q", "s", "search", "sort", "order", "name")
DEEP_PAYLOADS = ("'", '"')


def db_error(body_lower: str) -> str | None:
    for sig in SQLI_ERROR_SIGNATURES:
        if sig == "ora-":
            m = _ORA.search(body_lower)
            if m:
                return m.group(0)
        elif sig in body_lower:
            return sig
    return None


class SQLiScanner(BaseScanner):
    name = "sqli"
    category    = "active"
    scope       = "url"
    description = "Error-based SQL injection in URL parameters (new errors only; common names when deep)"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._deep_done: set[tuple[str, str]] = set()

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        plan: list[tuple[str, tuple[str, ...], str]] = [(p, tuple(SQLI_PAYLOADS), params[p][0]) for p in params]
        key = (parsed.netloc, parsed.path)
        if self.deep and key not in self._deep_done:
            self._deep_done.add(key)
            plan += [(n, DEEP_PAYLOADS, "1") for n in DEEP_NAMES if n not in params]
        if not plan:
            return []

        status, _, base_body = await self.fetch(url)
        baseline_error = db_error(base_body.lower()) if status != -1 and base_body else None
        if baseline_error:
            return []                           # the page prints DB errors on its own: nothing we inject can be told apart

        findings: list[Finding] = []

        for param, payloads, value in plan:
            for payload in payloads:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = value + payload
                new_query  = urlencode(test_params)
                test_url   = urlunparse(parsed._replace(query=new_query))
                status, headers, body = await self.fetch(test_url)

                if status == -1 or not body:
                    continue

                body_lower = body.lower()
                for sig in filter(None, [db_error(body_lower)]):
                    if sig:
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
