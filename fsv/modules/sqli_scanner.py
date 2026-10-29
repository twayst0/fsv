"""
FSV Module — SQL Injection Detection (error-based)

A database error that appears *only after* a metacharacter was injected — pages that always print "SQLSTATE"
(a tutorial, an error-handling doc) are not reported. Deep profile: also tries the parameter names
SQL-backed pages usually read (`id`, `cat`, `sort`…) even when no link mentions them. Full profile: adds *boolean-based* (differential) detection for
injections that print no error — the page answers `… AND 1=1` like the original and `… AND 1=2` differently, twice in a row,
with the injected text itself removed from the comparison. Read-only conditions only; nothing is modified.
"""

from __future__ import annotations
import html as _html
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Confidence, Finding, Severity
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

        if self.full:
            reported = {f.parameter for f in findings}
            for param, vals in params.items():
                if param in reported:
                    continue
                def build(v, _p=param):
                    q = {k: x[0] for k, x in params.items()}
                    q[_p] = v
                    return urlunparse(parsed._replace(query=urlencode(q)))
                hit = await boolean_probe(self, url, param, vals[0], build)
                if hit:
                    findings.append(boolean_finding(self.name, url, param, *hit))
        return findings


# ── boolean-based (differential) — full profile ───────────────────────────────

# (true payload, false payload, description)
_BOOL_PAIRS = (
    ("' AND '1'='1", "' AND '1'='2", "single-quoted string"),
    ('" AND "1"="1', '" AND "1"="2', "double-quoted string"),
    (" AND 1=1", " AND 1=2", "numeric"),
)


def _norm(body: str, payloads: tuple[str, ...]) -> str:
    """The body with every echo of an injected payload removed, so reflection cannot look like a difference."""
    for p in payloads:
        for variant in (p, _html.escape(p), _html.escape(p, quote=False)):
            body = body.replace(variant, "")
    return body


def _similar(a: tuple[int, str], b: tuple[int, str], noise: int) -> bool:
    return a[0] == b[0] and abs(len(a[1]) - len(b[1])) <= max(8, noise * 3, int(0.01 * max(len(a[1]), len(b[1]))))


def _different(a: tuple[int, str], b: tuple[int, str], noise: int) -> bool:
    return a[0] != b[0] or abs(len(a[1]) - len(b[1])) > max(40, noise * 6, int(0.08 * max(len(a[1]), len(b[1]))))


async def boolean_probe(scanner, url: str, param: str, value: str, build) -> tuple[str, str, int] | None:
    """(true payload, false payload, evidence length gap) if `param` behaves like an injectable boolean condition, else None."""
    async def get(v: str) -> tuple[int, str] | None:
        r = await scanner.http.request(build(v), cache=False)            # never from the cache: we are measuring change
        return (r.status, r.body or "") if r.ok else None

    base1, base2 = await get(value), await get(value)
    if not base1 or not base2 or base1[0] >= 500 or base1[0] == 404:
        return None
    noise = abs(len(base1[1]) - len(base2[1]))
    if base1[0] != base2[0]:
        return None
    for t_pay, f_pay, _kind in _BOOL_PAIRS:
        both = (t_pay, f_pay, value + t_pay, value + f_pay)
        outcomes = []
        for _ in range(2):                                               # the pattern must repeat
            t, f = await get(value + t_pay), await get(value + f_pay)
            if not t or not f:
                outcomes = []
                break
            t, f = (t[0], _norm(t[1], both)), (f[0], _norm(f[1], both))
            b = (base1[0], _norm(base1[1], both))
            outcomes.append(_similar(t, b, noise) and _different(f, b, noise) and _different(f, t, noise))
            gap = abs(len(f[1]) - len(b[1]))
        if len(outcomes) == 2 and all(outcomes):
            return t_pay, f_pay, gap
    return None


def boolean_finding(module: str, url: str, param: str, t_pay: str, f_pay: str, gap: int) -> Finding:
    return Finding(
        title="SQL Injection (Boolean-Based)", severity=Severity.HIGH, confidence=Confidence.TENTATIVE, url=url, module=module, parameter=param,
        description=(f"The `{param}` parameter changes the page's behaviour like a SQL condition: `… {t_pay.strip()}` returns the original page while "
                     f"`… {f_pay.strip()}` returns a clearly different one, twice in a row. No database error is printed, so error-based checks miss this "
                     "(blind injection). Dynamic pages can imitate it, which is why FSV reports it as tentative — confirm manually."),
        evidence=f"Parameter: {param}\nTrue condition:  {t_pay}\nFalse condition: {f_pay}\nResponse size differs by ≈ {gap} bytes (injected text excluded)",
        recommendation=("1. Use parameterised queries / prepared statements — never concatenate input into SQL.\n2. Apply least-privilege database accounts.\n"
                        "3. Confirm with a manual test (e.g. sqlmap against a copy), then fix the root cause."),
        references=["https://owasp.org/www-community/attacks/Blind_SQL_Injection", "https://cwe.mitre.org/data/definitions/89.html"],
        cwe="CWE-89", cvss_score=8.6, extra={"technique": "boolean", "true": t_pay, "false": f_pay})
