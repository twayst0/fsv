"""
FSV Module — Server-Side Template Injection (SSTI) Detection

Uses benign arithmetic markers only (e.g. {{7*7}} → 49). FSV never executes
code or reads files on the target — it just checks whether a template engine
evaluated a harmless math expression, which signals an injectable template.
"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.core.probing import reflected_candidates


# Template syntaxes, one benign arithmetic marker each. `{0}`/`{1}` are filled with plain str.replace — an earlier
# version used str.format on "{{{0}*{1}}}", which yields `{7331*7}` (single braces): the Jinja2/Twig/Nunjucks
# probe never contained the syntax it was meant to test, so that whole class went undetected.
PROBES = [
    "{{A*B}}",      # Jinja2 / Twig / Nunjucks / Handlebars-like
    "${A*B}",       # JSP/Spring EL, Freemarker, Velocity, JS template literals
    "#{A*B}",       # Ruby interpolation, Thymeleaf-style
    "<%= A*B %>",   # ERB / EJS
    "{A*B}",        # Smarty
]
A, B = 7331, 7  # 7331 * 7 = 51317 — unlikely to appear by accident
EXPECT = str(A * B)


class SSTIScanner(BaseScanner):
    name     = "ssti"
    category = "active"
    scope    = "url"
    description = "Server-Side Template Injection (benign math marker; hidden reflected parameters when deep)"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._discovery: dict = {}

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if self.deep:                                   # templates evaluate what they echo: probe names the page reflects
            for n in await reflected_candidates(self, url, self._discovery):
                params.setdefault(n, [""])
        if not params:
            return []

        findings: list[Finding] = []

        for param in params:
            for tmpl in PROBES:
                payload = tmpl.replace("A", str(A)).replace("B", str(B))
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                test_url = urlunparse(parsed._replace(query=urlencode(test_params)))

                status, _, body = await self.fetch(test_url)
                if status == -1 or not body:
                    continue

                # The engine evaluated the expression if the product appears
                # but the literal payload does not (i.e. it was rendered).
                if EXPECT in body and payload not in body:
                    findings.append(Finding(
                        title       = "Server-Side Template Injection (SSTI)",
                        severity    = Severity.CRITICAL,
                        url         = url,
                        module      = self.name,
                        parameter   = param,
                        confidence  = Confidence.FIRM,
                        description = (
                            f"The `{param}` parameter is evaluated by a server-side template "
                            "engine. A benign arithmetic marker was computed by the server, "
                            "confirming template injection. SSTI commonly escalates to remote "
                            "code execution."
                        ),
                        evidence    = (
                            f"Parameter: {param}\n"
                            f"Marker sent: {payload}\n"
                            f"Server computed {A}*{B} = {EXPECT} in the response."
                        ),
                        recommendation = (
                            "Never pass user input into template source. Use a logic-less "
                            "template context and pass user data strictly as sandboxed variables. "
                            "Keep template engines patched and run them in sandbox mode where available."
                        ),
                        references  = [
                            "https://portswigger.net/web-security/server-side-template-injection",
                            "https://owasp.org/www-project-web-security-testing-guide/",
                            "https://cwe.mitre.org/data/definitions/1336.html",
                        ],
                        cwe         = "CWE-1336",
                        cvss_score  = 9.0,
                    ))
                    break  # one finding per parameter

            if any(f.parameter == param for f in findings):
                continue

        return findings
