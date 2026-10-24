"""FSV Module — HTTP Methods / Verb Tampering"""

from __future__ import annotations
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


DANGEROUS = {
    "TRACE":  (Severity.MEDIUM, "CWE-693",
               "TRACE is enabled, enabling Cross-Site Tracing (XST) which can expose "
               "cookies and auth headers even when HttpOnly is set."),
    "TRACK":  (Severity.MEDIUM, "CWE-693",
               "TRACK (IIS equivalent of TRACE) is enabled and can be abused for XST."),
    "PUT":    (Severity.HIGH, "CWE-650",
               "PUT is enabled, potentially allowing attackers to upload arbitrary files "
               "to the server."),
    "DELETE": (Severity.HIGH, "CWE-650",
               "DELETE is enabled, potentially allowing attackers to remove server resources."),
    "CONNECT":(Severity.MEDIUM, "CWE-441",
               "CONNECT is enabled and may allow the server to be abused as a proxy."),
    "PATCH":  (Severity.LOW, "CWE-650",
               "PATCH is enabled; verify it is intentional and access-controlled."),
}


class HTTPMethodsScanner(BaseScanner):
    name = "http_methods"

    async def scan(self, url: str) -> list[Finding]:
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        findings: list[Finding] = []

        # Ask the server which methods it allows
        status, headers, _ = await self.fetch(base_url, method="OPTIONS")
        allow = (self._header(headers, "Allow") or
                 self._header(headers, "Access-Control-Allow-Methods") or "")
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

        if allowed:
            findings.append(Finding(
                title       = "HTTP Methods Enumerated (OPTIONS)",
                severity    = Severity.INFO,
                url         = base_url,
                module      = self.name,
                description = f"The server advertises the following methods: {', '.join(sorted(allowed))}.",
                evidence    = f"Allow: {allow}",
                recommendation = "Disable any HTTP methods not required by the application.",
                references  = ["https://owasp.org/www-project-web-security-testing-guide/"],
            ))

        for method, (sev, cwe, desc) in DANGEROUS.items():
            if method in allowed:
                findings.append(Finding(
                    title       = f"Dangerous HTTP Method Enabled: {method}",
                    severity    = sev,
                    url         = base_url,
                    module      = self.name,
                    description = desc,
                    evidence    = f"Server Allow header lists: {method}",
                    recommendation = (
                        f"Disable the {method} method unless explicitly required. "
                        "Configure your web server / framework to reject it."
                    ),
                    references  = [
                        "https://owasp.org/www-community/attacks/Cross_Site_Tracing",
                        "https://cwe.mitre.org/data/definitions/650.html",
                    ],
                    cwe         = cwe,
                ))

        return findings
