"""FSV Module — HTTP Security Headers"""

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import SECURITY_HEADERS


class HeadersScanner(BaseScanner):
    name = "headers"
    category    = "passive"
    scope       = "url"
    description = "Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options)"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, _ = await self.fetch(url)
        if status == -1:
            return []

        findings: list[Finding] = []

        # ── Missing security headers ──────────────────────
        for header_name, meta in SECURITY_HEADERS.items():
            value = self._header(headers, header_name)
            if value is None:
                findings.append(Finding(
                    title          = f"Missing Security Header: {header_name}",
                    severity       = Severity(meta["severity"]),
                    url            = url,
                    module         = self.name,
                    description    = (
                        f"The response does not include the `{header_name}` header. "
                        f"{meta['desc']}."
                    ),
                    evidence       = f"Header '{header_name}' not present in response.",
                    recommendation = meta["recommendation"],
                    references     = ["https://owasp.org/www-project-secure-headers/"],
                    cwe            = "CWE-693",
                ))

        # ── Server header leakage ─────────────────────────
        server = self._header(headers, "Server")
        if server and any(c.isdigit() for c in server):
            findings.append(Finding(
                title          = "Server Version Disclosure",
                severity       = Severity.LOW,
                url            = url,
                module         = self.name,
                description    = (
                    f"The `Server` header reveals the server software version: `{server}`. "
                    "Attackers can use this to look up known CVEs."
                ),
                evidence       = f"Server: {server}",
                recommendation = "Configure your web server to hide or genericise the Server header.",
                references     = ["https://owasp.org/www-project-web-security-testing-guide/"],
                cwe            = "CWE-200",
            ))

        # ── X-Powered-By leakage ──────────────────────────
        xpb = self._header(headers, "X-Powered-By")
        if xpb:
            findings.append(Finding(
                title          = "Technology Stack Disclosure via X-Powered-By",
                severity       = Severity.LOW,
                url            = url,
                module         = self.name,
                description    = (
                    f"`X-Powered-By: {xpb}` reveals backend technology information."
                ),
                evidence       = f"X-Powered-By: {xpb}",
                recommendation = "Remove the X-Powered-By header in your web server / framework config.",
                references     = ["https://owasp.org/www-project-secure-headers/"],
                cwe            = "CWE-200",
            ))

        # ── HSTS pre-load check ───────────────────────────
        hsts = self._header(headers, "Strict-Transport-Security")
        if hsts:
            if "max-age" in hsts.lower():
                try:
                    age = int(
                        [p for p in hsts.lower().split(";") if "max-age" in p][0]
                        .split("=")[1].strip()
                    )
                    if age < 15768000:  # < 6 months
                        findings.append(Finding(
                            title          = "HSTS max-age Too Short",
                            severity       = Severity.LOW,
                            url            = url,
                            module         = self.name,
                            description    = (
                                f"HSTS max-age is only {age} seconds (< 6 months). "
                                "Browsers will not include the site in the HSTS preload list."
                            ),
                            evidence       = f"Strict-Transport-Security: {hsts}",
                            recommendation = "Set max-age to at least 31536000 (1 year) and add 'includeSubDomains; preload'.",
                            references     = ["https://hstspreload.org/"],
                            cwe            = "CWE-523",
                        ))
                except (IndexError, ValueError):
                    pass

        # ── CSP quality check ─────────────────────────────
        csp = self._header(headers, "Content-Security-Policy")
        if csp:
            if "unsafe-inline" in csp or "unsafe-eval" in csp:
                findings.append(Finding(
                    title          = "Weak Content Security Policy (unsafe-inline / unsafe-eval)",
                    severity       = Severity.MEDIUM,
                    url            = url,
                    module         = self.name,
                    description    = (
                        "The CSP policy contains `unsafe-inline` or `unsafe-eval`, which "
                        "significantly weakens XSS protection."
                    ),
                    evidence       = f"Content-Security-Policy: {csp[:300]}",
                    recommendation = (
                        "Remove 'unsafe-inline' and 'unsafe-eval'. "
                        "Use nonces or hashes for inline scripts instead."
                    ),
                    references     = [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
                        "https://csp.withgoogle.com/",
                    ],
                    cwe            = "CWE-1021",
                ))
            if "*" in csp and "default-src *" in csp.replace(" ", ""):
                findings.append(Finding(
                    title          = "CSP Wildcard Source Detected",
                    severity       = Severity.HIGH,
                    url            = url,
                    module         = self.name,
                    description    = "CSP uses wildcard (*) as source, effectively disabling XSS protection.",
                    evidence       = f"Content-Security-Policy: {csp[:300]}",
                    recommendation = "Replace wildcard sources with explicit, trusted origins.",
                    references     = ["https://owasp.org/www-project-secure-headers/"],
                    cwe            = "CWE-1021",
                ))

        return findings
