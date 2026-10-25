"""FSV Module — HTTP Security Headers"""

import re
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import SECURITY_HEADERS


class HeadersScanner(BaseScanner):
    name = "headers"
    category    = "passive"
    scope       = "url"
    description = "Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options)"

    def _applies(self, rule: str, url: str, headers: dict, set_cookies: list[str]) -> bool:
        if rule == "https":
            return urlparse(url).scheme == "https"
        ctype = (self._header(headers, "Content-Type") or "").lower()
        if rule == "html":
            return "html" in ctype
        if rule == "sensitive":
            cfg = self.scan_config
            personal = bool(set_cookies) or bool(cfg.cookies) or any(
                h.lower() in ("authorization", "cookie") for h in cfg.headers)
            return personal and "html" in ctype
        return True

    async def scan(self, url: str) -> list[Finding]:
        resp = await self.fetch_response(url)
        if not resp.ok:
            return []
        headers = resp.headers

        findings: list[Finding] = []

        # ── Missing security headers ──────────────────────
        for header_name, meta in SECURITY_HEADERS.items():
            if not self._applies(meta.get("applies", "any"), resp.url or url, headers, resp.set_cookies):
                continue
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

        # ── Legacy XSS auditor switched on ────────────────
        xxp = self._header(headers, "X-XSS-Protection")
        if xxp and not xxp.strip().startswith("0"):
            findings.append(Finding(
                title          = "Legacy X-XSS-Protection Filter Enabled",
                severity       = Severity.INFO,
                url            = url,
                module         = self.name,
                description    = (
                    "The XSS auditor this header controls has been removed from every current browser; "
                    "where it still exists it has been abused to leak data cross-site. It adds no protection."),
                evidence       = f"X-XSS-Protection: {xxp}",
                recommendation = "Send `X-XSS-Protection: 0` (or drop it) and rely on a Content-Security-Policy.",
                references     = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"],
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
            if re.search(r"(?:^|;)\s*default-src\s+(?:[^;]*\s)?\*(?:\s|;|$)", csp):
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
