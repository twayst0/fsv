"""FSV Module — HTTP Methods / Verb Tampering"""

from __future__ import annotations
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Confidence, Finding, Severity


# Methods a REST API legitimately accepts. `Allow` only says the route has a handler for them —
# not that anyone may use them — so they are listed for review, never reported as "dangerous".
_REVIEW = ("PUT", "DELETE", "PATCH")
_MARKER = "fsv-trace-probe"


class HTTPMethodsScanner(BaseScanner):
    name = "http_methods"
    category    = "passive"
    scope       = "site"
    description = "TRACE echo (verified), CONNECT, advertised write methods"

    async def scan(self, url: str) -> list[Finding]:
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}/"

        findings: list[Finding] = []

        # Ask the server which methods it allows. Access-Control-Allow-Methods is CORS
        # policy, not what the server implements, so it is not used here.
        status, headers, _ = await self.fetch(base_url, method="OPTIONS")
        allow = self._header(headers, "Allow") or ""
        allowed = {m.strip().upper() for m in allow.split(",") if m.strip()}

        if allowed:
            write = sorted(m for m in allowed if m in _REVIEW)
            findings.append(Finding(
                title       = "HTTP Methods Enumerated (OPTIONS)",
                severity    = Severity.INFO,
                url         = base_url,
                module      = self.name,
                description = (
                    f"The server advertises: {', '.join(sorted(allowed))}."
                    + (f" {', '.join(write)} only means a handler exists; confirm each is "
                       "authenticated and authorised." if write else "")),
                evidence    = f"Allow: {allow}",
                recommendation = "Disable any HTTP methods not required by the application.",
                references  = ["https://owasp.org/www-project-web-security-testing-guide/"],
                extra       = {"methods": sorted(allowed)},
            ))

        # TRACE: verify instead of trusting Allow — an echo of our own header is proof.
        tstatus, _, tbody = await self.fetch(
            base_url, method="TRACE", headers={"X-FSV-Probe": _MARKER}, allow_redirects=False)
        echoed = (tbody or "").lstrip().upper().startswith("TRACE ") and _MARKER in (tbody or "")
        if tstatus == 200 and echoed:
            findings.append(Finding(
                title       = "Dangerous HTTP Method Enabled: TRACE",
                severity    = Severity.MEDIUM,
                url         = base_url,
                module      = self.name,
                description = ("TRACE echoes the request back, including headers. Combined with another "
                               "bug it enables Cross-Site Tracing (XST) and can reveal headers a proxy "
                               "adds (internal auth, client certificates)."),
                evidence    = f"TRACE / → {tstatus}; our X-FSV-Probe header was echoed in the body",
                recommendation = "Disable TRACE (Apache: `TraceEnable off`; most other servers reject it by default).",
                references  = ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                cwe         = "CWE-693",
                confidence  = Confidence.CERTAIN,
            ))
        elif "TRACE" in allowed or "TRACK" in allowed:
            findings.append(Finding(
                title       = "TRACE Advertised but Not Echoing",
                severity    = Severity.INFO,
                url         = base_url,
                module      = self.name,
                description = "The Allow header lists TRACE/TRACK, but a TRACE request did not echo the request back.",
                evidence    = f"Allow: {allow}",
                recommendation = "Remove TRACE/TRACK from the advertised methods to avoid confusion in audits.",
                references  = ["https://owasp.org/www-community/attacks/Cross_Site_Tracing"],
                confidence  = Confidence.TENTATIVE,
            ))

        if "CONNECT" in allowed:
            findings.append(Finding(
                title       = "Dangerous HTTP Method Enabled: CONNECT",
                severity    = Severity.MEDIUM,
                url         = base_url,
                module      = self.name,
                description = "CONNECT is advertised; a misconfigured server may let anyone use it as a proxy.",
                evidence    = f"Allow: {allow}",
                recommendation = "Disable CONNECT unless this host is meant to be a forward proxy.",
                references  = ["https://cwe.mitre.org/data/definitions/441.html"],
                cwe         = "CWE-441",
                confidence  = Confidence.TENTATIVE,
            ))

        return findings
