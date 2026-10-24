"""FSV Module — CORS Misconfiguration"""

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


class CORSScanner(BaseScanner):
    name = "cors"

    async def scan(self, url: str) -> list[Finding]:
        findings: list[Finding] = []

        # Test with an attacker-controlled origin
        evil_origin = "https://evil.fsv-test.com"
        status, headers, _ = await self.fetch(
            url,
            headers={"Origin": evil_origin},
        )
        if status == -1:
            return []

        acao  = self._header(headers, "Access-Control-Allow-Origin")
        acac  = self._header(headers, "Access-Control-Allow-Credentials")

        if acao == "*":
            sev = Severity.MEDIUM
            findings.append(Finding(
                title       = "CORS Wildcard Origin Allowed",
                severity    = sev,
                url         = url,
                module      = self.name,
                description = (
                    "The server returns `Access-Control-Allow-Origin: *`, allowing any website "
                    "to make cross-origin requests and read responses. Combined with sensitive "
                    "data in the response this can lead to data theft."
                ),
                evidence    = f"Access-Control-Allow-Origin: {acao}",
                recommendation = (
                    "Restrict CORS to known, trusted origins. Maintain an allowlist of "
                    "permitted origins and reflect only those."
                ),
                references  = [
                    "https://portswigger.net/web-security/cors",
                    "https://owasp.org/www-project-web-security-testing-guide/",
                ],
                cwe         = "CWE-942",
                cvss_score  = 6.5,
            ))

        elif acao == evil_origin:
            sev = Severity.HIGH if (acac and acac.lower() == "true") else Severity.MEDIUM
            desc = (
                "The server reflects arbitrary origins in `Access-Control-Allow-Origin`. "
                "An attacker can read cross-origin responses from any site."
            )
            if acac and acac.lower() == "true":
                desc += (
                    " Credentials (cookies, auth headers) are also included "
                    "(`Access-Control-Allow-Credentials: true`), making this critically "
                    "exploitable for authenticated session hijacking."
                )
                sev = Severity.CRITICAL

            findings.append(Finding(
                title       = "CORS Arbitrary Origin Reflection",
                severity    = sev,
                url         = url,
                module      = self.name,
                description = desc,
                evidence    = (
                    f"Request Origin: {evil_origin}\n"
                    f"Access-Control-Allow-Origin: {acao}\n"
                    f"Access-Control-Allow-Credentials: {acac or 'not set'}"
                ),
                recommendation = (
                    "1. Implement a strict origin allowlist — do not reflect arbitrary origins.\n"
                    "2. Never combine `Access-Control-Allow-Credentials: true` with a dynamic origin.\n"
                    "3. Validate the Origin header server-side before reflecting it."
                ),
                references  = [
                    "https://portswigger.net/web-security/cors",
                    "https://cheatsheetseries.owasp.org/cheatsheets/CORS_Cheat_Sheet.html",
                ],
                cwe         = "CWE-942",
                cvss_score  = 9.0 if sev == Severity.CRITICAL else 6.5,
            ))

        # Null origin bypass
        status2, headers2, _ = await self.fetch(
            url, headers={"Origin": "null"}
        )
        acao2 = self._header(headers2, "Access-Control-Allow-Origin")
        if acao2 == "null":
            findings.append(Finding(
                title       = "CORS Null Origin Allowed",
                severity    = Severity.HIGH,
                url         = url,
                module      = self.name,
                description = (
                    "The server allows `Origin: null`, which can be triggered by "
                    "sandboxed iframes, data: URIs, or redirected requests — "
                    "enabling cross-origin data theft."
                ),
                evidence    = "Access-Control-Allow-Origin: null",
                recommendation = "Remove `null` from your CORS origin allowlist.",
                references  = ["https://portswigger.net/web-security/cors"],
                cwe         = "CWE-942",
                cvss_score  = 7.5,
            ))

        return findings
