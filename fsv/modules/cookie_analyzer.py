"""FSV Module — Cookie Security Flags"""

from __future__ import annotations
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


class CookieScanner(BaseScanner):
    name = "cookies"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, _ = await self.fetch(url)
        if status == -1:
            return []

        findings: list[Finding] = []
        set_cookie_headers: list[str] = []

        # aiohttp merges Set-Cookie; retrieve raw
        for k, v in headers.items():
            if k.lower() == "set-cookie":
                set_cookie_headers.append(v)

        # Also check cookie jar for the session
        for cookie_str in set_cookie_headers:
            parts  = [p.strip() for p in cookie_str.split(";")]
            name   = parts[0].split("=")[0].strip() if parts else "unknown"
            flags  = {p.lower().split("=")[0].strip() for p in parts[1:]}

            is_secure_name = any(
                kw in name.lower()
                for kw in ("session", "auth", "token", "jwt", "csrf", "sid", "id")
            )

            # Missing Secure flag
            if "secure" not in flags:
                sev = Severity.HIGH if is_secure_name else Severity.MEDIUM
                findings.append(Finding(
                    title       = f"Cookie Missing Secure Flag: `{name}`",
                    severity    = sev,
                    url         = url,
                    module      = self.name,
                    description = (
                        f"The cookie `{name}` is set without the `Secure` flag. "
                        "It can be transmitted over unencrypted HTTP connections, "
                        "allowing network interception."
                    ),
                    evidence    = f"Set-Cookie: {cookie_str[:200]}",
                    recommendation = f"Add the `Secure` flag: Set-Cookie: {name}=...; Secure",
                    references  = [
                        "https://owasp.org/www-community/controls/SecureCookieAttribute",
                    ],
                    cwe         = "CWE-614",
                    cvss_score  = 5.9,
                ))

            # Missing HttpOnly flag
            if "httponly" not in flags:
                sev = Severity.HIGH if is_secure_name else Severity.MEDIUM
                findings.append(Finding(
                    title       = f"Cookie Missing HttpOnly Flag: `{name}`",
                    severity    = sev,
                    url         = url,
                    module      = self.name,
                    description = (
                        f"The cookie `{name}` does not have the `HttpOnly` flag. "
                        "JavaScript can read this cookie, making it vulnerable to theft "
                        "via XSS attacks."
                    ),
                    evidence    = f"Set-Cookie: {cookie_str[:200]}",
                    recommendation = f"Add `HttpOnly`: Set-Cookie: {name}=...; HttpOnly",
                    references  = [
                        "https://owasp.org/www-community/HttpOnly",
                    ],
                    cwe         = "CWE-1004",
                    cvss_score  = 5.4,
                ))

            # Missing SameSite flag
            has_samesite = any("samesite" in f for f in flags)
            if not has_samesite:
                findings.append(Finding(
                    title       = f"Cookie Missing SameSite Attribute: `{name}`",
                    severity    = Severity.LOW,
                    url         = url,
                    module      = self.name,
                    description = (
                        f"The cookie `{name}` has no `SameSite` attribute. "
                        "This may allow cross-site request forgery (CSRF) attacks."
                    ),
                    evidence    = f"Set-Cookie: {cookie_str[:200]}",
                    recommendation = f"Set SameSite=Lax or Strict: Set-Cookie: {name}=...; SameSite=Lax",
                    references  = [
                        "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite",
                    ],
                    cwe         = "CWE-1275",
                ))

            # SameSite=None without Secure (invalid and insecure)
            samesite_none = any(
                "samesite=none" in f for f in flags
            )
            if samesite_none and "secure" not in flags:
                findings.append(Finding(
                    title       = f"Cookie SameSite=None Without Secure: `{name}`",
                    severity    = Severity.MEDIUM,
                    url         = url,
                    module      = self.name,
                    description = (
                        f"Cookie `{name}` has SameSite=None but is missing the Secure flag. "
                        "Modern browsers will reject this cookie."
                    ),
                    evidence    = f"Set-Cookie: {cookie_str[:200]}",
                    recommendation = "Add the Secure flag when using SameSite=None.",
                    references  = [],
                    cwe         = "CWE-614",
                ))

        return findings
