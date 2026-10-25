"""FSV Module — Cookie Security Flags"""

from __future__ import annotations
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
import re

# session/auth-looking cookie names ("id" alone matched far too much before)
_SENSITIVE_NAME = re.compile(
    r"(sess|auth|token|jwt|remember|login|(^|[_\-.])sid($|[_\-.])|^id$)",
    re.IGNORECASE,
)
# Anti-CSRF tokens (Django `csrftoken`, Angular/Laravel `XSRF-TOKEN`, `_csrf` …). In the
# double-submit pattern the page's own JavaScript MUST read them, so HttpOnly is wrong advice,
# and stealing one gains nothing without the victim's session. Not a session cookie.
_CSRF_NAME = re.compile(r"(csrf|xsrf)", re.IGNORECASE)


class CookieScanner(BaseScanner):
    name = "cookies"
    category    = "passive"
    scope       = "url"
    description = "Cookie flags (Secure, HttpOnly, SameSite)"

    async def scan(self, url: str) -> list[Finding]:
        resp = await self.fetch_response(url)
        if not resp.ok:
            return []

        findings: list[Finding] = []

        for cookie_str in resp.set_cookies:
            parts  = [p.strip() for p in cookie_str.split(";")]
            name   = parts[0].split("=")[0].strip() if parts else "unknown"
            flags  = {p.lower().split("=")[0].strip() for p in parts[1:]}
            # attribute → value ("samesite" → "none"); `flags` alone loses the value
            attrs  = {p.split("=", 1)[0].strip().lower(): (p.split("=", 1)[1].strip() if "=" in p else "")
                      for p in parts[1:]}

            is_csrf = bool(_CSRF_NAME.search(name))
            is_secure_name = bool(_SENSITIVE_NAME.search(name)) and not is_csrf

            # Missing Secure flag
            if "secure" not in flags:
                sev = Severity.HIGH if is_secure_name else Severity.LOW
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
                    extra       = {"cookie": name, "session_like": is_secure_name, "flag": "secure"},
                    cvss_score  = 5.9,
                ))

            # Missing HttpOnly flag (anti-CSRF cookies are meant to be script-readable)
            if "httponly" not in flags and not is_csrf:
                sev = Severity.HIGH if is_secure_name else Severity.LOW
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
                    extra       = {"cookie": name, "session_like": is_secure_name, "flag": "httponly"},
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
                    extra       = {"cookie": name, "session_like": is_secure_name, "flag": "samesite"},
                ))

            # SameSite=None without Secure (invalid and insecure)
            samesite_none = attrs.get("samesite", "").lower() == "none"
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
                    extra       = {"cookie": name, "session_like": is_secure_name, "flag": "samesite_none"},
                ))

            # Cookie scoped to the parent domain → shared with EVERY subdomain
            dom = attrs.get("domain", "").lstrip(".").lower()
            if dom and is_secure_name:
                host = (urlparse(url).hostname or "").lower()
                if host != dom and host.endswith("." + dom) or host == dom:
                    findings.append(Finding(
                        title       = f"Session Cookie Shared With All Subdomains: `{name}`",
                        severity    = Severity.LOW,
                        url         = url,
                        module      = self.name,
                        description = (
                            f"`{name}` is set with Domain={dom}, so the browser sends it to every "
                            f"subdomain of {dom} — including forgotten, third-party-hosted or "
                            "compromised ones. Any one weak subdomain (an XSS, or a takeover of a "
                            "dangling record) can then read, overwrite or fixate this session."),
                        evidence    = f"Set-Cookie: {cookie_str[:200]}",
                        recommendation = (
                            "Omit the Domain attribute so the cookie is host-only, or use the "
                            "`__Host-` prefix (requires Secure, Path=/, no Domain)."),
                        references  = ["https://developer.mozilla.org/en-US/docs/Web/HTTP/Cookies#cookie_prefixes"],
                        cwe         = "CWE-565",
                        extra       = {"cookie": name, "session_like": True, "flag": "domain", "domain": dom},
                    ))

        return findings
