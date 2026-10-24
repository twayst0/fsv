"""
FSV Module — Cache-Control on potentially sensitive responses

Passive. Looks for pages that appear to carry authenticated/sensitive content
(login/account/admin/profile/token hints, Set-Cookie, Authorization echoes) but
are served without directives that prevent shared/browser caching. Cached
sensitive responses can leak to later users of a shared browser, a proxy, or a
CDN (a stepping stone to web-cache deception).
"""

from __future__ import annotations
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


_SENSITIVE_HINTS = (
    "login", "signin", "account", "admin", "dashboard", "profile",
    "settings", "password", "token", "billing", "checkout", "invoice",
    "logout", "session", "csrf", "authorization",
)


class CacheControlScanner(BaseScanner):
    name = "cache_control"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1:
            return []

        cc = (self._header(headers, "Cache-Control") or "").lower()
        pragma = (self._header(headers, "Pragma") or "").lower()
        set_cookie = self._header(headers, "Set-Cookie")

        low_url = url.lower()
        looks_sensitive = (
            any(h in low_url for h in _SENSITIVE_HINTS)
            or bool(set_cookie)
            or any(h in body.lower()[:4000] for h in ("type=\"password\"", "logout", "csrf"))
        )
        if not looks_sensitive:
            return []

        # Adequately protected?
        protected = ("no-store" in cc) or ("no-cache" in cc and "private" in cc)
        if protected:
            return []

        findings: list[Finding] = []
        reason = cc if cc else "(no Cache-Control header)"
        findings.append(Finding(
            title       = "Sensitive Response May Be Cacheable",
            severity    = Severity.LOW,
            confidence  = Confidence.TENTATIVE,
            url         = url,
            module      = self.name,
            description = (
                "This response appears to carry authenticated or sensitive content but does not "
                "set `Cache-Control: no-store` (or `no-cache, private`). Browsers, shared proxies "
                "or a CDN may cache it, exposing it to later users or enabling web-cache "
                "deception attacks."
            ),
            evidence    = (
                f"URL looks sensitive and/or sets cookies.\n"
                f"Cache-Control: {reason}\n"
                f"Pragma: {pragma or '(none)'}\n"
                f"Set-Cookie present: {'yes' if set_cookie else 'no'}"
            ),
            recommendation = (
                "On authenticated/sensitive responses send:\n"
                "Cache-Control: no-store, no-cache, must-revalidate, private\n"
                "Pragma: no-cache\n"
                "and ensure your CDN/proxy does not cache responses that set cookies."
            ),
            cwe         = "CWE-525",
            cvss_score  = 3.7,
        ))
        return findings
