"""FSV Module — CSRF Vulnerability Detection"""

from __future__ import annotations
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


CSRF_TOKEN_NAMES = {
    "csrf", "xsrf", "_token", "csrftoken", "authenticity_token",
    "__requestverificationtoken", "_csrf_token", "csrf_token",
    "xsrf-token", "anti-forgery",
}


class CSRFScanner(BaseScanner):
    name = "csrf"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or not body:
            return []

        findings: list[Finding] = []

        try:
            soup = BeautifulSoup(body, "lxml")
        except Exception:
            return []

        forms = soup.find_all("form")
        if not forms:
            return []

        for form in forms:
            method = (form.get("method") or "get").lower()
            action = form.get("action") or url

            # Only check POST forms (GET forms are generally safe for CSRF)
            if method != "post":
                continue

            # Look for CSRF token field
            inputs = form.find_all("input")
            has_csrf_token = False
            for inp in inputs:
                name  = (inp.get("name") or "").lower()
                itype = (inp.get("type") or "text").lower()
                if itype == "hidden" and any(t in name for t in CSRF_TOKEN_NAMES):
                    has_csrf_token = True
                    break

            # Check for SameSite cookie as an alternative protection
            set_cookies = [
                v for k, v in headers.items() if k.lower() == "set-cookie"
            ]
            samesite_protected = any(
                "samesite=strict" in c.lower() or "samesite=lax" in c.lower()
                for c in set_cookies
            )

            if not has_csrf_token and not samesite_protected:
                form_action = action[:100] if len(str(action)) > 100 else str(action)
                findings.append(Finding(
                    title       = "CSRF Token Missing in POST Form",
                    severity    = Severity.HIGH,
                    url         = url,
                    module      = self.name,
                    description = (
                        "A POST form was found without a CSRF token. Without this protection, "
                        "attackers can craft malicious pages that submit the form on behalf of "
                        "authenticated users, performing unintended actions."
                    ),
                    evidence    = (
                        f"Form action: {form_action}\n"
                        f"Method: POST\n"
                        f"No CSRF token input detected\n"
                        f"No SameSite cookie protection detected"
                    ),
                    recommendation = (
                        "1. Add a CSRF token to all state-changing forms (synchroniser token pattern).\n"
                        "2. Set SameSite=Lax or Strict on session cookies.\n"
                        "3. Validate the Origin and Referer headers server-side.\n"
                        "4. Use the Double Submit Cookie pattern as an alternative."
                    ),
                    references  = [
                        "https://owasp.org/www-community/attacks/csrf",
                        "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
                    ],
                    cwe         = "CWE-352",
                    cvss_score  = 8.0,
                ))

        return findings
