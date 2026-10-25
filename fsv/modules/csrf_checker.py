"""FSV Module — CSRF Vulnerability Detection"""

from __future__ import annotations
from urllib.parse import urljoin, urlparse
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
    category    = "passive"
    scope       = "url"
    description = "Missing CSRF protection on POST forms"

    async def scan(self, url: str) -> list[Finding]:
        resp = await self.fetch_response(url)
        status, headers, body = resp.status, resp.headers, resp.body
        if status == -1 or not body:
            return []
        page = urlparse(resp.url or url)

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
            # A form that posts to another site (a "share this" or payment form) carries none of
            # this site's cookies, so this site's CSRF defences are not involved.
            dest = urlparse(urljoin(resp.url or url, str(action)))
            if dest.scheme in ("http", "https") and dest.netloc and dest.netloc != page.netloc:
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
            set_cookies = resp.set_cookies
            samesite_protected = any(
                "samesite=strict" in c.lower() or "samesite=lax" in c.lower()
                for c in set_cookies
            )

            if not has_csrf_token and not samesite_protected:
                form_action = action[:100] if len(str(action)) > 100 else str(action)
                findings.append(Finding(
                    title       = "CSRF Token Missing in POST Form",
                    severity    = Severity.MEDIUM,
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
