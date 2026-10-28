"""FSV Module — Password / login form hygiene"""

from __future__ import annotations
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from fsv.core.scanner import BaseScanner, mask_secret
from fsv.core.models import Finding, Severity, Confidence


class FormSecurityScanner(BaseScanner):
    """Looks at forms that carry a password field. Reads HTML only."""
    name     = "form_security"
    description = "Login/password forms: HTTPS action, autocomplete, GET submission"
    category = "passive"
    scope    = "url"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or "html" not in (self._header(headers, "Content-Type") or ""):
            return []

        soup = BeautifulSoup(body, "lxml")
        findings: list[Finding] = []
        page_https = url.lower().startswith("https://")

        for form in soup.find_all("form"):
            pw = form.find("input", attrs={"type": lambda t: t and t.lower() == "password"})
            if pw is None:
                continue
            action = urljoin(url, form.get("action") or url)
            method = (form.get("method") or "get").lower()
            for field in form.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"}):
                if field.get("value"):                       # a pre-filled password must not be copied into the report
                    field["value"] = mask_secret(field["value"])
            snippet = str(form)[:300]

            if not page_https or urlparse(action).scheme == "http":
                findings.append(self._f(
                    url, "Password Form Submitted Over HTTP", Severity.HIGH,
                    "A form containing a password field is served or submitted over plain HTTP. "
                    "Credentials can be read or altered by anyone on the network path.",
                    "Serve the page and the form action exclusively over HTTPS and enable HSTS.",
                    "CWE-319", snippet, Confidence.CERTAIN,
                ))
            if method == "get":
                findings.append(self._f(
                    url, "Password Form Uses GET", Severity.MEDIUM,
                    "The login form submits with GET, so the password ends up in the URL — and "
                    "from there in browser history, proxy logs and Referer headers.",
                    "Use method=\"post\" for any form that carries credentials.",
                    "CWE-598", snippet, Confidence.CERTAIN,
                ))
            ac = (pw.get("autocomplete") or "").lower()
            if ac not in ("current-password", "new-password", "off", "one-time-code"):
                findings.append(self._f(
                    url, "Password Field Without autocomplete Hint", Severity.INFO,
                    "The password input has no `autocomplete` token. Password managers work best "
                    "with `current-password` / `new-password`; this is a usability and "
                    "credential-hygiene hint, not a vulnerability.",
                    "Add autocomplete=\"current-password\" (login) or \"new-password\" (signup/change).",
                    "CWE-522", snippet, Confidence.FIRM,
                ))
        return findings

    def _f(self, url, title, sev, desc, rec, cwe, evidence, conf) -> Finding:
        return Finding(
            title=title, severity=sev, url=url, module=self.name, description=desc,
            recommendation=rec, cwe=cwe, evidence=evidence, confidence=conf,
            references=["https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html"],
        )
