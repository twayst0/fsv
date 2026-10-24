"""
FSV Module — Form Security

Passive. Inspects HTML forms for common weaknesses:
  • a form containing a password/credential field that submits over HTTP
    (credentials travel in cleartext → interception);
  • a login/payment form whose `action` points to a non-HTTPS target from an
    HTTPS page (mixed, interceptable submission);
  • password fields that allow browser autocomplete on shared machines.
No payloads are sent — it only reads the rendered markup.
"""

from __future__ import annotations
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


class FormSecurityScanner(BaseScanner):
    name = "form_security"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or not body:
            return []
        if "<form" not in body.lower():
            return []

        page_https = urlparse(url).scheme == "https"
        soup = BeautifulSoup(body, "lxml")
        findings: list[Finding] = []

        for idx, form in enumerate(soup.find_all("form")):
            inputs = form.find_all("input")
            has_password = any(
                (i.get("type") or "").lower() == "password" for i in inputs
            )
            if not has_password:
                continue

            action = form.get("action") or url
            action_url = urljoin(url, action)
            action_scheme = urlparse(action_url).scheme or urlparse(url).scheme
            method = (form.get("method") or "get").upper()

            # 1) Credentials submitted over cleartext HTTP.
            if action_scheme == "http":
                findings.append(Finding(
                    title       = "Credentials Submitted Over HTTP",
                    severity    = Severity.HIGH,
                    confidence  = Confidence.FIRM,
                    url         = url,
                    module      = self.name,
                    description = (
                        "A form with a password field submits to an HTTP (non-TLS) endpoint. "
                        "Credentials are transmitted in cleartext and can be captured by anyone "
                        "on the network path."
                    ),
                    evidence    = f"Form #{idx+1} method={method} action={action_url}",
                    recommendation = (
                        "Submit all credential forms to an HTTPS endpoint, redirect HTTP→HTTPS, "
                        "and set HSTS. Never post passwords over plain HTTP."
                    ),
                    cwe         = "CWE-319",
                    cvss_score  = 7.4,
                ))

            # 2) Password field using GET (credentials end up in URL/logs/history).
            if method == "GET":
                findings.append(Finding(
                    title       = "Password Field Submitted via GET",
                    severity    = Severity.MEDIUM,
                    confidence  = Confidence.FIRM,
                    url         = url,
                    module      = self.name,
                    description = (
                        "A form containing a password field uses the GET method, so the password "
                        "is placed in the URL query string — where it is stored in browser history, "
                        "proxy logs, server access logs and the Referer header."
                    ),
                    evidence    = f"Form #{idx+1} method=GET action={action_url}",
                    recommendation = "Use method=POST for any form that handles credentials.",
                    cwe         = "CWE-598",
                    cvss_score  = 5.3,
                ))

            # 3) Password autocomplete not disabled (lower-risk hardening).
            for i in inputs:
                if (i.get("type") or "").lower() == "password":
                    ac = (i.get("autocomplete") or "").lower()
                    if ac not in ("off", "new-password", "current-password"):
                        findings.append(Finding(
                            title       = "Password Field Allows Autocomplete",
                            severity    = Severity.INFO,
                            confidence  = Confidence.TENTATIVE,
                            url         = url,
                            module      = self.name,
                            description = (
                                "A password input does not set a restrictive `autocomplete` value, "
                                "so browsers may cache the credential — a risk on shared devices."
                            ),
                            evidence    = f"Form #{idx+1}: <input type=password autocomplete='{ac or 'unset'}'>",
                            recommendation = (
                                "Set autocomplete='new-password' (registration) or "
                                "'current-password' (login); use 'off' for the most sensitive fields."
                            ),
                            cwe         = "CWE-200",
                            cvss_score  = 2.0,
                        ))
                    break  # one autocomplete note per form

        return findings
