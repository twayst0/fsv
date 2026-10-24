"""FSV Module — Open Redirect Detection"""

from __future__ import annotations
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.config import REDIRECT_PAYLOADS

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "next", "url",
    "return", "return_url", "returnurl", "goto", "target",
    "destination", "redir", "link", "continue", "forward",
    "location", "callback", "success", "back", "from",
}


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        findings: list[Finding] = []
        redirect_params = {
            k for k in params if k.lower() in REDIRECT_PARAMS
        }
        if not redirect_params:
            return []

        for param in redirect_params:
            for payload in REDIRECT_PAYLOADS:
                test_params = {k: v[0] for k, v in params.items()}
                test_params[param] = payload
                new_query  = urlencode(test_params)
                test_url   = urlunparse(parsed._replace(query=new_query))

                chain = await self.fetch_with_redirect_chain(test_url)
                for code, location in chain:
                    if code in (301, 302, 303, 307, 308) and location:
                        loc_parsed = urlparse(location)
                        payload_parsed = urlparse(payload)
                        if (
                            loc_parsed.hostname == payload_parsed.hostname
                            or loc_parsed.path.startswith(payload)
                        ):
                            findings.append(Finding(
                                title       = "Open Redirect",
                                severity    = Severity.MEDIUM,
                                url         = url,
                                module      = self.name,
                                parameter   = param,
                                description = (
                                    f"The `{param}` parameter can be used to redirect users to an "
                                    "arbitrary external URL. Attackers abuse this for phishing: "
                                    "the link appears legitimate but delivers victims to a malicious site."
                                ),
                                evidence    = (
                                    f"Parameter: {param}\n"
                                    f"Payload: {payload}\n"
                                    f"Redirect to: {location}\n"
                                    f"HTTP {code}"
                                ),
                                recommendation = (
                                    "1. Maintain an allowlist of permitted redirect destinations.\n"
                                    "2. Use relative paths for redirects instead of full URLs.\n"
                                    "3. Validate and reject external URLs that were not explicitly allowed.\n"
                                    "4. Add an intermediate confirmation page warning users they are leaving."
                                ),
                                references  = [
                                    "https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/04-Testing_for_Client-side_URL_Redirect",
                                ],
                                cwe         = "CWE-601",
                                cvss_score  = 6.1,
                                extra       = {"payload": payload, "redirect_to": location},
                            ))
                            break

        return findings
