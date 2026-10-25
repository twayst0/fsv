"""FSV Module — Open Redirect Detection"""

from __future__ import annotations
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Confidence, Finding, Severity
from fsv.config import REDIRECT_PAYLOADS

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "next", "url",
    "return", "return_url", "returnurl", "goto", "target",
    "destination", "redir", "link", "continue", "forward",
    "location", "callback", "success", "back", "from",
}


EVIL_HOST = "evil.example.com"
_REDIRECT_CODES = (301, 302, 303, 307, 308)


def browser_destination(current: str, location: str) -> str:
    """
    Where a browser actually goes for this Location header. Browsers drop leading/trailing
    whitespace and control characters and treat `\\` like `/` in http(s) URLs, so
    `/\\evil.example.com` is the protocol-relative `//evil.example.com`.
    """
    loc = "".join(ch for ch in location.strip() if ch >= " " and ch != "\x7f").replace("\\", "/")
    return urljoin(current, loc)


def _is_evil(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host == EVIL_HOST or host.endswith("." + EVIL_HOST)


class OpenRedirectScanner(BaseScanner):
    name = "open_redirect"
    category    = "active"
    scope       = "url"
    description = "Open redirect in redirect-style parameters"

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

                hit = await self._follow(test_url)
                if hit:
                    code, location = hit
                    findings.append(Finding(
                        title       = "Open Redirect",
                        severity    = Severity.MEDIUM,
                        url         = url,
                        module      = self.name,
                        parameter   = param,
                        confidence  = Confidence.CERTAIN,
                        description = (
                            f"The `{param}` parameter can be used to redirect users to an "
                            "arbitrary external URL. Attackers abuse this for phishing: "
                            "the link appears legitimate but delivers victims to a malicious site, "
                            "and it can leak OAuth codes or tokens carried in the URL."
                        ),
                        evidence    = (
                            f"Parameter: {param}\n"
                            f"Payload: {payload}\n"
                            f"Location: {location}\n"
                            f"HTTP {code} — a browser would go to {EVIL_HOST}"
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

    async def _follow(self, url: str) -> tuple[int, str] | None:
        """
        Follow redirects only while they stay on the target (never request the "evil" host);
        return (status, Location) of the hop that would send a browser off-site to it.
        """
        origin = urlparse(url).netloc
        current = url
        for _ in range(5):
            r = await self.fetch_response(current, allow_redirects=False)
            location = self._header(r.headers, "Location") or ""
            if r.status not in _REDIRECT_CODES or not location:
                return None
            dest = browser_destination(current, location)
            if _is_evil(dest):
                return r.status, location
            if urlparse(dest).netloc != origin:
                return None
            current = dest
        return None
