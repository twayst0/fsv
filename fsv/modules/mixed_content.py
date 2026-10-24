"""FSV Module — Mixed Content Detection"""

from __future__ import annotations
import re
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


# Resource attributes that cause active/passive mixed content
RESOURCE_RE = re.compile(
    r'(?:src|href|action|data)\s*=\s*["\'](http://[^"\']+)["\']',
    re.IGNORECASE,
)
ACTIVE_TAGS = ("script", "link", "iframe", "form", "object", "embed")


class MixedContentScanner(BaseScanner):
    name = "mixed_content"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return []  # mixed content only matters on HTTPS pages

        status, headers, body = await self.fetch(url)
        if status == -1 or not body:
            return []

        http_resources = RESOURCE_RE.findall(body)
        if not http_resources:
            return []

        # Deduplicate, cap
        unique = list(dict.fromkeys(http_resources))[:20]

        # Heuristic: is any of them an "active" resource (script/iframe/css)?
        active = [r for r in unique if r.lower().endswith((".js", ".css"))
                  or any(f"{t}" in body.lower() and r in body for t in ACTIVE_TAGS)]

        sev = Severity.MEDIUM if active else Severity.LOW
        return [Finding(
            title       = "Mixed Content (HTTP resources on HTTPS page)",
            severity    = sev,
            url         = url,
            module      = self.name,
            description = (
                "This HTTPS page loads one or more resources over plain HTTP. Mixed content "
                "weakens the security of the page: active mixed content (scripts, stylesheets, "
                "iframes) can be tampered with by a network attacker to compromise the whole page; "
                "passive mixed content (images) can leak information and triggers browser warnings."
            ),
            evidence    = "HTTP resources found:\n" + "\n".join(unique[:10]),
            recommendation = (
                "Load all resources over HTTPS. Replace http:// URLs with https:// (or "
                "protocol-relative/absolute HTTPS). Add a "
                "'Content-Security-Policy: upgrade-insecure-requests' header to auto-upgrade."
            ),
            references  = [
                "https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content",
            ],
            cwe         = "CWE-311",
            extra       = {"resources": unique},
        )]
