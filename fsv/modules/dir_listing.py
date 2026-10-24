"""FSV Module — Directory Listing Detection"""

from __future__ import annotations
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity


COMMON_DIRS = ["/", "/images/", "/img/", "/assets/", "/uploads/",
               "/files/", "/static/", "/css/", "/js/", "/backup/",
               "/tmp/", "/temp/", "/data/", "/includes/", "/lib/"]

LISTING_SIGNS = [
    "index of /",
    "<title>index of",
    "directory listing for",
    "<h1>index of",
    "parent directory</a>",
    "[to parent directory]",
]


class DirListingScanner(BaseScanner):
    name = "dir_listing"

    async def scan(self, url: str) -> list[Finding]:
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        findings: list[Finding] = []
        checked: set[str] = set()

        for d in COMMON_DIRS:
            target = base_url.rstrip("/") + d
            if target in checked:
                continue
            checked.add(target)

            status, headers, body = await self.fetch(target)
            if status != 200 or not body:
                continue

            body_lower = body.lower()
            if any(sign in body_lower for sign in LISTING_SIGNS):
                findings.append(Finding(
                    title       = f"Directory Listing Enabled: `{d}`",
                    severity    = Severity.MEDIUM,
                    url         = target,
                    module      = self.name,
                    description = (
                        f"The directory `{d}` returns an automatic file listing. This exposes "
                        "the full contents of the directory, potentially revealing backups, "
                        "source files, or other sensitive resources."
                    ),
                    evidence    = f"HTTP 200 with directory-index markers at {target}",
                    recommendation = (
                        "Disable directory listing:\n"
                        "• Apache:  Options -Indexes\n"
                        "• Nginx:   autoindex off;\n"
                        "• IIS:     disable Directory Browsing\n"
                        "Also add an index file to each directory."
                    ),
                    references  = ["https://owasp.org/www-community/attacks/Forced_browsing"],
                    cwe         = "CWE-548",
                ))

        return findings
