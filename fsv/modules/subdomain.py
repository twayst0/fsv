"""FSV Module — Subdomain Enumeration (passive, wordlist-based)"""

from __future__ import annotations
import asyncio
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlparse

from fsv.core import dnsutil
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
from fsv.core.netsafety import registrable_domain


# Common subdomain prefixes. Keeps the probe quick while covering the
# ones that most often expose staging/admin/dev surfaces.
WORDLIST = [
    "www", "mail", "ftp", "webmail", "smtp", "pop", "imap", "ns1", "ns2",
    "admin", "administrator", "test", "dev", "staging", "stage", "demo",
    "api", "api-dev", "beta", "portal", "vpn", "remote", "gateway",
    "dashboard", "panel", "cpanel", "whm", "git", "gitlab", "jenkins",
    "jira", "confluence", "wiki", "docs", "blog", "shop", "store",
    "app", "mobile", "m", "cdn", "static", "assets", "img", "media",
    "db", "database", "mysql", "sql", "backup", "old", "new", "internal",
    "intranet", "corp", "secure", "login", "sso", "auth", "status",
    "monitor", "grafana", "kibana", "prometheus", "s3", "storage",
]

# Subdomains whose exposure is particularly interesting.
INTERESTING = {
    "admin", "administrator", "test", "dev", "staging", "stage",
    "jenkins", "gitlab", "git", "jira", "confluence", "db", "database",
    "mysql", "sql", "backup", "old", "internal", "intranet", "panel",
    "cpanel", "whm", "grafana", "kibana", "prometheus", "monitor",
}


class SubdomainScanner(BaseScanner):
    """Site-wide: resolves common subdomains of the registrable domain."""
    name = "subdomain"
    category    = "passive"
    scope       = "site"
    description = "Subdomain enumeration + sensitive subdomain exposure"

    async def scan(self, url: str) -> list[Finding]:
        if not dnsutil.HAVE_DNS:
            return []

        domain = registrable_domain(urlparse(url).hostname or "")
        if not domain:
            return []

        found = await asyncio.to_thread(self._enumerate, domain)
        if not found:
            return []

        findings: list[Finding] = []
        interesting_found = [s for s in found if s.split(".")[0] in INTERESTING]

        findings.append(Finding(
            title       = f"Subdomains Discovered ({len(found)})",
            severity    = Severity.INFO,
            url         = f"dns://{domain}",
            module      = self.name,
            description = (
                f"{len(found)} subdomain(s) of {domain} resolve publicly. Each one expands "
                "the attack surface and should be inventoried and secured."
            ),
            evidence    = "\n".join(found),
            recommendation = (
                "Maintain an inventory of all public subdomains. Decommission unused ones "
                "(watch for dangling CNAMEs that enable subdomain takeover)."
            ),
            references  = ["https://owasp.org/www-project-web-security-testing-guide/"],
            extra       = {"subdomains": found},
        ))

        if interesting_found:
            findings.append(Finding(
                title       = "Sensitive Subdomains Exposed",
                severity    = Severity.MEDIUM,
                url         = f"dns://{domain}",
                module      = self.name,
                description = (
                    "Subdomains that commonly front internal, admin, or non-production "
                    "systems are publicly resolvable: "
                    f"{', '.join(interesting_found)}. These are frequent entry points."
                ),
                evidence    = "\n".join(interesting_found),
                recommendation = (
                    "Restrict admin/dev/staging hosts to a VPN or IP allowlist. "
                    "Ensure non-production environments are not publicly reachable."
                ),
                references  = ["https://owasp.org/www-project-web-security-testing-guide/"],
                cwe         = "CWE-200",
            ))

        return findings

    def _enumerate(self, domain: str) -> list[str]:
        def _resolve(prefix: str) -> str | None:
            fqdn = f"{prefix}.{domain}"
            # exists() follows CNAMEs, so a live alias counts; a dangling one is
            # reported by the `takeover` module instead of being listed as live
            return fqdn if dnsutil.exists(fqdn, 2.5).status in ("ok",) else None

        found: list[str] = []
        with ThreadPoolExecutor(max_workers=20) as pool:
            for res in pool.map(_resolve, WORDLIST):
                if res:
                    found.append(res)
        return sorted(found)
