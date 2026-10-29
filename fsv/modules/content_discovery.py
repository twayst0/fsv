"""
FSV Module — content discovery (full profile only)

Links are only part of a site. Admin panels, old installers, staging copies, upload folders and API roots are often
reachable but referenced from nowhere, so a crawler never sees them. This tries ~600 common directory and page names
and reports what answers.

How it avoids noise:
  • calibration first — random impossible names tell it how this server answers "nothing here" (a catch-all that returns
    200 or 403 for everything produces no findings)
  • a hit is a real 200 with content that differs from that baseline, a 401 (there *is* something, behind a login) or a
    403 that the server does not give to random names
  • one aggregated finding per kind instead of 40 separate ones; paths with admin/backup/internal/… in the name are
    called out separately

Does nothing unless the profile is `full`. Read-only GETs.
"""

from __future__ import annotations
import asyncio
import random
import re
import string
from urllib.parse import urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

# directories / pages that commonly exist but are rarely linked
_WORDS = """
admin administrator adminpanel admin-panel admincp backend manage manager management console dashboard panel cpanel controlpanel control
login signin sign-in logon logout signup register registration forgot reset password account accounts profile user users member members me
api api/v1 api/v2 api/v3 v1 v2 v3 rest graphql gql swagger openapi docs documentation doc help support faq status health healthz ping ready live metrics
monitor monitoring stats statistics analytics report reports export import data db database sql dump dumps backup backups bak old new archive archives
tmp temp cache logs log debug trace test tests testing dev development stage staging uat qa beta alpha demo sandbox preview internal intranet private
secret secrets hidden confidential restricted staff employee employees partner partners vendor vendors customer customers client clients
upload uploads file files download downloads media images image img assets static public resources resource attachments
config conf configuration settings setup install installer installation update upgrade migrate migration cron jobs queue worker
cgi-bin bin src source app application web www site html include includes inc lib libs library packages modules plugins extensions themes
shop store cart checkout order orders invoice invoices billing payment payments pay subscription subscriptions plans pricing
blog news press events calendar careers about contact search sitemap feed rss atom
wp-admin wp-login.php wp-content wp-includes xmlrpc.php administrator/index.php user/login phpmyadmin pma adminer mysql myadmin dbadmin webmail mail email
shell cmd terminal ssh ftp sftp git svn hg cvs
readme.md readme.txt changelog.md license.txt version.txt humans.txt manifest.json service-worker.js sw.js
""".split()
_CORE = 45                                                          # the first words also get the usual file extensions
_EXT_CORE = ("", "/", ".php", ".html", ".json")
_EXT_REST = ("", "/")
_SENSITIVE = re.compile(r"(?i)admin|backup|bak|private|internal|staging|stage|dev|test|secret|confidential|config|conf|database|db|dump|log|tmp|upload|"
                        r"phpmyadmin|pma|adminer|console|debug|intranet|beta|staff|employee|install|setup|shell|cmd|git|svn|cron|jobs|queue|restricted")
MAX_PROBES = 600


def candidate_paths() -> list[str]:
    out: list[str] = []
    for i, w in enumerate(dict.fromkeys(_WORDS)):
        if "." in w:
            out.append("/" + w)                                      # a file name: try it as-is only
            continue
        for ext in (_EXT_CORE if i < _CORE else _EXT_REST):
            out.append("/" + w + ext)
    return list(dict.fromkeys(out))[:MAX_PROBES]


class ContentDiscoveryScanner(BaseScanner):
    name        = "content_discovery"
    category    = "passive"
    scope       = "site"
    description = "Full profile: ~600 common directories/pages nothing links to (admin, backup, staging, uploads…), calibrated against catch-all servers"

    async def _calibrate(self, base: str) -> dict:
        samples = []
        for _ in range(3):
            rnd = "/fsv-" + "".join(random.choices(string.ascii_lowercase + string.digits, k=18))
            r = await self.http.request(base + rnd, cache=False)
            samples.append((r.status, len(r.body or ""), (r.body or "")[:300]))
        return {"statuses": {s for s, _, _ in samples}, "len": sum(n for _, n, _ in samples) / len(samples), "heads": {h for _, _, h in samples}}

    def _is_hit(self, status: int, body: str, base: dict) -> str | None:
        if status != 200 and status in base["statuses"]:
            return None                                              # "everything is 403/401/…" on this server
        if status == 200:
            if len(body) < 20 or re.search(r"(?i)404 not found|page not found|not found|error 404", body[:600]):
                return None
            if 200 in base["statuses"]:                              # catch-all: only a clearly different page counts
                if abs(len(body) - base["len"]) <= max(50, base["len"] * 0.15) or body[:300] in base["heads"]:
                    return None
            return "open"
        if status == 401:
            return "login required"
        if status == 403:
            return "forbidden"
        return None

    async def scan(self, url: str) -> list[Finding]:
        if not self.full:
            return []
        p = urlparse(url)
        base_url = f"{p.scheme}://{p.netloc}"
        base = await self._calibrate(base_url)
        hits: list[tuple[str, int, str]] = []
        sem = asyncio.Semaphore(12)

        async def probe(path: str) -> None:
            async with sem:
                r = await self.http.request(base_url + path, allow_redirects=False)
            if not r.ok:
                return
            kind = self._is_hit(r.status, r.body or "", base)
            if kind:
                hits.append((path, r.status, kind))

        await asyncio.gather(*(probe(x) for x in candidate_paths()))
        if not hits:
            return []
        hits.sort(key=lambda h: h[0])
        # "/admin", "/admin/" and "/admin.php" answering alike are one page
        seen: set[tuple[str, str]] = set()
        unique = []
        for path, status, kind in hits:
            key = (path.rstrip("/").rsplit(".", 1)[0], kind)
            if key not in seen:
                seen.add(key)
                unique.append((path, status, kind))
        sens = [h for h in unique if _SENSITIVE.search(h[0]) and h[2] in ("open", "login required")]
        rest = [h for h in unique if h not in sens]
        out: list[Finding] = []

        def lines(items):
            return "\n".join(f"{status} {path}  ({kind})" for path, status, kind in items[:40]) + (f"\n… and {len(items) - 40} more" if len(items) > 40 else "")

        if sens:
            open_ones = [h for h in sens if h[2] == "open"]
            out.append(Finding(
                title=f"Unlinked Administrative or Internal Paths Found ({len(sens)})",
                severity=Severity.LOW if open_ones else Severity.INFO, confidence=Confidence.FIRM, url=base_url, module=self.name,
                description=("Paths whose names suggest administration, backups, staging or internal tools answer — although no page links to them. "
                             "Hiding a page behind a link nobody posts is not access control: wordlists find these in minutes. Check each one is "
                             "meant to be reachable and protected by real authentication."),
                evidence=lines(sens),
                recommendation="Require authentication (SSO + MFA) or restrict by network for every administrative path; delete anything that is no longer used.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/05-Enumerate_Infrastructure_and_Application_Admin_Interfaces"],
                cwe="CWE-284", extra={"paths": [h[0] for h in sens]}))
        if rest:
            out.append(Finding(
                title=f"Unlinked Pages and Directories Discovered ({len(rest)})", severity=Severity.INFO, confidence=Confidence.FIRM, url=base_url, module=self.name,
                description=("The crawler follows links; these paths exist but nothing links to them. They extend the attack surface a crawl-based scan "
                             "(including this one) does not test deeply — review whether each should be public."),
                evidence=lines(rest), recommendation="Remove what is unused; make sure the rest is intentionally public.", cwe="CWE-200",
                extra={"paths": [h[0] for h in rest]}))
        return out
