"""
FSV Module — robots.txt & sitemap review

robots.txt is a public list of "please don't look here" — which is exactly where an attacker looks first. This reads it
(and the sitemap) and reports:

  • Disallow entries that name sensitive areas (admin, backup, staging, internal, dumps, config…)
  • (deep profile, and only when robots rules are not being respected) which of those paths actually answer to anyone
  • sitemap entries on non-production hosts or with internal-looking paths

Common harmless defaults (`/wp-admin/` on WordPress, `/cgi-bin/`) are not reported on their own.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

# whole path segments only: "blog" must not match "log", "devices" must not match "dev"
_WORDS = {"admin", "administrator", "backup", "bak", "private", "internal", "staging", "stage", "dev", "test", "old", "secret", "config", "conf",
          "database", "db", "dump", "log", "tmp", "temp", "upload", "phpmyadmin", "manage", "management", "console", "debug", "intranet",
          "beta", "archive", "export", "install", "setup", "cms", "portal", "sql", "git", "svn", "env", "vendor"}
_SEG = re.compile(r"[^a-z0-9]+")


def _is_sensitive(path: str) -> bool:
    for seg in _SEG.split(path.lower()):
        if seg in _WORDS or (seg.endswith("s") and seg[:-1] in _WORDS):
            return True
    return False


_BENIGN = {"/wp-admin/", "/wp-admin", "/wp-admin/admin-ajax.php", "/wp-login.php", "/cgi-bin/", "/search", "/search/", "/*?s=", "/tmp/", "/temp/"}
_NONPROD_HOST = re.compile(r"(?i)(?:^|[.\-])(?:staging|stage|stg|dev|uat|qa|test|preprod|internal|sandbox)(?:[.\-]|$)")
_LOGIN = re.compile(r"(?i)type=[\"']?password|<form[^>]*login|sign[ -]?in|log[ -]?in")
MAX_PROBES = 8


def parse_robots(text: str) -> tuple[list[str], list[str]]:
    """(disallowed paths, sitemap URLs)."""
    disallow, sitemaps = [], []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        k, v = (x.strip() for x in line.split(":", 1))
        if k.lower() == "disallow" and v and v != "/":
            disallow.append(v)
        elif k.lower() == "sitemap" and v:
            sitemaps.append(v)
    return list(dict.fromkeys(disallow)), list(dict.fromkeys(sitemaps))


def sensitive_entries(disallow: list[str]) -> list[str]:
    return [d for d in disallow if d not in _BENIGN and _is_sensitive(d)]


class RobotsReviewScanner(BaseScanner):
    name        = "robots_review"
    category    = "passive"
    scope       = "site"
    description = "robots.txt & sitemap: sensitive Disallow entries, reachability (deep), non-production hosts in the sitemap"

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        r = await self.http.request(base + "/robots.txt")
        if not (r.ok and r.status == 200 and r.body and "<html" not in r.body[:200].lower()):
            return []
        disallow, sitemaps = parse_robots(r.body)
        out: list[Finding] = []
        hot = sensitive_entries(disallow)
        if hot:
            out.append(Finding(
                title="robots.txt Points Out Sensitive Paths", severity=Severity.INFO, confidence=Confidence.CERTAIN, url=base + "/robots.txt", module=self.name,
                description=("robots.txt asks crawlers to stay away from paths that sound sensitive. It does not protect them — it advertises them to anyone who reads the file, "
                             "and malicious crawlers ignore it."),
                evidence="\n".join(f"Disallow: {d}" for d in hot[:12]),
                recommendation="Protect those areas with authentication or network rules; keep robots.txt for crawl hints, not as a hiding place.",
                references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/01-Information_Gathering/03-Review_Webserver_Metafiles_for_Information_Leakage"],
                cwe="CWE-200"))
            if self.deep and not self.scan_config.respect_robots:
                for d in hot[:MAX_PROBES]:
                    path = d.split("*")[0].split("$")[0]
                    if not path.startswith("/") or len(path) < 2:
                        continue
                    pr = await self.http.request(base + path)
                    if pr.ok and pr.status == 200 and len(pr.body) > 200 and not _LOGIN.search(pr.body[:4000]):
                        out.append(Finding(
                            title=f"Path Listed in robots.txt Is Open: `{path}`", severity=Severity.LOW, confidence=Confidence.TENTATIVE,
                            url=base + path, module=self.name,
                            description="A path that robots.txt marks as off-limits answers HTTP 200 with real content and no login form. Check whether it should be public.",
                            evidence=f"GET {path} → 200 ({len(pr.body)} bytes)", recommendation="Require authentication, or remove the content.", cwe="CWE-284"))
        for sm in sitemaps[:2]:
            sr = await self.http.request(sm if sm.startswith("http") else base + sm)
            if not (sr.ok and sr.status == 200 and "<loc" in sr.body[:5000].lower()):
                continue
            hosts = {urlparse(m).hostname or "" for m in re.findall(r"(?i)<loc>\s*([^<\s]+)\s*</loc>", sr.body[:400_000])}
            nonprod = sorted(h for h in hosts if _NONPROD_HOST.search(h))
            if nonprod:
                out.append(Finding(
                    title="Sitemap Lists Non-Production Hosts", severity=Severity.LOW, confidence=Confidence.FIRM, url=sm, module=self.name,
                    description="The sitemap includes staging/dev/test hosts. They are indexed by search engines and usually less protected than production.",
                    evidence="\n".join(nonprod[:8]), recommendation="Generate the production sitemap from production URLs only; put non-production behind authentication.",
                    cwe="CWE-200"))
            break
        return out
