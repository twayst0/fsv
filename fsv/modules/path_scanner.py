"""FSV Module — Sensitive Path & File Exposure"""

from __future__ import annotations
import asyncio
import json
import re
from typing import Callable
from urllib.parse import urljoin, urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.config import SENSITIVE_PATHS


PATH_SEVERITY: dict[str, Severity] = {
    "/.git/HEAD":          Severity.CRITICAL,
    "/.env":               Severity.CRITICAL,
    "/.env.local":         Severity.CRITICAL,
    "/.env.production":    Severity.CRITICAL,
    "/config.php":         Severity.CRITICAL,
    "/wp-config.php":      Severity.CRITICAL,
    "/.htpasswd":          Severity.CRITICAL,
    "/id_rsa":             Severity.CRITICAL,
    "/.aws/credentials":   Severity.CRITICAL,
    "/phpinfo.php":        Severity.HIGH,
    "/backup.sql":         Severity.HIGH,
    "/db.sql":             Severity.HIGH,
    "/dump.sql":           Severity.HIGH,
    "/backup.zip":         Severity.HIGH,
    "/web.config":         Severity.HIGH,
    "/.htaccess":          Severity.MEDIUM,
    "/server-status":      Severity.MEDIUM,
    "/server-info":        Severity.MEDIUM,
    "/swagger.json":       Severity.MEDIUM,
    "/openapi.json":       Severity.MEDIUM,
    "/graphql":            Severity.MEDIUM,
    "/package.json":       Severity.LOW,
    "/composer.json":      Severity.LOW,
    "/.travis.yml":        Severity.LOW,
    "/Dockerfile":         Severity.LOW,
    "/docker-compose.yml": Severity.LOW,
    "/.DS_Store":          Severity.LOW,
    "/robots.txt":         Severity.INFO,
    "/sitemap.xml":        Severity.INFO,
    "/.well-known/security.txt": Severity.INFO,
    "/crossdomain.xml":    Severity.INFO,
}

PATH_DESCRIPTIONS: dict[str, str] = {
    "/.git/HEAD":        "Exposed .git directory allows full source code download including credentials.",
    "/.env":             "Exposed .env file may contain database credentials, API keys, and secret keys.",
    "/phpinfo.php":      "phpinfo() reveals detailed server configuration, PHP version, and loaded modules.",
    "/wp-config.php":    "WordPress config file contains database credentials and secret keys.",
    "/backup.sql":       "Exposed database backup may contain all application data including user credentials.",
    "/server-status":    "Apache server-status exposes internal server metrics and active request details.",
    "/swagger.json":     "Exposed API documentation reveals all endpoints, parameters, and authentication methods.",
    "/graphql":          "Exposed GraphQL endpoint may allow introspection revealing the full API schema.",
    "/.aws/credentials": "Exposed AWS credentials file would give attackers full cloud infrastructure access.",
    "/id_rsa":           "Exposed private SSH key would allow server login.",
}


class PathScanner(BaseScanner):
    name = "paths"

    async def scan(self, url: str) -> list[Finding]:
        parsed   = urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        # ── Baseline calibration ──────────────────────────
        # Probe two random, certainly-nonexistent paths. If the server answers
        # 200 for them, it serves a catch-all page — so a 200 alone proves
        # nothing. We then only report paths whose response clearly differs.
        baseline = await self._calibrate(base_url)

        # Probe all paths concurrently (batched)
        batch_size = 15
        findings: list[Finding] = []

        paths_list = list(SENSITIVE_PATHS)
        for i in range(0, len(paths_list), batch_size):
            batch   = paths_list[i: i + batch_size]
            tasks   = [self._probe(base_url, path, baseline) for path in batch]
            results = await asyncio.gather(*tasks)
            for finding in results:
                if finding:
                    findings.append(finding)

        return findings

    async def _calibrate(self, base_url: str) -> dict:
        """Detect catch-all/soft-404 behavior."""
        import random, string
        samples = []
        for _ in range(2):
            rnd = "/fsv_" + "".join(random.choices(string.ascii_lowercase, k=16)) + ".nonexistent"
            status, _, body = await self.fetch(base_url.rstrip("/") + rnd)
            samples.append((status, len(body)))
        # Catch-all if a random path returns 200/206
        catch_all = any(s in (200, 206) for s, _ in samples)
        avg_len = sum(l for _, l in samples) / len(samples) if samples else 0
        return {"catch_all": catch_all, "len": avg_len}

    async def _probe(self, base_url: str, path: str, baseline: dict) -> Finding | None:
        target = base_url.rstrip("/") + path
        status, headers, body = await self.fetch(target)

        if status not in (200, 206):
            return None

        ctype = (self._header(headers, "Content-Type") or "").lower()
        validator = VALIDATORS.get(path)

        if validator is not None:
            # A known file format: the body must actually look like that file.
            # Extension alone proved nothing on catch-all / SPA servers.
            if not validator(body, ctype):
                return None
            confidence = Confidence.CERTAIN
        else:
            # Filter out soft-404s: very short body or generic "not found" content
            if len(body) < 20:
                return None
            body_lower = body.lower()
            if any(phrase in body_lower for phrase in (
                "404 not found", "page not found", "not found", "error 404"
            )):
                return None
            confidence = Confidence.FIRM
            # Catch-all calibration: if random paths also return 200, only report
            # when this response differs meaningfully from that baseline.
            if baseline.get("catch_all"):
                base_len = baseline.get("len", 0)
                if base_len and abs(len(body) - base_len) <= max(50, base_len * 0.15):
                    return None
                confidence = Confidence.TENTATIVE

        sev  = PATH_SEVERITY.get(path, Severity.LOW)
        desc = PATH_DESCRIPTIONS.get(path, f"Sensitive file `{path}` is publicly accessible.")

        return Finding(
            title       = f"Sensitive File Exposed: `{path}`",
            severity    = sev,
            confidence  = confidence,
            url         = target,
            module      = self.name,
            description = desc,
            evidence    = (f"HTTP {status} — file accessible at {target}\n"
                           f"Response preview (secrets masked):\n{redact_preview(path, body)}"),
            recommendation = (
                f"Immediately restrict access to `{path}`:\n"
                "1. Remove the file from the web root if it shouldn't be there.\n"
                "2. Configure your web server to deny access to sensitive paths.\n"
                "3. Use .htaccess / nginx location blocks to return 403 or 404.\n"
                "4. If it contained credentials or keys, treat them as compromised and rotate them."
            ),
            references  = [
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            cwe         = "CWE-538" if ".git" in path or ".env" in path else "CWE-200",
        )


# ── content validators ────────────────────────────────────────────────────────
# Each returns True only when the body really is the named file.

def _not_html(body: str, ctype: str) -> bool:
    head = body.lstrip()[:200].lower()
    return "text/html" not in ctype and not head.startswith(("<!doctype", "<html"))


def _json_with(*keys: str):
    def check(body: str, ctype: str) -> bool:
        try:
            data = json.loads(body)
        except ValueError:
            return False
        return isinstance(data, dict) and any(k in data for k in keys)
    return check


def _regex(pattern: str, flags: int = re.IGNORECASE | re.MULTILINE, html_ok: bool = False):
    rx = re.compile(pattern, flags)
    def check(body: str, ctype: str) -> bool:
        return (html_ok or _not_html(body, ctype)) and bool(rx.search(body))
    return check


_ENV = _regex(r"^\s*[A-Z_][A-Z0-9_]*\s*=", flags=re.MULTILINE)
_SQL = _regex(r"(create\s+table|insert\s+into|-- mysql dump|postgresql database dump)")

VALIDATORS: dict[str, Callable[[str, str], bool]] = {
    "/.git/HEAD":        _regex(r"^(ref:\s*refs/|[0-9a-f]{40}\s*$)"),
    "/.env":             _ENV,
    "/.env.local":       _ENV,
    "/.env.production":  _ENV,
    "/config.php":       _regex(r"(<\?php|define\s*\()", html_ok=True),
    "/wp-config.php":    _regex(r"(<\?php|DB_PASSWORD|define\s*\()", html_ok=True),
    "/.htpasswd":        _regex(r"^[^:\s<>]+:\S{6,}$"),
    "/.htaccess":        _regex(r"^\s*(RewriteEngine|RewriteRule|Deny from|Allow from|Require|AuthType|Options)\b"),
    "/id_rsa":           _regex(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "/id_rsa.pub":       _regex(r"^(ssh-(rsa|ed25519|dss)|ecdsa-sha2-)\s"),
    "/.aws/credentials": _regex(r"aws_access_key_id\s*="),
    "/phpinfo.php":      _regex(r"(phpinfo\(\)|PHP Version\s*[0-9])", html_ok=True),
    "/backup.sql":       _SQL,
    "/db.sql":           _SQL,
    "/dump.sql":         _SQL,
    "/backup.zip":       lambda b, c: b.startswith("PK\x03\x04") or "zip" in c,
    "/.DS_Store":        lambda b, c: "Bud1" in b[:16],
    "/web.config":       _regex(r"<configuration[\s>]", html_ok=True),
    "/server-status":    _regex(r"(Apache Server Status|Server uptime)", html_ok=True),
    "/swagger.json":     _json_with("swagger", "openapi"),
    "/api/swagger.json": _json_with("swagger", "openapi"),
    "/openapi.json":     _json_with("swagger", "openapi"),
    "/package.json":     _json_with("dependencies", "devDependencies", "scripts"),
    "/package-lock.json":_json_with("lockfileVersion"),
    "/composer.json":    _json_with("require", "autoload"),
    "/yarn.lock":        _regex(r"^# (yarn lockfile|THIS IS AN AUTOGENERATED FILE)"),
    "/Dockerfile":       _regex(r"^\s*FROM\s+\S+"),
    "/docker-compose.yml": _regex(r"^\s*services\s*:"),
    "/.travis.yml":       _regex(r"^\s*(language|script|install|dist)\s*:"),
    "/robots.txt":       _regex(r"^\s*(user-agent|disallow|sitemap)\s*:"),
    "/sitemap.xml":      _regex(r"<(urlset|sitemapindex)[\s>]", html_ok=True),
    "/crossdomain.xml":  _regex(r"<cross-domain-policy", html_ok=True),
    "/.well-known/security.txt": _regex(r"^\s*contact\s*:"),
}

_SECRET_FILES = ("/.env", "/.env.local", "/.env.production", "/.aws/credentials",
                 "/.htpasswd", "/config.php", "/wp-config.php", "/id_rsa")
_KV = re.compile(r"^(\s*[\w.\-]+\s*[=:]\s*)(.+)$")
_PHP_DEFINE = re.compile(r"(define\s*\(\s*['\"][^'\"]+['\"]\s*,\s*)(['\"]).*?\2", re.IGNORECASE)


def redact_preview(path: str, body: str, limit: int = 300) -> str:
    """
    Preview of the exposed file for the report. For files that hold secrets the
    keys stay visible (that is the evidence) but every value is masked, so the
    scan report itself never becomes a second copy of the leaked credentials.
    """
    if path == "/id_rsa":
        return "-----BEGIN … PRIVATE KEY----- (contents withheld)"
    preview = body[:limit]
    if path not in _SECRET_FILES:
        return preview
    out = []
    for line in preview.splitlines():
        line = _PHP_DEFINE.sub(lambda m: m.group(1) + "'****'", line)
        m = _KV.match(line)
        if m and not line.lstrip().startswith(("#", "//", "<?")):
            line = m.group(1) + "****"
        out.append(line)
    return "\n".join(out)
