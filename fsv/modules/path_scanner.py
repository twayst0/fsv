"""FSV Module — Sensitive Path & File Exposure"""

from __future__ import annotations
import asyncio
from urllib.parse import urljoin, urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity
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

        # Filter out soft-404s: very short body or generic "not found" content
        if len(body) < 20:
            return None
        body_lower = body.lower()
        if any(phrase in body_lower for phrase in (
            "404 not found", "page not found", "not found", "error 404"
        )) and status == 200:
            return None

        # Catch-all calibration: if the server returns 200 for random paths too,
        # only report when this response differs meaningfully from the baseline
        # (length differs by >15%) OR the body carries a strong content signal.
        if baseline.get("catch_all"):
            base_len = baseline.get("len", 0)
            len_differs = base_len == 0 or abs(len(body) - base_len) > max(50, base_len * 0.15)
            content_signal = any(sig in body_lower for sig in (
                "ref:", "[core]", "private key", "db_password", "api_key",
                "<?php", "define(", "aws_access", "begin rsa",
                "sql dump", "create table", "swagger", "openapi",
                "__data", "server-status", "apache server status",
            )) or path.endswith((".sql", ".zip", ".git/HEAD"))
            if not (len_differs or content_signal):
                return None

        sev  = PATH_SEVERITY.get(path, Severity.LOW)
        desc = PATH_DESCRIPTIONS.get(path, f"Sensitive file `{path}` is publicly accessible.")

        return Finding(
            title       = f"Sensitive File Exposed: `{path}`",
            severity    = sev,
            url         = target,
            module      = self.name,
            description = desc,
            evidence    = f"HTTP {status} — File accessible at {target}\nResponse preview: {body[:200]}",
            recommendation = (
                f"Immediately restrict access to `{path}`:\n"
                "1. Remove the file from the web root if it shouldn't be there.\n"
                "2. Configure your web server to deny access to sensitive paths.\n"
                "3. Use .htaccess / nginx location blocks to return 403 or 404."
            ),
            references  = [
                "https://owasp.org/www-project-web-security-testing-guide/",
            ],
            cwe         = "CWE-538" if ".git" in path or ".env" in path else "CWE-200",
        )
