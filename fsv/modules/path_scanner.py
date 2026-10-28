"""FSV Module — Sensitive Path & File Exposure"""

from __future__ import annotations
import asyncio
import json
import re
from typing import Callable
from urllib.parse import urlparse

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
    "/crossdomain.xml":    Severity.LOW,
    "/admin":              Severity.LOW,
    "/admin/":             Severity.LOW,
    "/administrator":      Severity.LOW,
}

# Paths whose finding is not "a file that should not exist" — they get their own wording.
_ADMIN_REC = ("Keep administration off the public Internet: allow it only from a VPN / office IP range, "
              "or put it behind SSO with MFA. At minimum enforce MFA and rate-limit the login.")
PATH_TITLES: dict[str, tuple[str, str, str]] = {   # path → (title, description, recommendation)
    "/admin": ("Admin Interface Publicly Reachable",
               "An administration interface answers to anyone on the Internet. It is the most attacked "
               "page of any site: credential stuffing, password spraying and any auth bug land here.",
               _ADMIN_REC),
    "/crossdomain.xml": ("Permissive crossdomain.xml (any origin)",
                         "crossdomain.xml allows every domain. Legacy Flash/Silverlight clients — and some "
                         "proxies and PDF readers that still honour it — may read authenticated responses cross-origin.",
                         "Delete crossdomain.xml, or list only the exact domains that need access."),
}
PATH_TITLES["/admin/"] = PATH_TITLES["/administrator"] = PATH_TITLES["/admin"]

PATH_CWE: dict[str, str] = {}

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


_MERGED_TITLES = {t for t, _, _ in PATH_TITLES.values()}


class PathScanner(BaseScanner):
    name = "paths"
    category    = "passive"
    scope       = "site"
    description = "Exposed sensitive files (.git, .env, backups, admin) w/ calibration"

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

        paths_list = list(ALL_PATHS)
        if self.deep:
            paths_list += DEEP_PATHS + host_backup_paths(parsed.hostname or "")
            paths_list = list(dict.fromkeys(paths_list))
        for i in range(0, len(paths_list), batch_size):
            batch   = paths_list[i: i + batch_size]
            tasks   = [self._probe(base_url, path, baseline) for path in batch]
            results = await asyncio.gather(*tasks)
            for finding in results:
                if finding:
                    findings.append(finding)

        # `/admin` and `/admin/` (or two backup names served by one catch-all) are one problem.
        unique: dict[tuple, Finding] = {}
        for f in findings:
            # same kind of finding landing on the same final page (redirects followed)
            key = (f.title, f.extra.get("final")) if f.title in _MERGED_TITLES else (f.url,)
            if key in unique:
                unique[key].extra.setdefault("aliases", []).append(urlparse(f.url).path)
            else:
                unique[key] = f
        return list(unique.values())

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
        resp = await self.fetch_response(target)
        status, headers, body = resp.status, resp.headers, resp.body

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
        final = urlparse(resp.url or target).path.rstrip("/") or "/"

        if path in PATH_TITLES:
            title, desc, rec = PATH_TITLES[path]
            return Finding(
                title=title, severity=sev, confidence=confidence, url=target, module=self.name,
                description=desc, recommendation=rec, cwe="CWE-284",
                evidence=f"HTTP {status} at {target}\nResponse preview:\n{redact_preview(path, body)}",
                references=["https://owasp.org/www-project-web-security-testing-guide/"],
                extra={"final": final})

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
            cwe         = PATH_CWE.get(path) or ("CWE-538" if ".git" in path or ".env" in path else "CWE-200"),
            extra       = {"final": final},
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
    "/crossdomain.xml":  _regex(r"<allow-access-from[^>]*domain\s*=\s*[\"']\*[\"']", html_ok=True),
}

_BINARY_FILES = ("/actuator/heapdump", "/backup.zip", "/backup.tar.gz", "/backup.tgz", "/site.zip",
                 "/www.zip", "/web.zip", "/public_html.zip", "/.DS_Store", "/.svn/wc.db")
_SECRET_FILES = ("/.env", "/.env.local", "/.env.production", "/.env.bak", "/.env.backup",
                 "/.aws/credentials", "/.htpasswd", "/config.php", "/wp-config.php",
                 "/wp-config.php.bak", "/wp-config.php~", "/wp-config.php.old", "/config.php.bak",
                 "/id_rsa", "/.ssh/id_rsa", "/.npmrc", "/.docker/config.json", "/appsettings.json",
                 "/appsettings.Development.json", "/application.properties", "/application.yml",
                 "/config/database.yml", "/settings.py", "/terraform.tfvars", "/terraform.tfstate",
                 "/actuator/env", "/actuator/configprops", "/actuator/httptrace")
_KV = re.compile(r"^(\s*[\w.\-]+\s*[=:]\s*)(.+)$")
_JSON_SECRET = re.compile(r'(?i)("[^"\n]*(?:pass|secret|token|key|auth|credential|connection)[^"\n]*"\s*:\s*)"[^"\n]*"')
_PHP_DEFINE = re.compile(r"(define\s*\(\s*['\"][^'\"]+['\"]\s*,\s*)(['\"]).*?\2", re.IGNORECASE)


def redact_preview(path: str, body: str, limit: int = 300) -> str:
    """
    Preview of the exposed file for the report. For files that hold secrets the
    keys stay visible (that is the evidence) but every value is masked, so the
    scan report itself never becomes a second copy of the leaked credentials.
    Binary / archive files get no preview at all.
    """
    if path in ("/id_rsa", "/.ssh/id_rsa") or "PRIVATE KEY-----" in body[:300]:
        return "-----BEGIN … PRIVATE KEY----- (contents withheld)"
    if path in _WITHHOLD:
        return f"(contents withheld: the file holds secrets that are not in key=value form; {len(body)} bytes received)"
    if path in _BINARY_FILES or path in _BINARY_FILES_DYNAMIC:
        return f"(binary content withheld; {len(body)} bytes received)"
    preview = body[:limit]
    if path not in _SECRET_FILES:
        return preview
    out = []
    for line in preview.splitlines():
        line = _JSON_SECRET.sub(lambda m: m.group(1) + '"****"', line)
        line = _PHP_DEFINE.sub(lambda m: m.group(1) + "'****'", line)
        m = _KV.match(line)
        if m and "****" not in line and not line.lstrip().startswith(("#", "//", "<?", "{", "}", "[", '"')):
            line = m.group(1) + "****"
        out.append(line)
    return "\n".join(out)


# ── extended checks (every one content-validated) ─────────────────────────────

def _json_list_with(key: str):
    def check(body: str, ctype: str) -> bool:
        try:
            data = json.loads(body)
        except ValueError:
            return False
        return isinstance(data, list) and bool(data) and isinstance(data[0], dict) and key in data[0]
    return check


_PHP_SRC = _regex(r"(<\?php|DB_PASSWORD|define\s*\()", html_ok=True)
_PRIVKEY = _regex(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")
_PHPINFO = _regex(r"(phpinfo\(\)|PHP Version\s*[0-9])", html_ok=True)
_ZIP = lambda b, c: b.startswith("PK\x03\x04")
_GZIP = lambda b, c: b[:1] == "\x1f" and b[1:2] == "\ufffd"
_SWAGGER = _json_with("swagger", "openapi")

S, V = Severity, None
# (path, severity, validator, description, cwe)
_EXTRA_CHECKS: list[tuple] = [
    ("/.git/config", S.HIGH, _regex(r"^\s*\[(core|remote|branch)\b"),
     "Exposed git configuration: reveals the repository URL (often with embedded credentials) and confirms the .git directory is downloadable.", "CWE-538"),
    ("/.svn/wc.db", S.CRITICAL, lambda b, c: b.startswith("SQLite format 3"),
     "Exposed Subversion working-copy database: lists every file in the repository and lets the source be reconstructed.", "CWE-538"),
    ("/.npmrc", S.HIGH, _regex(r"(_authToken\s*=|_auth\s*=|^\s*registry\s*=)"),
     "Exposed npm configuration: frequently contains a publish token for the organisation's registry.", "CWE-538"),
    ("/.docker/config.json", S.CRITICAL, _json_with("auths"),
     "Exposed Docker client config: contains registry credentials.", "CWE-538"),
    ("/.ssh/id_rsa", S.CRITICAL, _PRIVKEY, "Exposed SSH private key.", "CWE-538"),
    ("/appsettings.json", S.HIGH, _json_with("ConnectionStrings", "Logging", "AllowedHosts", "Jwt", "AzureAd"),
     "Exposed ASP.NET configuration: typically holds database connection strings and signing keys.", "CWE-538"),
    ("/appsettings.Development.json", S.HIGH, _json_with("ConnectionStrings", "Logging", "AllowedHosts", "Jwt"),
     "Exposed ASP.NET development configuration.", "CWE-538"),
    ("/application.properties", S.HIGH, _regex(r"^\s*(spring|server|logging)\.[\w.\-]+\s*="),
     "Exposed Spring Boot configuration: usually contains datasource credentials.", "CWE-538"),
    ("/application.yml", S.HIGH, _regex(r"^\s*(spring|server|logging)\s*:"),
     "Exposed Spring Boot configuration.", "CWE-538"),
    ("/config/database.yml", S.HIGH, _regex(r"^\s*(adapter|database|username|password)\s*:"),
     "Exposed Rails database configuration.", "CWE-538"),
    ("/settings.py", S.HIGH, _regex(r"(SECRET_KEY\s*=|INSTALLED_APPS\s*=)"),
     "Exposed Django settings: SECRET_KEY allows forging sessions and, with some serializers, code execution.", "CWE-538"),
    ("/wp-config.php.bak", S.CRITICAL, _PHP_SRC, "Backup of wp-config.php served as plain text: database credentials and salts.", "CWE-538"),
    ("/wp-config.php~", S.CRITICAL, _PHP_SRC, "Editor backup of wp-config.php served as plain text.", "CWE-538"),
    ("/wp-config.php.old", S.CRITICAL, _PHP_SRC, "Old copy of wp-config.php served as plain text.", "CWE-538"),
    ("/config.php.bak", S.CRITICAL, _PHP_SRC, "Backup of config.php served as plain text.", "CWE-538"),
    ("/.env.bak", S.CRITICAL, _ENV, "Backup of the environment file: credentials and API keys.", "CWE-538"),
    ("/.env.backup", S.CRITICAL, _ENV, "Backup of the environment file: credentials and API keys.", "CWE-538"),
    ("/terraform.tfstate", S.CRITICAL, _json_with("terraform_version", "resources"),
     "Exposed Terraform state: contains the full infrastructure inventory and, in clear text, every secret the configuration touched.", "CWE-538"),
    ("/terraform.tfvars", S.HIGH, _regex(r'^\s*\w+\s*=\s*"'), "Exposed Terraform variables: often credentials and account identifiers.", "CWE-538"),
    ("/actuator", S.MEDIUM, _json_with("_links"), "Spring Boot Actuator index is public: it lists every management endpoint that is enabled.", "CWE-200"),
    ("/actuator/env", S.HIGH, _json_with("propertySources", "activeProfiles"),
     "Spring Boot Actuator /env is public: exposes configuration properties (older versions show secrets unmasked).", "CWE-200"),
    ("/actuator/heapdump", S.CRITICAL, lambda b, c: b.startswith("JAVA PROFILE"),
     "Spring Boot Actuator /heapdump is public: a full JVM memory dump — session tokens, credentials and personal data in clear text.", "CWE-200"),
    ("/actuator/configprops", S.HIGH, _json_with("contexts", "beans"), "Spring Boot Actuator /configprops is public.", "CWE-200"),
    ("/actuator/mappings", S.MEDIUM, _json_with("contexts"), "Spring Boot Actuator /mappings is public: lists every route, including hidden ones.", "CWE-200"),
    ("/actuator/httptrace", S.HIGH, _json_with("traces"), "Spring Boot Actuator /httptrace is public: recent requests including headers and cookies.", "CWE-200"),
    ("/metrics", S.MEDIUM, _regex(r"^# (HELP|TYPE) ", html_ok=False),
     "Prometheus metrics are public: internal topology, endpoints, versions and traffic volumes.", "CWE-200"),
    ("/debug/pprof/", S.HIGH, _regex(r"(Types of profiles available|/debug/pprof/)", html_ok=True),
     "Go pprof profiling endpoint is public: memory/CPU profiles can leak data and are an easy denial-of-service vector.", "CWE-489"),
    ("/debug/vars", S.MEDIUM, _json_with("cmdline", "memstats"), "Go expvar is public: command line and memory statistics.", "CWE-489"),
    ("/_profiler/", S.HIGH, _regex(r"Symfony Profiler", html_ok=True),
     "Symfony profiler is public: request/response data, configuration and database queries of other users.", "CWE-489"),
    ("/telescope", S.HIGH, _regex(r"Laravel Telescope", html_ok=True),
     "Laravel Telescope is public: every request, query, exception and job of the application.", "CWE-489"),
    ("/storage/logs/laravel.log", S.HIGH, _regex(r"\[\d{4}-\d\d-\d\d[ T][\d:]+\]\s+\w+\.(ERROR|WARNING|INFO|DEBUG)"),
     "Laravel application log is public: stack traces, paths and sometimes credentials and tokens.", "CWE-532"),
    ("/elmah.axd", S.HIGH, _regex(r"Error Log for", html_ok=True), "ELMAH error log is public.", "CWE-532"),
    ("/trace.axd", S.HIGH, _regex(r"Application Trace", html_ok=True), "ASP.NET trace viewer is public: request data of other users.", "CWE-489"),
    ("/phpmyadmin/", S.MEDIUM, _regex(r"phpMyAdmin", html_ok=True), "phpMyAdmin is reachable from the Internet.", "CWE-284"),
    ("/pma/", S.MEDIUM, _regex(r"phpMyAdmin", html_ok=True), "phpMyAdmin is reachable from the Internet.", "CWE-284"),
    ("/adminer.php", S.MEDIUM, _regex(r"Adminer", html_ok=True), "Adminer database client is reachable from the Internet.", "CWE-284"),
    ("/_cluster/health", S.HIGH, _json_with("cluster_name", "status"),
     "An Elasticsearch API answers without authentication — the data and cluster controls are likely open.", "CWE-306"),
    ("/wp-json/wp/v2/users", S.LOW, _json_list_with("slug"),
     "WordPress REST API lists user accounts (login names), which helps credential-stuffing and phishing.", "CWE-200"),
    ("/xmlrpc.php", S.LOW, _regex(r"XML-RPC server accepts POST requests only", html_ok=True),
     "WordPress XML-RPC is enabled: used for password-guessing amplification (system.multicall) and pingback abuse.", "CWE-307"),
    ("/wp-content/debug.log", S.HIGH, _regex(r"(PHP (Warning|Notice|Fatal error|Deprecated)|^\[\d\d-\w{3}-\d{4})"),
     "WordPress debug log is public: file paths, errors and sometimes secrets.", "CWE-532"),
    ("/WEB-INF/web.xml", S.HIGH, _regex(r"<web-app", html_ok=True), "Java deployment descriptor is downloadable: reveals servlets, filters and security constraints.", "CWE-538"),
    ("/info.php", S.HIGH, _PHPINFO, "phpinfo() page: full PHP/server configuration and environment variables.", "CWE-200"),
    ("/test.php", S.HIGH, _PHPINFO, "phpinfo() page: full PHP/server configuration and environment variables.", "CWE-200"),
    ("/backup.tar.gz", S.HIGH, _GZIP, "Downloadable site backup archive.", "CWE-530"),
    ("/backup.tgz", S.HIGH, _GZIP, "Downloadable site backup archive.", "CWE-530"),
    ("/site.zip", S.HIGH, _ZIP, "Downloadable site archive.", "CWE-530"),
    ("/www.zip", S.HIGH, _ZIP, "Downloadable site archive.", "CWE-530"),
    ("/web.zip", S.HIGH, _ZIP, "Downloadable site archive.", "CWE-530"),
    ("/public_html.zip", S.HIGH, _ZIP, "Downloadable site archive.", "CWE-530"),
    ("/v2/api-docs", S.MEDIUM, _SWAGGER, "Swagger/OpenAPI document is public: every endpoint and parameter.", "CWE-200"),
    ("/v3/api-docs", S.MEDIUM, _SWAGGER, "OpenAPI document is public: every endpoint and parameter.", "CWE-200"),
    ("/swagger-ui.html", S.LOW, _regex(r"Swagger UI", html_ok=True), "Swagger UI is public.", "CWE-200"),
    ("/swagger-ui/index.html", S.LOW, _regex(r"Swagger UI", html_ok=True), "Swagger UI is public.", "CWE-200"),
    ("/composer.lock", S.LOW, _json_with("packages"), "Exposed PHP dependency lock file: exact versions for targeting known CVEs.", "CWE-200"),
    ("/.gitlab-ci.yml", S.LOW, _regex(r"^\s*(stages|script|image)\s*:"), "Exposed CI pipeline: internal hosts, deployment targets and secret variable names.", "CWE-200"),
    ("/Jenkinsfile", S.LOW, _regex(r"\b(pipeline|node)\s*\{"), "Exposed Jenkins pipeline definition.", "CWE-200"),
    ("/.idea/workspace.xml", S.LOW, _regex(r"<project version=", html_ok=True), "Exposed IDE workspace: local paths and project structure.", "CWE-200"),
    ("/nginx_status", S.LOW, _regex(r"Active connections:", html_ok=False), "nginx stub_status is public.", "CWE-200"),
]

# merge into the lookup tables used by _probe
for _path, _sev, _val, _desc, _cwe in _EXTRA_CHECKS:
    PATH_SEVERITY[_path] = _sev
    PATH_DESCRIPTIONS[_path] = _desc
    VALIDATORS[_path] = _val
    PATH_CWE[_path] = _cwe

ALL_PATHS: list[str] = list(dict.fromkeys([*SENSITIVE_PATHS, *(c[0] for c in _EXTRA_CHECKS)]))


# ── deep profile: a much longer list, every entry content-validated ───────────
# (Not run by default: ~90 more requests per scan. `fsv scan --profile deep`.)

_SQLITE = lambda b, c: b.startswith("SQLite format 3")
_GZ_SQL = _GZIP
_RAR = lambda b, c: b.startswith("Rar!")
_7Z = lambda b, c: b.startswith("7z��")
_SHELL_HIST = _regex(r"^(?:cd|ls|sudo|git|ssh|scp|mysql|psql|vim?|nano|cat|apt(?:-get)?|npm|pip3?|docker|curl|wget|chmod|export)\s", html_ok=False)
_GCP_KEY = _json_with("private_key", "client_secret", "private_key_id")
_KUBE = _regex(r"^\s*(apiVersion|clusters|contexts|current-context)\s*:")


def _json_secretish(body: str, ctype: str) -> bool:
    """A JSON config whose keys name secrets and whose values look like them (not 'password': '')."""
    try:
        data = json.loads(body)
    except ValueError:
        return False

    def walk(o, depth=0):
        if depth > 4:
            return False
        if isinstance(o, dict):
            for k, v in o.items():
                if re.search(r"(?i)pass(word|wd)?|secret|token|api[_-]?key|private[_-]?key|connection[_-]?string", str(k)) \
                        and isinstance(v, str) and len(v) >= 6 and not re.search(r"(?i)^(x+|\*+|changeme|your[_-].*|<.*>|\$\{.*)$", v):
                    return True
                if walk(v, depth + 1):
                    return True
        elif isinstance(o, list):
            return any(walk(i, depth + 1) for i in o[:20])
        return False
    return walk(data)


_DEEP_CHECKS: list[tuple] = [
    ("/.git/index", S.HIGH, lambda b, c: b.startswith("DIRC"), "Exposed git index: lists every file of the repository and confirms it can be downloaded object by object.", "CWE-538"),
    ("/.git/logs/HEAD", S.HIGH, _regex(r"^[0-9a-f]{40} [0-9a-f]{40} "), "Exposed git reflog: commit ids, author names and e-mail addresses.", "CWE-538"),
    ("/.hg/hgrc", S.MEDIUM, _regex(r"^\s*\[(paths|ui)\]"), "Exposed Mercurial configuration (repository paths, sometimes credentials).", "CWE-538"),
    ("/.bzr/branch-format", S.MEDIUM, _regex(r"Bazaar"), "Exposed Bazaar repository metadata.", "CWE-538"),
    ("/CVS/Entries", S.MEDIUM, _regex(r"^/[^/\n]+/\d"), "Exposed CVS metadata: file list of the repository.", "CWE-538"),
    ("/.env.development", S.CRITICAL, _ENV, "Exposed development environment file: credentials and API keys.", "CWE-538"),
    ("/.env.staging", S.CRITICAL, _ENV, "Exposed staging environment file: credentials and API keys.", "CWE-538"),
    ("/.env.dev", S.CRITICAL, _ENV, "Exposed development environment file: credentials and API keys.", "CWE-538"),
    ("/.env.test", S.HIGH, _ENV, "Exposed test environment file: often reuses real credentials.", "CWE-538"),
    ("/.bash_history", S.HIGH, _SHELL_HIST, "Exposed shell history: commands, hostnames and often passwords typed on a command line.", "CWE-538"),
    ("/.zsh_history", S.HIGH, _SHELL_HIST, "Exposed shell history: commands, hostnames and often passwords typed on a command line.", "CWE-538"),
    ("/.mysql_history", S.HIGH, _regex(r"(?:select|insert|update|create|show|use)\s", html_ok=False), "Exposed MySQL client history: queries and sometimes credentials.", "CWE-538"),
    ("/.viminfo", S.MEDIUM, _regex(r"^# This viminfo file"), "Exposed vim state: recently edited file paths and search strings.", "CWE-538"),
    ("/.git-credentials", S.CRITICAL, _regex(r"^https?://[^:\s/]+:[^@\s]+@"), "Exposed git credential store: plaintext usernames and passwords/tokens.", "CWE-538"),
    ("/.netrc", S.CRITICAL, _regex(r"^\s*(machine|default)\b"), "Exposed .netrc: plaintext logins for remote hosts.", "CWE-538"),
    ("/.pgpass", S.CRITICAL, _regex(r"^[^:\s]+:\d+:[^:\s]+:[^:\s]+:\S+"), "Exposed PostgreSQL password file.", "CWE-538"),
    ("/.my.cnf", S.HIGH, _regex(r"^\s*\[client\]|^\s*password\s*="), "Exposed MySQL client configuration with credentials.", "CWE-538"),
    ("/.s3cfg", S.CRITICAL, _regex(r"^\s*(access_key|secret_key)\s*="), "Exposed s3cmd configuration: AWS access and secret keys.", "CWE-538"),
    ("/.kube/config", S.CRITICAL, _KUBE, "Exposed kubeconfig: cluster endpoints and credentials.", "CWE-538"),
    ("/kubeconfig", S.CRITICAL, _KUBE, "Exposed kubeconfig: cluster endpoints and credentials.", "CWE-538"),
    ("/terraform.tfstate.backup", S.CRITICAL, _json_with("terraform_version", "resources"), "Exposed Terraform state backup: infrastructure inventory and secrets in clear text.", "CWE-538"),
    ("/.vscode/sftp.json", S.CRITICAL, _regex(r'"(host|password|privateKeyPath)"'), "Exposed VS Code SFTP configuration: server host and credentials.", "CWE-538"),
    ("/.vscode/settings.json", S.LOW, _regex(r'^\s*\{[\s\S]*"[\w.]+"\s*:'), "Exposed editor settings: local paths and tooling.", "CWE-200"),
    ("/sftp-config.json", S.CRITICAL, _regex(r'"(host|password|user)"'), "Exposed Sublime SFTP configuration: server host and credentials.", "CWE-538"),
    ("/db.sqlite", S.CRITICAL, _SQLITE, "Downloadable SQLite database.", "CWE-530"),
    ("/db.sqlite3", S.CRITICAL, _SQLITE, "Downloadable SQLite database (Django default name): user table with password hashes.", "CWE-530"),
    ("/database.sqlite", S.CRITICAL, _SQLITE, "Downloadable SQLite database.", "CWE-530"),
    ("/data.db", S.HIGH, _SQLITE, "Downloadable SQLite database.", "CWE-530"),
    ("/app.db", S.HIGH, _SQLITE, "Downloadable SQLite database.", "CWE-530"),
    ("/database.sql", S.HIGH, _SQL, "Downloadable SQL dump.", "CWE-530"),
    ("/dump.sql.gz", S.HIGH, _GZ_SQL, "Downloadable compressed SQL dump.", "CWE-530"),
    ("/backup.sql.gz", S.HIGH, _GZ_SQL, "Downloadable compressed SQL dump.", "CWE-530"),
    ("/server.key", S.CRITICAL, _PRIVKEY, "Exposed TLS private key.", "CWE-321"),
    ("/private.key", S.CRITICAL, _PRIVKEY, "Exposed private key.", "CWE-321"),
    ("/privkey.pem", S.CRITICAL, _PRIVKEY, "Exposed TLS private key (Let's Encrypt default name).", "CWE-321"),
    ("/key.pem", S.CRITICAL, _PRIVKEY, "Exposed private key.", "CWE-321"),
    ("/id_ed25519", S.CRITICAL, _PRIVKEY, "Exposed SSH private key.", "CWE-321"),
    ("/id_ecdsa", S.CRITICAL, _PRIVKEY, "Exposed SSH private key.", "CWE-321"),
    ("/config.json", S.HIGH, _json_secretish, "Exposed JSON configuration that holds secret-looking values.", "CWE-538"),
    ("/secrets.json", S.CRITICAL, _json_secretish, "Exposed secrets file.", "CWE-538"),
    ("/env.json", S.HIGH, _json_secretish, "Exposed environment JSON with secret-looking values.", "CWE-538"),
    ("/local.settings.json", S.HIGH, _json_with("Values", "ConnectionStrings", "IsEncrypted"), "Exposed Azure Functions settings: storage and service connection strings.", "CWE-538"),
    ("/credentials.json", S.CRITICAL, _GCP_KEY, "Exposed Google credentials file.", "CWE-538"),
    ("/client_secrets.json", S.CRITICAL, _GCP_KEY, "Exposed OAuth client secrets.", "CWE-538"),
    ("/service-account.json", S.CRITICAL, _GCP_KEY, "Exposed GCP service-account key.", "CWE-538"),
    ("/.user.ini", S.MEDIUM, _regex(r"^\s*(auto_prepend_file|auto_append_file|display_errors|upload_max_filesize)\s*="), "Exposed PHP per-directory configuration.", "CWE-200"),
    ("/php.ini", S.MEDIUM, _regex(r"^\s*\[PHP\]"), "Exposed PHP configuration.", "CWE-200"),
    ("/web.config.bak", S.HIGH, _regex(r"<configuration[\s>]", html_ok=True), "Backup of web.config served as text: connection strings and machine keys.", "CWE-538"),
    ("/.circleci/config.yml", S.LOW, _regex(r"^\s*version\s*:\s*[\d.]+", flags=re.MULTILINE), "Exposed CircleCI pipeline: deploy targets and secret variable names.", "CWE-200"),
    ("/bitbucket-pipelines.yml", S.LOW, _regex(r"^\s*(pipelines|image)\s*:"), "Exposed Bitbucket pipeline: deploy targets and variable names.", "CWE-200"),
    ("/azure-pipelines.yml", S.LOW, _regex(r"^\s*(trigger|pool|steps|stages)\s*:"), "Exposed Azure pipeline definition.", "CWE-200"),
    ("/Vagrantfile", S.LOW, _regex(r"Vagrant\.configure"), "Exposed Vagrantfile: development environment details.", "CWE-200"),
    ("/ansible.cfg", S.LOW, _regex(r"^\s*\[defaults\]"), "Exposed Ansible configuration.", "CWE-200"),
    ("/requirements.txt", S.LOW, _regex(r"^[A-Za-z0-9_.\-]+\s*(==|>=|<=|~=)\s*\d", flags=re.MULTILINE), "Exposed Python dependency list: exact versions for targeting known CVEs.", "CWE-200"),
    ("/Gemfile.lock", S.LOW, _regex(r"^(GEM|PLATFORMS|DEPENDENCIES)\s*$", flags=re.MULTILINE), "Exposed Ruby dependency lock file.", "CWE-200"),
    ("/pom.xml", S.LOW, _regex(r"<project[\s>]", html_ok=True), "Exposed Maven project file: dependencies and internal repository URLs.", "CWE-200"),
    ("/manager/html", S.HIGH, _regex(r"Tomcat Web Application Manager", html_ok=True), "Tomcat Manager is open without authentication: deploy a WAR = remote code execution.", "CWE-306"),
    ("/jmx-console/", S.HIGH, _regex(r"JMX Agent View|JBoss", html_ok=True), "JBoss JMX console is reachable: remote code execution path.", "CWE-306"),
    ("/solr/admin/", S.MEDIUM, _regex(r"Solr Admin", html_ok=True), "Solr admin interface is reachable.", "CWE-284"),
    ("/_all_dbs", S.HIGH, lambda b, c: b.lstrip().startswith("[") and '"_users"' in b, "CouchDB answers without authentication: every database is listable.", "CWE-306"),
    ("/_utils/", S.MEDIUM, _regex(r"Fauxton|CouchDB", html_ok=True), "CouchDB admin UI (Fauxton) is reachable.", "CWE-284"),
    ("/_cat/indices", S.HIGH, _regex(r"^(green|yellow|red)\s+(open|close)\s", flags=re.MULTILINE), "Elasticsearch lists its indices without authentication.", "CWE-306"),
    ("/_nodes", S.HIGH, _json_with("nodes", "cluster_name"), "Elasticsearch node information without authentication.", "CWE-306"),
    ("/script", S.CRITICAL, _regex(r"Jenkins[\s\S]{0,4000}Script Console|Script Console[\s\S]{0,4000}Jenkins", html_ok=True), "Jenkins script console is open: arbitrary code execution.", "CWE-306"),
    ("/jenkins/script", S.CRITICAL, _regex(r"Script Console", html_ok=True), "Jenkins script console is open: arbitrary code execution.", "CWE-306"),
    ("/h2-console", S.CRITICAL, _regex(r"H2 Console", html_ok=True), "H2 database console is reachable: SQL and, via CREATE ALIAS, code execution.", "CWE-306"),
    ("/druid/index.html", S.MEDIUM, _regex(r"Druid Stat Index", html_ok=True), "Alibaba Druid monitor is reachable: SQL statements and sessions.", "CWE-284"),
    ("/jolokia/", S.HIGH, _json_with("agent", "request"), "Jolokia JMX-over-HTTP endpoint is reachable.", "CWE-306"),
    ("/env", S.HIGH, _json_with("profiles", "systemProperties", "systemEnvironment"), "Spring Boot 1.x /env is public: environment variables including secrets.", "CWE-200"),
    ("/__debug__/", S.MEDIUM, _regex(r"djdt|Django Debug Toolbar", html_ok=True), "Django Debug Toolbar is reachable.", "CWE-489"),
    ("/rails/info/properties", S.HIGH, _regex(r"Rails version", html_ok=True), "Rails info pages are public (development mode in production).", "CWE-489"),
    ("/rails/info/routes", S.MEDIUM, _regex(r"Routes", html_ok=True), "Rails routes page is public (development mode in production).", "CWE-489"),
    ("/_ignition/health-check", S.HIGH, _json_with("can_execute_commands"), "Laravel Ignition is exposed: with can_execute_commands this is a remote-code-execution vector (CVE-2021-3129).", "CWE-489"),
    ("/horizon", S.MEDIUM, _regex(r"Laravel Horizon", html_ok=True), "Laravel Horizon dashboard is reachable: queue payloads and job data.", "CWE-284"),
    ("/mongo-express/", S.HIGH, _regex(r"Mongo Express", html_ok=True), "mongo-express admin UI is reachable.", "CWE-306"),
]

for _path, _sev, _val, _desc, _cwe in _DEEP_CHECKS:
    PATH_SEVERITY[_path] = _sev
    PATH_DESCRIPTIONS[_path] = _desc
    VALIDATORS[_path] = _val
    PATH_CWE[_path] = _cwe

DEEP_PATHS: list[str] = [c[0] for c in _DEEP_CHECKS if c[0] not in ALL_PATHS]
# secrets that a key=value masker cannot see (URLs with passwords, typed commands, connection strings, state files)
_WITHHOLD = ("/.git-credentials", "/.netrc", "/.pgpass", "/.bash_history", "/.zsh_history", "/.mysql_history", "/local.settings.json",
             "/terraform.tfstate", "/terraform.tfstate.backup", "/.kube/config", "/kubeconfig", "/secrets.json", "/credentials.json",
             "/client_secrets.json", "/service-account.json")
_BINARY_FILES = _BINARY_FILES + ("/db.sqlite", "/db.sqlite3", "/database.sqlite", "/data.db", "/app.db", "/dump.sql.gz", "/backup.sql.gz")
_SECRET_FILES = _SECRET_FILES + tuple(c[0] for c in _DEEP_CHECKS if c[1] in (S.CRITICAL,) and c[0] not in _BINARY_FILES)


def host_backup_paths(hostname: str) -> list[str]:
    """`/<name>.zip` … for names derived from the host (www.example.com → example.com, example): where admins park a backup."""
    host = (hostname or "").lower().removeprefix("www.")
    if not host or re.fullmatch(r"[\d.:]+", host):
        return []
    names = [n for n in dict.fromkeys([host, host.split(".")[0]]) if len(n) >= 3]
    out: list[str] = []
    for n in names:
        for ext, val, sev in ((".zip", _ZIP, S.HIGH), (".tar.gz", _GZIP, S.HIGH), (".sql", _SQL, S.HIGH), (".sql.gz", _GZ_SQL, S.HIGH),
                              (".bak", _SQL, S.HIGH), (".7z", _7Z, S.HIGH), (".rar", _RAR, S.HIGH)):
            path = f"/{n}{ext}"
            PATH_SEVERITY[path] = sev
            PATH_DESCRIPTIONS[path] = "Downloadable backup named after the site."
            VALIDATORS[path] = val
            PATH_CWE[path] = "CWE-530"
            if ext != ".sql" and ext != ".bak" and path not in _BINARY_FILES:
                _BINARY_FILES_DYNAMIC.add(path)
            out.append(path)
    return out


_BINARY_FILES_DYNAMIC: set[str] = set()
