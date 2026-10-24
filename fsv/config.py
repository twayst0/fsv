"""FSV Global Configuration"""

import os

# ── Server ──────────────────────────────────────────────
WEB_HOST = os.getenv("FSV_HOST", "127.0.0.1")
WEB_PORT = int(os.getenv("FSV_PORT", "7474"))
DB_PATH  = os.getenv("FSV_DB", os.path.expanduser("~/.fsv/scans.db"))

# ── Scanner defaults ─────────────────────────────────────
DEFAULT_TIMEOUT   = 10      # seconds per request
DEFAULT_MAX_URLS  = 50      # max URLs to crawl per scan
DEFAULT_THREADS   = 10      # concurrent requests
USER_AGENT        = (
    "FSV/1.0 (Security Scanner — authorized use only; "
    "https://github.com/fsvproject/fsv)"
)

# ── Module toggles ────────────────────────────────────────
MODULES_ENABLED = {
    "headers":        True,
    "ssl":            True,
    "xss":            True,
    "sqli":           True,
    "cors":           True,
    "cookies":        True,
    "csrf":           True,
    "open_redirect":  True,
    "tech":           True,
    "paths":          True,
    "info_disclosure":True,
    "clickjacking":   True,
    "http_methods":   True,
    "dns_security":   True,
    "dir_listing":    True,
    "mixed_content":  True,
    "subdomain":      True,
    "security_txt":        True,
    "waf_detect":          True,
    "graphql_introspection":True,
    "host_header_injection":True,
    "jwt_analysis":        True,
    "ssti":                True,
    "sri":                 True,
    "cache_control":       True,
    "form_security":       True,
    "api_discovery":       True,
    "cve_matcher":         True,
}

# A unique, benign marker so reflection is unambiguous (not a stray word on the page).
XSS_MARKER = "fsv7x9z"

# ── XSS payloads (detection only — no real alert/exploit intent) ──────────
# Each entry is a (context, payload) pair so the scanner can tell *where* the
# reflection lands (HTML body, attribute, JS string, URL/href). The marker keeps
# detection precise and the payloads benign (they probe reflection, not RCE).
XSS_PAYLOADS = [
    f'<fsvtag>{XSS_MARKER}</fsvtag>',
    f'<script>/*{XSS_MARKER}*/</script>',
    f'"><svg onload=\'/*{XSS_MARKER}*/\'>',
    f"'><img src=x onerror='/*{XSS_MARKER}*/'>",
    f'"{XSS_MARKER}"',
    f"'{XSS_MARKER}'",
    f'javascript:/*{XSS_MARKER}*/',
    f'{XSS_MARKER}"><b>{XSS_MARKER}</b>',
    f'</title><fsv>{XSS_MARKER}</fsv>',
    f'</textarea><fsv>{XSS_MARKER}</fsv>',
]

# Characters whose *unencoded* reflection indicates missing output encoding.
XSS_SPECIAL_CHARS = ['<', '>', '"', "'", '`', '(', ')', '{', '}']

# ── SQLi detection payloads ───────────────────────────────
# Error-based probes …
SQLI_PAYLOADS = [
    "'",
    "\"",
    "')",
    "';",
    "`",
    "\\",
    "' OR '1'='1",
    "' OR 1=1-- -",
    "\" OR \"1\"=\"1",
    "' AND '1'='2",
    "1' ORDER BY 1-- -",
    "' UNION SELECT NULL-- -",
    ") OR (1=1",
]

# … and safe boolean-pairs for boolean-based inference (TRUE vs FALSE responses
# should differ if the parameter is injectable). No destructive statements.
SQLI_BOOLEAN_PAIRS = [
    ("' AND '1'='1", "' AND '1'='2"),
    ("\" AND \"1\"=\"1", "\" AND \"1\"=\"2"),
    (" AND 1=1", " AND 1=2"),
    ("' OR '1'='1' -- ", "' OR '1'='2' -- "),
]

# Time-based probes (used only in the aggressive profile). The DELAY seconds is
# small and the scanner compares timing against a baseline — no data is altered.
SQLI_TIME_PAYLOADS = [
    "' AND SLEEP({d})-- -",
    "\" AND SLEEP({d})-- -",
    "' AND pg_sleep({d})-- -",
    "'; WAITFOR DELAY '0:0:{d}'-- -",
    "' AND 1=(SELECT 1 FROM PG_SLEEP({d}))-- -",
]
SQLI_TIME_DELAY = 3  # seconds

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "mysql_fetch", "mysql_num_rows", "mysqli",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-0", "ora-1", "oracle error", "oci_",
    "pg_query", "pg_exec", "postgresql", "psql:",
    "sqlite_error", "sqlite3::", "near \"",
    "microsoft oledb provider for sql server",
    "odbc sql server driver", "sql server",
    "incorrect syntax near",
    "db2 sql error", "sybase message",
    "syntax error at or near",
    "conversion failed when converting",
    "division by zero",
    "supplied argument is not a valid",
]

# ── Open redirect payloads (benign external marker domain) ────────────────
REDIRECT_MARKER_HOST = "fsv-redirect-check.example"
REDIRECT_PAYLOADS = [
    f"https://{REDIRECT_MARKER_HOST}",
    f"//{REDIRECT_MARKER_HOST}",
    f"/\\{REDIRECT_MARKER_HOST}",
    f"https:/{REDIRECT_MARKER_HOST}",
    f"http://{REDIRECT_MARKER_HOST}",
    f"\\/\\/{REDIRECT_MARKER_HOST}",
    f"https://example.com@{REDIRECT_MARKER_HOST}",
]

# ── Sensitive paths to probe ──────────────────────────────
SENSITIVE_PATHS = [
    "/.git/HEAD",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/config.php",
    "/wp-config.php",
    "/phpinfo.php",
    "/admin",
    "/admin/",
    "/administrator",
    "/backup",
    "/backup.zip",
    "/backup.sql",
    "/db.sql",
    "/dump.sql",
    "/.htaccess",
    "/.htpasswd",
    "/web.config",
    "/crossdomain.xml",
    "/robots.txt",
    "/sitemap.xml",
    "/.well-known/security.txt",
    "/server-status",
    "/server-info",
    "/.DS_Store",
    "/Thumbs.db",
    "/package.json",
    "/composer.json",
    "/yarn.lock",
    "/package-lock.json",
    "/.travis.yml",
    "/Dockerfile",
    "/docker-compose.yml",
    "/swagger.json",
    "/api/swagger.json",
    "/openapi.json",
    "/graphql",
    "/__debug__",
    "/.aws/credentials",
    "/id_rsa",
    "/id_rsa.pub",
    # ── VCS / source control ──
    "/.git/config",
    "/.git/logs/HEAD",
    "/.gitignore",
    "/.svn/entries",
    "/.svn/wc.db",
    "/.hg/requires",
    "/.bzr/README",
    # ── env / secrets ──
    "/.env.dev",
    "/.env.development",
    "/.env.staging",
    "/.env.backup",
    "/.env.example",
    "/.env.save",
    "/config.yml",
    "/config.yaml",
    "/config.json",
    "/settings.py",
    "/application.properties",
    "/application.yml",
    "/secrets.json",
    "/credentials.json",
    "/.npmrc",
    "/.pypirc",
    "/.dockercfg",
    "/.docker/config.json",
    "/.kube/config",
    "/.ssh/id_rsa",
    "/.ssh/authorized_keys",
    "/.ssh/known_hosts",
    "/.netrc",
    "/.bash_history",
    "/.mysql_history",
    # ── backups / archives ──
    "/backup.tar.gz",
    "/backup.tar",
    "/www.zip",
    "/site.zip",
    "/web.zip",
    "/database.sql",
    "/database.sql.gz",
    "/data.sql",
    "/mysql.sql",
    "/export.sql",
    "/backup/",
    "/backups/",
    "/old/",
    "/temp/",
    "/tmp/",
    "/.backup",
    "/index.php.bak",
    "/config.php.bak",
    "/wp-config.php.bak",
    "/index.php~",
    "/web.config.bak",
    # ── admin / management panels ──
    "/admin.php",
    "/admin/login",
    "/admin/index.php",
    "/administrator/index.php",
    "/wp-admin/",
    "/wp-login.php",
    "/user/login",
    "/login",
    "/manager/html",
    "/phpmyadmin/",
    "/pma/",
    "/adminer.php",
    "/console",
    "/actuator",
    "/actuator/health",
    "/actuator/env",
    "/actuator/heapdump",
    "/metrics",
    "/debug/pprof/",
    "/_profiler/",
    "/telescope/requests",
    "/.vscode/sftp.json",
    "/.idea/workspace.xml",
    # ── API / docs ──
    "/api",
    "/api/",
    "/api/v1",
    "/api/v2",
    "/api-docs",
    "/api/docs",
    "/swagger-ui.html",
    "/swagger/index.html",
    "/v2/api-docs",
    "/v3/api-docs",
    "/graphiql",
    "/playground",
    "/.well-known/openid-configuration",
    # ── cloud / CI ──
    "/.github/workflows/",
    "/.gitlab-ci.yml",
    "/.circleci/config.yml",
    "/jenkins/",
    "/.terraform/",
    "/terraform.tfstate",
    "/.serverless/",
    # ── misc leaks ──
    "/phpinfo",
    "/info.php",
    "/test.php",
    "/debug.php",
    "/.well-known/",
    "/elmah.axd",
    "/trace.axd",
    "/server-status/",
    "/nginx_status",
    "/status",
    "/health",
    "/readme.html",
    "/license.txt",
    "/CHANGELOG.md",
    "/.well-known/change-password",
]

# ── Security headers to check ─────────────────────────────
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HTTP Strict Transport Security (HSTS)",
        "severity": "high",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "Content-Security-Policy": {
        "desc": "Content Security Policy (CSP)",
        "severity": "high",
        "recommendation": "Define a strict CSP to prevent XSS: Content-Security-Policy: default-src 'self'",
    },
    "X-Frame-Options": {
        "desc": "Clickjacking protection",
        "severity": "medium",
        "recommendation": "Add: X-Frame-Options: DENY  (or use CSP frame-ancestors)",
    },
    "X-Content-Type-Options": {
        "desc": "MIME-type sniffing protection",
        "severity": "medium",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "desc": "Referrer information leakage control",
        "severity": "low",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "desc": "Browser feature permissions control",
        "severity": "low",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "X-XSS-Protection": {
        "desc": "Legacy XSS filter (deprecated — use CSP instead)",
        "severity": "info",
        "recommendation": "Add: X-XSS-Protection: 0  (disabled is correct; rely on CSP)",
    },
    "Cache-Control": {
        "desc": "Caching behavior for sensitive pages",
        "severity": "low",
        "recommendation": "Add: Cache-Control: no-store for sensitive pages",
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Cross-origin isolation / protection against XS-Leaks & Spectre",
        "severity": "low",
        "recommendation": "Add: Cross-Origin-Opener-Policy: same-origin",
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Requires explicit opt-in for cross-origin resources (COEP)",
        "severity": "info",
        "recommendation": "Add: Cross-Origin-Embedder-Policy: require-corp (enables crossOriginIsolated)",
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Limits which origins may embed this resource (CORP)",
        "severity": "info",
        "recommendation": "Add: Cross-Origin-Resource-Policy: same-origin",
    },
}

# ── Technology fingerprinting signatures ──────────────────
TECH_SIGNATURES = {
    "WordPress":   ["wp-content", "wp-includes", "wp-login.php"],
    "Drupal":      ["sites/all", "Drupal.settings", "/misc/drupal.js"],
    "Joomla":      ["/components/com_", "Joomla!", "/media/jui/"],
    "Laravel":     ["laravel_session", "XSRF-TOKEN"],
    "Django":      ["csrfmiddlewaretoken", "django"],
    "Rails":       ["_rails_session", "X-Request-Id"],
    "Next.js":     ["__NEXT_DATA__", "_next/static"],
    "React":       ["__reactInternalInstance", "_react"],
    "Vue.js":      ["__vue__", "v-cloak"],
    "Angular":     ["ng-version", "angular"],
    "jQuery":      ["jquery"],
    "Bootstrap":   ["bootstrap.min.css", "bootstrap.min.js"],
    "Apache":      ["Apache/"],
    "Nginx":       ["nginx/"],
    "IIS":         ["Microsoft-IIS", "X-Powered-By: ASP.NET"],
    "PHP":         ["X-Powered-By: PHP", ".php"],
    "ASP.NET":     ["__VIEWSTATE", "ASP.NET_SessionId"],
    "Node.js":     ["X-Powered-By: Express"],
    "Cloudflare":  ["cf-ray", "cf-cache-status", "__cfduid"],
    "Varnish":     ["X-Varnish", "Via: 1.1 varnish"],
    "Fastly":      ["X-Served-By", "Fastly-Debug-Digest"],
}


# ── API specification discovery (api_discovery module) ───────────────────
# Well-known locations for machine-readable API specs. If reachable, FSV parses
# them to enumerate every declared endpoint — turning a hidden API into a map.
API_SPEC_PATHS = [
    "/swagger.json", "/swagger/v1/swagger.json", "/api/swagger.json",
    "/openapi.json", "/openapi.yaml", "/api/openapi.json",
    "/v2/api-docs", "/v3/api-docs", "/api-docs", "/api/docs.json",
    "/swagger/index.html", "/swagger-ui.html", "/api/swagger-ui.html",
    "/graphql", "/graphiql", "/api/graphql",
    "/.well-known/openid-configuration",
    "/wp-json/", "/wp-json/wp/v2/", "/api/v1/", "/api/v2/", "/rest/",
    "/sitemap.xml", "/robots.txt",
]

# ── Offline version → known-issue heuristics (cve_matcher module) ─────────
# A compact, offline knowledge table. Keys are product names (as emitted by the
# tech fingerprint). Each rule: software versions BELOW `fixed` are flagged with
# the summary. This is a *heuristic hint* ("this version line has had serious
# published CVEs — verify and update"), not a definitive per-CVE verdict.
VERSION_VULN_DB = {
    "jQuery": [
        {"fixed": "3.5.0", "severity": "medium", "cve": "CVE-2020-11022/11023",
         "summary": "jQuery < 3.5.0 is affected by XSS via htmlPrefilter (CVE-2020-11022/11023)."},
        {"fixed": "3.0.0", "severity": "medium", "cve": "CVE-2015-9251",
         "summary": "jQuery < 3.0.0 is affected by XSS through cross-domain Ajax (CVE-2015-9251)."},
    ],
    "Bootstrap": [
        {"fixed": "3.4.0", "severity": "medium", "cve": "CVE-2018-14041",
         "summary": "Bootstrap < 3.4.0 / < 4.1.2 has XSS in data-* attributes (CVE-2018-14040/14041/14042)."},
    ],
    "AngularJS": [
        {"fixed": "1.8.0", "severity": "medium", "cve": "multiple",
         "summary": "AngularJS 1.x is end-of-life; several sandbox-bypass/XSS issues exist. Migrate off 1.x."},
    ],
    "Lodash": [
        {"fixed": "4.17.21", "severity": "high", "cve": "CVE-2021-23337",
         "summary": "lodash < 4.17.21 is affected by command-injection/prototype-pollution (CVE-2021-23337/2020-8203)."},
    ],
    "Apache": [
        {"fixed": "2.4.52", "severity": "high", "cve": "CVE-2021-44790/41773",
         "summary": "Apache httpd < 2.4.52 line has had path-traversal/RCE (CVE-2021-41773/42013) and buffer issues (CVE-2021-44790)."},
    ],
    "Nginx": [
        {"fixed": "1.21.0", "severity": "medium", "cve": "CVE-2021-23017",
         "summary": "nginx < 1.21.0 is affected by a DNS resolver off-by-one heap write (CVE-2021-23017)."},
    ],
    "OpenSSL": [
        {"fixed": "3.0.7", "severity": "high", "cve": "CVE-2022-3602/3786",
         "summary": "OpenSSL 3.0.x < 3.0.7 has X.509 punycode buffer overflows (CVE-2022-3602/3786)."},
    ],
    "PHP": [
        {"fixed": "7.4.0", "severity": "medium", "cve": "EOL",
         "summary": "PHP < 7.4 is end-of-life and no longer receives security fixes. Upgrade to a supported branch."},
    ],
    "WordPress": [
        {"fixed": "6.0.0", "severity": "medium", "cve": "multiple",
         "summary": "Older WordPress core has numerous published CVEs; keep core, themes and plugins current."},
    ],
}

# ── Subresource Integrity (sri module) ───────────────────────────────────
# Hosts considered 'first-party'/trusted get a pass; everything else loaded
# without an integrity attribute is flagged. Extend per deployment.
SRI_TRUSTED_SELF_ONLY = True  # same-origin scripts don't require SRI

# ── Secret / token regexes (shared; info_disclosure + api_discovery) ──────
SECRET_PATTERNS = {
    "AWS Access Key ID":      r"AKIA[0-9A-Z]{16}",
    "AWS Secret Access Key":  r"(?i)aws(.{0,20})?(secret|private)?.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
    "Google API Key":         r"AIza[0-9A-Za-z\-_]{35}",
    "Google OAuth Token":     r"ya29\.[0-9A-Za-z\-_]+",
    "Slack Token":            r"xox[baprs]-[0-9A-Za-z-]{10,}",
    "Slack Webhook":          r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+",
    "GitHub Token":           r"gh[pousr]_[0-9A-Za-z]{36,}",
    "GitLab Token":           r"glpat-[0-9A-Za-z\-_]{20}",
    "Stripe Secret Key":      r"sk_live_[0-9a-zA-Z]{24,}",
    "Stripe Restricted Key":  r"rk_live_[0-9a-zA-Z]{24,}",
    "Twilio SID":             r"AC[0-9a-fA-F]{32}",
    "SendGrid Key":           r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
    "Mailgun Key":            r"key-[0-9a-zA-Z]{32}",
    "JWT":                    r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
    "Private Key Block":      r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----",
    "Generic API Key":        r"(?i)(api[_-]?key|apikey|secret|token)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]",
    "Basic Auth in URL":      r"https?://[^/\s:@]+:[^/\s:@]+@",
    "Internal IPv4":          r"\b(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b",
}
