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
    "csp_analyzer":        True,
    "form_security":       True,
}

# Disable modules without editing code: FSV_DISABLED_MODULES=subdomain,dns_security
for _m in filter(None, (x.strip() for x in os.getenv("FSV_DISABLED_MODULES", "").split(","))):
    MODULES_ENABLED[_m] = False

# ── Web server limits ──────────────────────────────────────
MAX_CONCURRENT_SCANS = int(os.getenv("FSV_MAX_SCANS", "3"))
# Optional API token: when set, every /api and /ws call must send it
# (header "X-FSV-Token" or ?token=...). Recommended if FSV_HOST is not loopback.
API_TOKEN = os.getenv("FSV_TOKEN", "")
# Extra Host names the dashboard may be reached by (comma-separated; "*" = any).
# Loopback names and FSV_HOST are always allowed. Guards against DNS rebinding.
ALLOWED_HOSTS = os.getenv("FSV_ALLOWED_HOSTS", "")
# When FSV runs as a shared service, "scan this URL" is a request-forgery
# primitive. FSV_BLOCK_PRIVATE=1 refuses loopback / RFC1918 / ULA targets (also
# via redirects and DNS). Cloud-metadata and link-local ranges are ALWAYS blocked.
BLOCK_PRIVATE = os.getenv("FSV_BLOCK_PRIVATE", "").lower() in ("1", "true", "yes")

# ── XSS payloads (detection only) ────────────────────────
XSS_PAYLOADS = [
    '<script>alert("fsv")</script>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
]

# ── SQLi detection payloads ───────────────────────────────
SQLI_PAYLOADS = [
    "'",
    "\"",
    "' OR '1'='1",
    "' AND 1=1--",
    "' AND SLEEP(1)--",
    "1; DROP TABLE--",
]

SQLI_ERROR_SIGNATURES = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "sqlstate",
    "ora-",
    "pg_query",
    "sqlite_error",
    "microsoft oledb provider for sql server",
    "odbc sql server driver",
    "mysql_num_rows",
]

# ── Open redirect payloads ────────────────────────────────
REDIRECT_PAYLOADS = [
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
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
]

# ── Security headers to check ─────────────────────────────
# `applies`: "https" → only meaningful on HTTPS responses (HSTS is ignored over HTTP);
#            "html"  → document-level policy, irrelevant on JSON/image/API responses;
#            "sensitive" → only where the response is personal (sets a cookie / authenticated scan).
# X-Frame-Options is owned by the `clickjacking` module (which also accepts CSP frame-ancestors);
# X-XSS-Protection is deliberately absent: modern guidance is to omit it or send `0`.
SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "HTTP Strict Transport Security (HSTS)",
        "severity": "medium",
        "applies": "https",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
    },
    "Content-Security-Policy": {
        "desc": "Content Security Policy (CSP)",
        "severity": "medium",
        "applies": "html",
        "recommendation": "Define a strict CSP to prevent XSS: Content-Security-Policy: default-src 'self'",
    },
    "X-Content-Type-Options": {
        "desc": "MIME-type sniffing protection",
        "severity": "low",
        "applies": "any",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
    },
    "Referrer-Policy": {
        "desc": "Referrer information leakage control",
        "severity": "info",
        "applies": "html",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
    },
    "Permissions-Policy": {
        "desc": "Browser feature permissions control",
        "severity": "info",
        "applies": "html",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
    },
    "Cache-Control": {
        "desc": "Caching behavior for sensitive pages",
        "severity": "low",
        "applies": "sensitive",
        "recommendation": "Add: Cache-Control: no-store for pages that show personal data",
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

# Shared-service safeguard: scans that send payloads (non-passive) are refused for public
# hosts unless the owner has proven control (DNS TXT or /.well-known file). See core/ownership.py.
REQUIRE_VERIFICATION = os.getenv("FSV_REQUIRE_VERIFICATION", "").lower() in ("1", "true", "yes")
