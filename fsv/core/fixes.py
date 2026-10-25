"""
FSV — fix packs
───────────────
Turns a scan's findings into configuration you can paste: nginx, Apache, Caddy,
Express (helmet) and DNS records. Only issues that were actually found on this
scan produce a snippet, and each snippet says which finding it addresses.

Deliberately conservative:
  • Content-Security-Policy is emitted as *Report-Only* — a blind enforcing CSP
    breaks sites; start by observing.
  • Nothing here is applied for you. Review, test on staging, then deploy.
"""

from __future__ import annotations
from dataclasses import dataclass, field
from urllib.parse import urlparse

from fsv.core.models import Finding, ScanResult

SERVERS = ("nginx", "apache", "caddy", "express", "dns")

_CSP_STARTER = ("default-src 'self'; object-src 'none'; base-uri 'self'; "
                "frame-ancestors 'self'; form-action 'self'")

# header name → value that is safe as a default
_HEADERS = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "X-Content-Type-Options":    "nosniff",
    "X-Frame-Options":           "SAMEORIGIN",
    "Referrer-Policy":           "strict-origin-when-cross-origin",
    "Permissions-Policy":        "geolocation=(), microphone=(), camera=()",
    "X-XSS-Protection":          "0",
}


@dataclass
class Snippet:
    why:  str                 # finding title(s) this addresses
    code: str
    lang: str = ""
    note: str = ""


@dataclass
class Facts:
    """What the scan found, reduced to the things a config fix can act on."""
    missing_headers: list[str] = field(default_factory=list)
    csp_missing:     bool = False
    server_version:  bool = False
    powered_by:      bool = False
    cookie_flags:    set[str] = field(default_factory=set)       # secure / httponly / samesite
    exposed_paths:   list[str] = field(default_factory=list)
    source_maps:     bool = False
    dir_listing:     bool = False
    trace_enabled:   bool = False
    dns:             list[Finding] = field(default_factory=list)
    takeover_hosts:  list[str] = field(default_factory=list)
    titles:          dict[str, str] = field(default_factory=dict)   # key → finding title


def extract_facts(result: ScanResult) -> Facts:
    f = Facts()
    for x in result.active_findings:
        t = x.title
        if x.module == "headers" and t.startswith("Missing Security Header: "):
            h = t.split(": ", 1)[1]
            if h == "Content-Security-Policy":
                f.csp_missing = True
            elif h in _HEADERS:
                f.missing_headers.append(h)
                f.titles[h] = t
        elif t == "Server Version Disclosure":
            f.server_version, f.titles["server"] = True, t
        elif t.startswith("Technology Stack Disclosure via X-Powered-By"):
            f.powered_by, f.titles["powered"] = True, t
        elif x.module == "cookies" and x.extra.get("flag") in ("secure", "httponly", "samesite"):
            f.cookie_flags.add(x.extra["flag"])
        elif x.module == "paths" and t.startswith("Sensitive File Exposed"):
            p = urlparse(x.url).path
            if p and p not in f.exposed_paths:
                f.exposed_paths.append(p)
        elif t == "Source Map Exposes Original Source Code":
            f.source_maps = True
        elif t.startswith("Directory Listing Enabled"):
            f.dir_listing = True
        elif x.module == "http_methods" and "TRACE" in t.upper():
            f.trace_enabled = True
        elif x.module == "dns_security":
            f.dns.append(x)
        elif x.module == "takeover" and x.extra.get("kind") in ("dangling", "claimable"):
            f.takeover_hosts.append(x.extra.get("host", ""))
    return f


# ── per-server generators ─────────────────────────────────────────────────────

def _nginx(f: Facts) -> list[Snippet]:
    out: list[Snippet] = []
    lines = [f'add_header {h} "{_HEADERS[h]}" always;' for h in f.missing_headers]
    if f.csp_missing:
        lines.append(f'add_header Content-Security-Policy-Report-Only "{_CSP_STARTER}" always;')
    if lines:
        out.append(Snippet("Missing security headers", "\n".join(lines), "nginx",
                           "Put in the `server {}` block (add_header is not inherited into a block "
                           "that defines its own add_header). CSP is report-only: watch reports, then enforce."))
    if f.server_version:
        out.append(Snippet(f.titles["server"], "server_tokens off;", "nginx", "http {} or server {} block."))
    if f.powered_by:
        out.append(Snippet(f.titles["powered"], 'proxy_hide_header X-Powered-By;\nfastcgi_hide_header X-Powered-By;', "nginx"))
    if f.cookie_flags:
        flags = " ".join(x for x in ("secure" if "secure" in f.cookie_flags else "",
                                     "httponly" if "httponly" in f.cookie_flags else "",
                                     "samesite=lax" if "samesite" in f.cookie_flags else "") if x)
        out.append(Snippet("Cookie flags missing", f"proxy_cookie_flags ~ {flags};", "nginx",
                           "Requires nginx ≥ 1.19.3. Better: set the flags in the application."))
    if f.exposed_paths:
        locs = "\n".join(f"location = {p} {{ return 404; }}" for p in f.exposed_paths if not p.endswith("/"))
        dirs = "\n".join(f"location ^~ {p} {{ return 404; }}" for p in f.exposed_paths if p.endswith("/"))
        out.append(Snippet("Exposed sensitive files",
                           "# always: dotfiles and VCS metadata\nlocation ~ /\\.(?!well-known) { deny all; return 404; }\n"
                           + "\n".join(x for x in (locs, dirs) if x), "nginx",
                           "Also REMOVE the files from the web root and rotate anything they contained."))
    if f.source_maps:
        out.append(Snippet("Source maps exposed", "location ~* \\.map$ { return 404; }", "nginx"))
    if f.dir_listing:
        out.append(Snippet("Directory listing enabled", "autoindex off;", "nginx"))
    if f.trace_enabled:
        out.append(Snippet("TRACE enabled", 'if ($request_method ~ ^(TRACE|TRACK)$) { return 405; }', "nginx"))
    return out


def _apache(f: Facts) -> list[Snippet]:
    out: list[Snippet] = []
    lines = [f'Header always set {h} "{_HEADERS[h]}"' for h in f.missing_headers]
    if f.csp_missing:
        lines.append(f'Header always set Content-Security-Policy-Report-Only "{_CSP_STARTER}"')
    if lines:
        out.append(Snippet("Missing security headers", "<IfModule mod_headers.c>\n  "
                           + "\n  ".join(lines) + "\n</IfModule>", "apache",
                           "Needs mod_headers. CSP is report-only first."))
    srv = []
    if f.server_version:
        srv += ["ServerTokens Prod", "ServerSignature Off"]
    if f.powered_by:
        srv += ["Header always unset X-Powered-By", "Header unset X-Powered-By"]
    if srv:
        out.append(Snippet("Version / technology disclosure", "\n".join(srv), "apache", "Server config (not .htaccess) for ServerTokens."))
    if f.cookie_flags:
        out.append(Snippet("Cookie flags missing",
                           'Header edit Set-Cookie ^(.*)$ "$1; HttpOnly; Secure; SameSite=Lax"', "apache",
                           "Blunt: applies to every cookie (and can duplicate existing flags). Prefer setting flags in the application."))
    if f.exposed_paths:
        rules = "\n".join(f'RedirectMatch 404 "^{p.rstrip("/")}(/|$)"' for p in f.exposed_paths)
        out.append(Snippet("Exposed sensitive files",
                           '# dotfiles and VCS metadata\nRedirectMatch 404 "/\\.(?!well-known)"\n' + rules, "apache",
                           "Also REMOVE the files from the web root and rotate anything they contained."))
    if f.source_maps:
        out.append(Snippet("Source maps exposed", '<FilesMatch "\\.map$">\n  Require all denied\n</FilesMatch>', "apache"))
    if f.dir_listing:
        out.append(Snippet("Directory listing enabled", "Options -Indexes", "apache"))
    if f.trace_enabled:
        out.append(Snippet("TRACE enabled", "TraceEnable off", "apache"))
    return out


def _caddy(f: Facts) -> list[Snippet]:
    out: list[Snippet] = []
    hdr = [f'{h} "{_HEADERS[h]}"' for h in f.missing_headers]
    if f.csp_missing:
        hdr.append(f'Content-Security-Policy-Report-Only "{_CSP_STARTER}"')
    if f.server_version or f.powered_by:
        hdr += ["-Server", "-X-Powered-By"]
    if hdr:
        out.append(Snippet("Security headers / disclosure", "header {\n  " + "\n  ".join(hdr) + "\n}", "caddy"))
    if f.exposed_paths:
        paths = " ".join(p.rstrip("/") + ("/*" if p.endswith("/") else "") for p in f.exposed_paths)
        out.append(Snippet("Exposed sensitive files",
                           f"@exposed path /.* {paths}\nrespond @exposed 404", "caddy",
                           "Also REMOVE the files from the web root and rotate anything they contained."))
    if f.source_maps:
        out.append(Snippet("Source maps exposed", "@maps path *.map\nrespond @maps 404", "caddy"))
    return out


def _express(f: Facts) -> list[Snippet]:
    out: list[Snippet] = []
    if f.missing_headers or f.csp_missing or f.powered_by or f.server_version:
        opts = ["  hsts: { maxAge: 31536000, includeSubDomains: true },",
                '  referrerPolicy: { policy: "strict-origin-when-cross-origin" },']
        if f.csp_missing:
            opts.append("  contentSecurityPolicy: { useDefaults: true, reportOnly: true },")
        code = ("// npm i helmet\nimport helmet from 'helmet';\napp.disable('x-powered-by');\n"
                "app.use(helmet({\n" + "\n".join(opts) + "\n}));")
        out.append(Snippet("Missing security headers / X-Powered-By", code, "js",
                           "helmet sets X-Content-Type-Options, X-Frame-Options (via frame-ancestors) and more by default."))
    if f.cookie_flags:
        out.append(Snippet("Cookie flags missing",
                           "app.use(session({\n  cookie: { httpOnly: true, secure: true, sameSite: 'lax' },\n  // + a strong secret from the environment, resave:false, saveUninitialized:false\n}));",
                           "js", "Set `app.set('trust proxy', 1)` when behind a TLS-terminating proxy, or secure cookies are dropped."))
    if f.source_maps:
        out.append(Snippet("Source maps exposed",
                           "// build: devtool: false  (webpack)  |  build.sourcemap: false  (vite)\n// or upload maps to your error tracker and delete them from the deploy artefact", "js"))
    return out


def _dns(f: Facts) -> list[Snippet]:
    out: list[Snippet] = []
    for x in f.dns:
        t = x.title
        d = urlparse(x.url).netloc or x.url.removeprefix("dns://")
        apex = d.removeprefix("_dmarc.")
        if t == "Missing SPF Record" or t.startswith("SPF Allows Any Sender") or t.startswith("SPF Neutral"):
            out.append(Snippet(t, f'{apex}.  IN TXT  "v=spf1 include:<your-mail-provider> -all"', "dns",
                               'Mail-less domain? Use exactly "v=spf1 -all".'))
        elif t.startswith("SPF References a Non-Existent Domain"):
            dom = x.extra.get("dangling_domain", "?")
            out.append(Snippet(t, f"; edit the SPF TXT record at {apex}: delete  include:{dom}", "dns",
                               "Then re-check the 10-lookup limit."))
        elif t == "Missing DMARC Record" or t == "DMARC Policy Set to 'none'":
            out.append(Snippet(t, f'_dmarc.{apex}.  IN TXT  "v=DMARC1; p=quarantine; rua=mailto:dmarc@{apex}; adkim=s; aspf=s"', "dns",
                               "Move to p=reject after reviewing aggregate reports."))
        elif t == "No CAA Record":
            out.append(Snippet(t, f'{apex}.  IN CAA  0 issue "letsencrypt.org"\n{apex}.  IN CAA  0 iodef "mailto:security@{apex}"', "dns",
                               "Replace with the CA(s) you actually use."))
        elif t.startswith("MTA-STS"):
            out.append(Snippet(t, f'_mta-sts.{apex}.  IN TXT  "v=STSv1; id=20260101T000000"\n'
                                  f"# https://mta-sts.{apex}/.well-known/mta-sts.txt:\n"
                                  "# version: STSv1\n# mode: testing\n# mx: <your-mx-host>\n# max_age: 86400", "dns",
                               "Start in testing, move to enforce."))
    for h in dict.fromkeys(f.takeover_hosts):
        out.append(Snippet(f"Dangling record: {h}", f"; remove the DNS record for {h}\n"
                           f"{h}.  CNAME  <DELETE>", "dns", "Or re-create the resource at the provider so you own it again."))
    return out


_GENERATORS = {"nginx": _nginx, "apache": _apache, "caddy": _caddy, "express": _express, "dns": _dns}
_TITLES = {"nginx": "nginx", "apache": "Apache httpd", "caddy": "Caddy", "express": "Node / Express", "dns": "DNS"}


def generate(result: ScanResult, server: str) -> str:
    server = server.lower()
    if server not in _GENERATORS:
        raise ValueError(f"unknown target '{server}' (choose: {', '.join(SERVERS)})")
    snippets = _GENERATORS[server](extract_facts(result))
    head = [f"# FSV fix pack — {_TITLES[server]}", "",
            f"Target: `{result.target}`  ·  scan `{result.scan_id[:8]}`", "",
            "> Generated from this scan's findings. **Review and test on staging before deploying** — "
            "FSV cannot know your application. Re-scan afterwards to confirm.", ""]
    if not snippets:
        return "\n".join(head + [f"✅ Nothing in this scan can be fixed with {_TITLES[server]} configuration."])
    body: list[str] = []
    for s in snippets:
        body += [f"## {s.why}", "", f"```{s.lang}", s.code, "```", ""]
        if s.note:
            body += [f"_{s.note}_", ""]
    return "\n".join(head + body)
