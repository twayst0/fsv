"""
FSV MCP Server
──────────────
Exposes FSV's scanning capabilities to AI agents over the Model Context Protocol
(MCP SDK 2.x / MCPServer API).

An AI client (Claude, Cursor, Codex, …) can call these tools to run an authorized
security assessment and receive structured, remediation-focused reports.

IMPORTANT: Active-scan tools require the caller to pass `authorized=true`,
confirming the target is owned by the user or that explicit permission exists.
Reports describe what the issue is, why it matters, and how to fix it — not how
to weaponize it.
"""

from __future__ import annotations
import json

from mcp.server.mcpserver import MCPServer

from fsv import __version__
from fsv.core.models import ScanConfig, ScanProfile
from fsv.core import engine, database as db, registry
from fsv.core.report import generate_markdown, generate_json


mcp = MCPServer(
    "fsv",
    instructions=(
        "FSV is a defensive web vulnerability scanner (OWASP-ZAP/Nikto class). "
        "Only scan targets the user owns or is explicitly authorized to test. "
        "Before any active scan, confirm authorization with the user, then pass "
        "authorized=true. Prefer fsv_quick_check / profile='passive' for a safe "
        "first look; use profile='balanced' or 'aggressive' only with clear "
        "authorization. Every finding carries a severity, CWE, confidence and "
        "remediation — summarize those for the user, don't produce exploits."
    ),
)


def _findings_payload(result) -> dict:
    payload = {
        **result.summary_dict(),
        "findings": [
            {
                "title":          f.title,
                "severity":       f.severity.value,
                "confidence":     f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "url":            f.url,
                "module":         f.module,
                "parameter":      f.parameter,
                "cwe":            f.cwe,
                "cvss_score":     f.cvss_score,
                "description":    f.description,
                "evidence":       f.evidence,
                "recommendation": f.recommendation,
                "references":     f.references,
            }
            for f in result.findings
        ],
        "hint": f"Call fsv_get_report(scan_id='{result.scan_id}') for a formatted report.",
    }
    if result.error:
        payload["error"] = result.error
    return payload


def _auth_error() -> str:
    return json.dumps({
        "error": "authorization_required",
        "message": (
            "Scan refused. Ask the user to confirm they own or are explicitly "
            "authorized to test this target, then call again with authorized=true."
        ),
    }, indent=2)


# ── tools ────────────────────────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Run a web vulnerability scan against a target URL. Crawls the site (same-origin, "
        "skips logout/asset links) and runs modules by profile: 'passive' sends no payloads "
        "(headers, SSL/TLS, DNS, cookies, WAF, fingerprint, JWT, security.txt, GraphQL); "
        "'balanced' (default) adds safe active checks (XSS, SQLi, CORS, open-redirect, SSTI, "
        "host-header); 'aggressive' is the same modules at higher rate/concurrency. Returns "
        "findings with severity, CWE, confidence and remediation. Only scan targets the user "
        "owns or is authorized to test; pass authorized=true only after they confirm."
    )
)
async def fsv_scan(
    target: str,
    authorized: bool,
    profile: str = "balanced",
    crawl: bool = True,
    max_urls: int = 50,
    depth: int = 2,
    modules: list[str] | None = None,
) -> str:
    """Full vulnerability scan with selectable profile."""
    await db.init_db()
    if not authorized:
        return _auth_error()
    try:
        prof = ScanProfile(profile)
    except ValueError:
        prof = ScanProfile.BALANCED
    config = ScanConfig(
        target=target, modules=list(modules or []), crawl=crawl,
        max_urls=max_urls, depth=depth, profile=prof,
    )
    result = await engine.run_scan(config)
    return json.dumps(_findings_payload(result), indent=2, ensure_ascii=False)


@mcp.tool(
    description=(
        "Fast passive check of a single URL — no payloads sent. Runs security headers, SSL/TLS, "
        "cookies, clickjacking, WAF/CDN detection, technology fingerprint, DNS (SPF/DMARC), "
        "HTTP methods, security.txt, and JWT analysis. Safe for a first look. Pass authorized=true "
        "after the user confirms authorization."
    )
)
async def fsv_quick_check(target: str, authorized: bool) -> str:
    """Passive posture check (no payloads)."""
    await db.init_db()
    if not authorized:
        return _auth_error()
    config = ScanConfig(target=target, crawl=False, max_urls=1,
                        profile=ScanProfile.PASSIVE)
    result = await engine.run_scan(config)
    return json.dumps(_findings_payload(result), indent=2, ensure_ascii=False)


@mcp.tool(
    description=(
        "Detect whether a target sits behind a Web Application Firewall or CDN (Cloudflare, "
        "AWS WAF, Akamai, Imperva, Sucuri, F5, ModSecurity, Fastly, …). Passive, single request. "
        "Pass authorized=true after the user confirms."
    )
)
async def fsv_waf_check(target: str, authorized: bool) -> str:
    """WAF/CDN fingerprint only."""
    await db.init_db()
    if not authorized:
        return _auth_error()
    config = ScanConfig(target=target, modules=["waf_detect"], crawl=False, max_urls=1)
    result = await engine.run_scan(config)
    return json.dumps(_findings_payload(result), indent=2, ensure_ascii=False)


@mcp.tool(description="Get the full Markdown remediation report for a completed scan by scan_id.")
async def fsv_get_report(scan_id: str, as_json: bool = False) -> str:
    """Formatted report (Markdown by default, or JSON)."""
    await db.init_db()
    result = await db.get_scan(scan_id)
    if result is None:
        return "Scan not found."
    return generate_json(result) if as_json else generate_markdown(result)


@mcp.tool(description="List recent scans with IDs, targets, status, risk grade, and finding counts.")
async def fsv_list_scans(limit: int = 20) -> str:
    """Recent scan history."""
    await db.init_db()
    return json.dumps(await db.list_scans(limit=limit), indent=2, ensure_ascii=False)


@mcp.tool(
    description=(
        "Compare two scans by scan_id (e.g. before vs after a fix). Reports which findings were "
        "resolved, which are new, and the risk-score/grade delta."
    )
)
async def fsv_compare_scans(baseline_id: str, current_id: str) -> str:
    """Diff two scans."""
    await db.init_db()
    a = await db.get_scan(baseline_id)
    b = await db.get_scan(current_id)
    if a is None or b is None:
        return json.dumps({"error": "one or both scan_ids not found"}, indent=2)

    def key(f):
        return f"{f.module}:{f.title}:{f.parameter}"
    a_keys = {key(f): f for f in a.findings}
    b_keys = {key(f): f for f in b.findings}
    resolved = [a_keys[k].title for k in a_keys if k not in b_keys]
    added    = [b_keys[k].title for k in b_keys if k not in a_keys]
    return json.dumps({
        "baseline": {"scan_id": a.scan_id, "grade": a.grade, "risk_score": a.risk_score,
                     "findings": len(a.findings)},
        "current":  {"scan_id": b.scan_id, "grade": b.grade, "risk_score": b.risk_score,
                     "findings": len(b.findings)},
        "risk_delta": b.risk_score - a.risk_score,
        "resolved":  resolved,
        "new":       added,
    }, indent=2, ensure_ascii=False)


@mcp.tool(description="Get the HTTP statistics of a scan (requests sent, cache hits, retries, errors, bytes).")
async def fsv_scan_stats(scan_id: str) -> str:
    """Per-scan request statistics."""
    await db.init_db()
    result = await db.get_scan(scan_id)
    if result is None:
        return json.dumps({"error": "scan not found"}, indent=2)
    return json.dumps({
        "scan_id": result.scan_id, "target": result.target,
        "duration_s": result.duration_s, "urls_scanned": result.urls_scanned,
        "profile": result.profile, "stats": result.stats,
    }, indent=2, ensure_ascii=False)


@mcp.tool(description="List all FSV scan modules with their category (passive/active), scope, and what each checks.")
async def fsv_list_modules() -> str:
    """Describe scan modules with metadata."""
    descriptions = {
        "headers":              "Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options)",
        "ssl":                  "SSL/TLS: HTTPS, cert validity/expiry, weak protocols & ciphers",
        "xss":                  "Reflected Cross-Site Scripting in URL parameters",
        "sqli":                 "Error-based SQL injection in URL parameters",
        "cors":                 "CORS misconfiguration (wildcard, origin reflection, null)",
        "cookies":              "Cookie flags (Secure, HttpOnly, SameSite)",
        "csrf":                 "Missing CSRF protection on POST forms",
        "open_redirect":        "Open redirect in redirect-style parameters",
        "tech":                 "Technology fingerprint + outdated-software hints",
        "paths":                "Exposed sensitive files (.git, .env, backups, admin) w/ calibration",
        "info_disclosure":      "Leaked secrets, stack traces, internal IPs",
        "clickjacking":         "Missing frame protection",
        "http_methods":         "Dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT)",
        "dns_security":         "Email/DNS anti-spoofing records (SPF, DMARC, CAA)",
        "dir_listing":          "Directory listing / auto-index enabled",
        "mixed_content":        "HTTP resources on HTTPS pages",
        "subdomain":            "Subdomain enumeration + sensitive subdomain exposure",
        "security_txt":         "security.txt / responsible-disclosure policy (RFC 9116)",
        "waf_detect":           "WAF/CDN fingerprinting",
        "graphql_introspection":"GraphQL introspection exposure",
        "host_header_injection":"Host header injection (redirect/cache poisoning)",
        "jwt_analysis":         "JWT weaknesses (alg:none, weak HMAC, sensitive claims)",
        "ssti":                 "Server-Side Template Injection (benign math marker)",
    }
    out = {}
    for name, desc in descriptions.items():
        meta = registry.META.get(name, {})
        out[name] = {
            "description": desc,
            "category":    meta.get("category", "passive"),
            "scope":       meta.get("scope", "url"),
        }
    return json.dumps({
        "total": len(out),
        "profiles": {
            "passive":    "passive modules only — no payloads",
            "balanced":   "all modules, safe active checks, polite rate (default)",
            "aggressive": "all modules, higher rate & concurrency",
        },
        "modules": out,
    }, indent=2, ensure_ascii=False)


def run() -> None:
    """Entry point — runs the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
