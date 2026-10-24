"""
FSV MCP Server
──────────────
Exposes FSV's scanning capabilities to AI agents over the Model Context Protocol.

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
from fsv.core.models import ScanConfig, ScanProfile, FindingStatus, normalize_target
from fsv.core import engine, database as db, registry
from fsv.core import report as report_mod
from fsv.core.diff import compare


mcp = MCPServer(
    "fsv",
    instructions=(
        "FSV is a defensive web vulnerability scanner (OWASP-ZAP/Nikto class). "
        "Only scan targets the user owns or is explicitly authorized to test. "
        "Before any active scan, confirm authorization with the user, then pass "
        "authorized=true. Prefer fsv_quick_check / profile='passive' for a safe "
        "first look; use profile='balanced' or 'aggressive' only with clear "
        "authorization. Every finding carries a severity, CWE, OWASP category, "
        "confidence and remediation — summarize those for the user, don't produce "
        "exploits. Use fsv_triage to record false positives/accepted risks (they "
        "persist per host), and fsv_compare_scans to show progress after a fix."
    ),
)


def _dump(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False)


def _findings_payload(result) -> dict:
    payload = {
        **result.summary_dict(),
        "findings": [
            {
                "id":             f.id,
                "fingerprint":    f.fingerprint,
                "title":          f.title,
                "severity":       f.severity.value,
                "confidence":     f.confidence.value,
                "status":         f.status.value,
                "url":            f.url,
                "affected_urls":  f.affected_urls,
                "module":         f.module,
                "parameter":      f.parameter,
                "cwe":            f.cwe,
                "owasp":          f.owasp,
                "cvss_score":     f.cvss_score,
                "description":    f.description,
                "evidence":       f.evidence,
                "recommendation": f.recommendation,
                "references":     f.references,
            }
            for f in result.findings
        ],
        "hint": f"fsv_get_report(scan_id='{result.scan_id}') for a formatted report; "
                f"fsv_triage(...) to suppress false positives.",
    }
    if result.error:
        payload["error"] = result.error
    return payload


def _auth_error() -> str:
    return _dump({
        "error": "authorization_required",
        "message": (
            "Scan refused. Ask the user to confirm they own or are explicitly "
            "authorized to test this target, then call again with authorized=true."
        ),
    })


def _validate(target: str) -> tuple[str | None, str | None]:
    try:
        return normalize_target(target), None
    except ValueError as exc:
        return None, _dump({"error": "invalid_target", "message": str(exc)})


# ── scanning tools ─────────────────────────────────────────────────────────────

@mcp.tool(
    description=(
        "Run a web vulnerability scan against a target URL. Crawls the site (same-origin, "
        "skips logout/asset links) and runs modules by profile: 'passive' sends no payloads "
        "(headers, SSL/TLS, DNS, cookies, WAF, fingerprint, JWT, CSP, SRI, security.txt); "
        "'balanced' (default) adds safe active checks (XSS, SQLi, CORS, open-redirect, SSTI, "
        "host-header); 'aggressive' is the same modules at higher rate/concurrency. Returns "
        "findings grouped with severity, CWE, OWASP category, confidence and remediation. "
        "Time-boxed by max_minutes (default 20; partial results are kept). "
        "Only scan targets the user owns or is authorized to test; pass authorized=true only "
        "after they confirm."
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
    exclude_paths: list[str] | None = None,
    max_minutes: int = 20,
) -> str:
    """Full vulnerability scan with selectable profile (time-boxed, default 20 min)."""
    if not authorized:
        return _auth_error()
    norm, err = _validate(target)
    if err:
        return err
    try:
        prof = ScanProfile(profile)
    except ValueError:
        prof = ScanProfile.BALANCED
    config = ScanConfig(
        target=norm, modules=list(modules or []), crawl=crawl,
        max_urls=max_urls, depth=depth, profile=prof,
        exclude_paths=list(exclude_paths or []),
        max_duration=max(0, max_minutes) * 60,
    )
    result = await engine.run_scan(config)
    return _dump(_findings_payload(result))


@mcp.tool(
    description=(
        "Fast passive check of a single URL — no payloads sent. Runs security headers, SSL/TLS, "
        "cookies, clickjacking, CSP review, SRI, WAF/CDN detection, technology fingerprint, DNS "
        "(SPF/DMARC), HTTP methods, security.txt, and JWT analysis. Safe for a first look. Pass "
        "authorized=true after the user confirms authorization."
    )
)
async def fsv_quick_check(target: str, authorized: bool) -> str:
    """Passive posture check (no payloads)."""
    if not authorized:
        return _auth_error()
    norm, err = _validate(target)
    if err:
        return err
    config = ScanConfig(target=norm, crawl=False, max_urls=1, profile=ScanProfile.PASSIVE)
    result = await engine.run_scan(config)
    return _dump(_findings_payload(result))


@mcp.tool(
    description=(
        "Detect whether a target sits behind a Web Application Firewall or CDN (Cloudflare, "
        "AWS WAF, Akamai, Imperva, Sucuri, F5, ModSecurity, Fastly, …). Passive, single request. "
        "Pass authorized=true after the user confirms."
    )
)
async def fsv_waf_check(target: str, authorized: bool) -> str:
    """WAF/CDN fingerprint only."""
    if not authorized:
        return _auth_error()
    norm, err = _validate(target)
    if err:
        return err
    config = ScanConfig(target=norm, modules=["waf_detect"], crawl=False, max_urls=1)
    result = await engine.run_scan(config)
    return _dump(_findings_payload(result))


# ── reporting / history tools ───────────────────────────────────────────────────

@mcp.tool(description=(
    "Get a formatted report for a completed scan. format: 'md' (default, OWASP-grouped), "
    "'json', 'html' (self-contained), 'sarif' (for CI/code-scanning), or 'csv'."))
async def fsv_get_report(scan_id: str, format: str = "md") -> str:
    """Formatted report in the requested format."""
    result = await db.get_scan(scan_id)
    if result is None:
        return "Scan not found."
    try:
        content, _ = report_mod.render(result, format)
    except ValueError as exc:
        return _dump({"error": str(exc)})
    return content


@mcp.tool(description=(
    "List recent scans with IDs, targets, status, risk grade and finding counts. "
    "Optionally filter by target host substring."))
async def fsv_list_scans(limit: int = 20, target: str | None = None) -> str:
    """Recent scan history."""
    return _dump({"scans": await db.list_scans(limit=limit, target=target)})


@mcp.tool(description=(
    "Compare two scans by scan_id (e.g. before vs after a fix). Reports which findings were "
    "resolved, which are new, which persist, the risk-score delta and an improved/regressed "
    "verdict. Triaged-away findings are excluded, so false positives don't skew the diff."))
async def fsv_compare_scans(baseline_id: str, current_id: str) -> str:
    """Diff two scans."""
    a = await db.get_scan(baseline_id)
    b = await db.get_scan(current_id)
    if a is None or b is None:
        return _dump({"error": "one or both scan_ids not found"})
    return _dump(compare(a, b))


@mcp.tool(description=(
    "Show the risk-score trend for a host across its scan history (oldest first) — useful for "
    "reporting whether a site's posture is improving over time."))
async def fsv_target_trend(target: str, limit: int = 20) -> str:
    """Risk trend for one host."""
    return _dump({"target": target, "history": await db.target_history(target, limit=limit)})


@mcp.tool(description=(
    "Record a triage decision for a finding so it persists across future scans of the same host. "
    "status: 'confirmed', 'false_positive', 'accepted_risk', 'fixed', or 'open' (clears it). "
    "false_positive / accepted_risk / fixed are excluded from the risk score. Identify the finding "
    "by its id or fingerprint from a scan result."))
async def fsv_triage(scan_id: str, finding: str, status: str, note: str = "") -> str:
    """Mark a finding's triage state (persists per host)."""
    result = await db.get_scan(scan_id)
    if result is None:
        return _dump({"error": "scan not found"})
    match = [f for f in result.findings if f.id == finding or f.fingerprint == finding]
    if not match:
        return _dump({"error": f"no finding '{finding}' in scan {scan_id}"})
    try:
        st = FindingStatus(status)
    except ValueError:
        return _dump({"error": f"invalid status '{status}'",
                      "valid": [s.value for s in FindingStatus]})
    f = match[0]
    host = db.host_of(result.target)
    await db.set_triage(host, f.fingerprint, st, note)
    return _dump({"ok": True, "finding": f.title, "status": st.value, "host": host,
                  "note": note})


@mcp.tool(description=(
    "Get the HTTP statistics of a scan (requests, cache hits, coalesced requests, retries, "
    "errors, status-code breakdown, average latency)."))
async def fsv_scan_stats(scan_id: str) -> str:
    """Per-scan request statistics."""
    result = await db.get_scan(scan_id)
    if result is None:
        return _dump({"error": "scan not found"})
    return _dump({
        "scan_id": result.scan_id, "target": result.target,
        "duration_s": result.duration_s, "urls_scanned": result.urls_scanned,
        "profile": result.profile, "modules_run": result.modules_run,
        "module_errors": result.module_errors, "stats": result.stats,
    })


@mcp.tool(description=(
    "List all FSV scan modules with their category (passive/active), scope (site/url) and what "
    "each checks, plus the available scan profiles."))
async def fsv_list_modules() -> str:
    """Describe scan modules with metadata."""
    mods = registry.describe()
    return _dump({
        "total": len(mods),
        "profiles": {
            "passive":    "passive modules only — no payloads",
            "balanced":   "all modules, safe active checks, polite rate (default)",
            "aggressive": "all modules, higher rate & concurrency",
        },
        "modules": mods,
    })


def run() -> None:
    """Entry point — runs the MCP server over stdio."""
    mcp.run(transport="stdio")


if __name__ == "__main__":
    run()
