"""MCP tools are plain async functions — call them against a seeded database."""
import json


from fsv.core import database as db
from fsv.core.correlate import correlate
from fsv.core.models import Finding, ScanResult, ScanStatus, Severity, FindingStatus
from fsv.mcp import server as m

T = "https://www.example.com"


def F(title, module, sev=Severity.MEDIUM, **extra):
    return Finding(title=title, severity=sev, url=T + "/", module=module, description="d", extra=extra)


async def seed():
    base = [F("Reflected Cross-Site Scripting (XSS)", "xss", Severity.HIGH),
            F("Cookie Missing HttpOnly Flag: `SID`", "cookies", Severity.HIGH,
              cookie="SID", session_like=True, flag="httponly"),
            F("Missing Security Header: X-Content-Type-Options", "headers")]
    r = ScanResult(scan_id="mcp-scan-1", target=T, status=ScanStatus.COMPLETED,
                   started_at="2026-01-01T00:00:00+00:00", findings=base + correlate(base))
    await db.upsert_scan(r)
    return r


async def test_authorization_and_validation_gates():
    assert "authorization_required" in await m.fsv_scan("example.com", authorized=False)
    assert "invalid_target" in await m.fsv_scan("ftp://x", authorized=True)
    assert "authorization_required" in await m.fsv_quick_check("example.com", authorized=False)


async def test_fix_and_report_tools_and_attack_paths():
    await seed()
    out = await m.fsv_fixes("mcp-scan-1", "nginx")
    assert "X-Content-Type-Options" in out and out.startswith("# FSV fix pack")
    assert "error" in json.loads(await m.fsv_fixes("mcp-scan-1", "iis"))
    assert "error" in json.loads(await m.fsv_fixes("missing", "nginx"))
    assert (await m.fsv_get_report("mcp-scan-1", "fix-nginx")).startswith("# FSV fix pack")
    assert "unknown report format" in await m.fsv_get_report("mcp-scan-1", "pdf")

    res = await db.get_scan("mcp-scan-1")
    payload = m._findings_payload(res)
    assert [p["title"] for p in payload["attack_paths"]] == ["Attack Path: XSS → Session Hijack (cookie readable by script)"]
    assert payload["attack_paths"][0]["break_the_chain"] and payload["attack_paths"][0]["links"]


async def test_triage_tool_validates_status_and_breaks_the_chain():
    await seed()
    res = await db.get_scan("mcp-scan-1")
    xss = next(f for f in res.findings if f.module == "xss")
    bad = json.loads(await m.fsv_triage("mcp-scan-1", xss.id, "superseded"))
    assert "invalid status" in bad["error"] and "superseded" not in bad["valid"]
    ok = json.loads(await m.fsv_triage("mcp-scan-1", xss.id, "false_positive", "test page"))
    assert ok["ok"] is True
    after = await db.get_scan("mcp-scan-1")
    chain = next(f for f in after.findings if f.module == "correlation")
    assert chain.status == FindingStatus.SUPERSEDED
    assert not m._findings_payload(after)["attack_paths"]


async def test_list_modules_reports_external_and_source():
    data = json.loads(await m.fsv_list_modules())
    mods = {x["name"]: x for x in data["modules"]}
    assert mods["takeover"]["external"] is True and mods["headers"]["external"] is False
    assert data["total"] == len(mods) >= 30
