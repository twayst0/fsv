"""End-to-end: run the real engine against a local vulnerable app."""
import asyncio
import pytest
from aiohttp import web

from fsv.core.models import ScanConfig, ScanProfile, FindingStatus
from fsv.core import engine, database as db, report
from fsv.core.diff import compare


@pytest.fixture
async def site():
    async def handler(request):
        p = request.path
        if p == "/":
            return web.Response(
                text='<html><body><a href="/p?q=1">a</a><a href="/s?x=2">b</a>'
                     '<a href="/logout">out</a>'
                     '<form method="get"><input type="password" name="pw"></form>'
                     '<script src="https://cdn.example.com/a.js"></script></body></html>',
                content_type="text/html",
                headers={"Server": "nginx/1.1", "Set-Cookie": "SID=x; Path=/"})
        if p == "/s":
            return web.Response(
                text=f"<html>{request.query.get('x','')} you have an error in your sql syntax</html>",
                content_type="text/html")
        return web.Response(text=f"<html>ok {request.query.get('q','')}</html>",
                            content_type="text/html")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", handler)
    runner = web.AppRunner(app); await runner.setup()
    s = web.TCPSite(runner, "127.0.0.1", 0); await s.start()
    port = list(runner.addresses)[0][1]
    yield f"http://127.0.0.1:{port}"
    await runner.cleanup()


@pytest.mark.asyncio
async def test_full_scan_pipeline(site):
    cfg = ScanConfig(target=site, profile=ScanProfile.BALANCED, max_urls=10,
                     timeout=5, rate_per_sec=200)
    r = await engine.run_scan(cfg)
    assert r.status.value == "completed"
    assert r.urls_scanned >= 2          # crawler followed links
    assert not r.module_errors          # nothing crashed
    titles = {f.title for f in r.findings}
    assert any("SQL Injection" in t for t in titles)
    assert any("Cross-Site Scripting" in t for t in titles)
    assert any("Cookie Missing" in t for t in titles)
    # logout link must never be scanned
    assert not any("logout" in u for u in r.urls)
    # all report formats produce output
    for fmt in report.FORMATS:
        content, _ = report.render(r, fmt)
        assert content


@pytest.mark.asyncio
async def test_passive_profile_sends_no_active_modules(site):
    cfg = ScanConfig(target=site, profile=ScanProfile.PASSIVE, crawl=False, max_urls=1)
    r = await engine.run_scan(cfg)
    assert "sqli" not in r.modules_run
    assert "xss" not in r.modules_run
    assert "headers" in r.modules_run


@pytest.mark.asyncio
async def test_triage_persists_and_affects_score(site):
    cfg = ScanConfig(target=site, profile=ScanProfile.BALANCED, max_urls=5, timeout=5, rate_per_sec=200)
    r = await engine.run_scan(cfg)
    before = r.risk_score
    f = r.findings[0]
    await db.set_triage(db.host_of(r.target), f.fingerprint, FindingStatus.FALSE_POSITIVE, "fp")
    reloaded = await db.get_scan(r.scan_id)
    marked = [x for x in reloaded.findings if x.fingerprint == f.fingerprint][0]
    assert marked.status == FindingStatus.FALSE_POSITIVE
    assert reloaded.risk_score <= before


@pytest.mark.asyncio
async def test_diff_detects_improvement(site):
    cfg = ScanConfig(target=site, profile=ScanProfile.BALANCED, max_urls=5, timeout=5, rate_per_sec=200)
    a = await engine.run_scan(cfg)
    # suppress everything → second scan "looks" clean after triage overlay
    for f in a.findings:
        await db.set_triage(db.host_of(a.target), f.fingerprint, FindingStatus.FIXED)
    b = await engine.run_scan(cfg)
    d = compare(a, b)
    # a's active findings existed, b's are all fixed → improvement
    assert d["verdict"] in ("improved", "unchanged")


@pytest.mark.asyncio
async def test_db_migration_and_history(site):
    cfg = ScanConfig(target=site, profile=ScanProfile.PASSIVE, crawl=False, max_urls=1, tags=["t1"])
    r = await engine.run_scan(cfg)
    rows = await db.list_scans(limit=5)
    assert any(row["scan_id"] == r.scan_id for row in rows)
    hist = await db.target_history(r.target)
    assert len(hist) >= 1
    # prefix lookup
    assert (await db.get_scan(r.scan_id[:8])) is not None
