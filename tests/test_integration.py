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


async def test_concurrent_init_db_is_safe():
    """Regression: parallel first calls used to race on ALTER TABLE (duplicate column)."""
    import aiosqlite, os
    path = os.environ["FSV_DB"]
    # start from a v1-shaped table so the migration path actually runs
    async with aiosqlite.connect(path) as conn:
        await conn.execute("CREATE TABLE scans (scan_id TEXT PRIMARY KEY, target TEXT NOT NULL, "
                           "status TEXT NOT NULL DEFAULT 'pending', started_at TEXT NOT NULL, "
                           "finished_at TEXT, duration_s REAL DEFAULT 0, urls_scanned INTEGER DEFAULT 0, "
                           "tech_stack TEXT DEFAULT '[]', findings TEXT DEFAULT '[]', error TEXT, "
                           "config TEXT DEFAULT '{}')")
        await conn.commit()
    db._initialized.clear()
    await asyncio.gather(*(db.init_db() for _ in range(8)))
    assert await db.list_scans() == []


async def test_module_failures_are_recorded_with_a_reason(monkeypatch, caplog):
    """A crashing module must not vanish silently: count it, keep the reason, log it."""
    import logging
    from fsv.core import registry
    from fsv.core.scanner import BaseScanner

    class Boom(BaseScanner):
        name = "boom_plugin"; scope = "site"; description = "always fails"
        async def scan(self, url):
            raise RuntimeError("kaboom detail")
    registry.load_registry()
    registry._register(Boom, "test")
    try:
        async def h(r):
            return web.Response(text="<html></html>", content_type="text/html")
        app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
        rn = web.AppRunner(app); await rn.setup()
        s = web.TCPSite(rn, "127.0.0.1", 0); await s.start()
        port = list(rn.addresses)[0][1]
        try:
            with caplog.at_level(logging.WARNING, logger="fsv.engine"):
                r = await engine.run_scan(ScanConfig(target=f"http://127.0.0.1:{port}", crawl=False,
                                                     max_urls=1, modules=["boom_plugin", "headers"]))
        finally:
            await rn.cleanup()
    finally:
        registry.load_registry(reload=True)
    assert r.status.value == "completed"                       # one broken module doesn't fail the scan
    assert r.module_errors == {"boom_plugin": 1}
    assert "RuntimeError: kaboom detail" in r.module_error_samples["boom_plugin"]
    assert any("boom_plugin" in rec.message for rec in caplog.records)
    reloaded = await db.get_scan(r.scan_id)                    # survives persistence
    assert "kaboom" in reloaded.module_error_samples["boom_plugin"]
    assert "module_error_samples" not in reloaded.stats
