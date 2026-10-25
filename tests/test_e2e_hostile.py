"""
Whole-engine runs against real local servers that behave badly. A scanner that is only tested
with polite fakes falls over on the first real site; these servers are the impolite ones.
"""
import asyncio
import os
import time

import pytest
from aiohttp import web

from fsv.core.engine import run_scan
from fsv.core.models import ScanConfig

SPA = "<!doctype html><html><head><title>App</title></head><body><div id=root></div>" \
      "<script src=/static/main.js></script></body></html>"


async def _serve(handler):
    app = web.Application()
    app.router.add_route("*", "/{tail:.*}", handler)
    runner = web.AppRunner(app, shutdown_timeout=0.5)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    return runner, list(runner.addresses)[0][1]


@pytest.fixture(autouse=True)
def _db(tmp_path, monkeypatch):
    monkeypatch.setenv("FSV_DB", str(tmp_path / "e2e.db"))
    from fsv.core import database
    if hasattr(database, "_initialised"):
        database._initialised.clear()


def _cfg(port, **kw):
    base = dict(target=f"http://127.0.0.1:{port}", max_urls=25, timeout=3, rate_per_sec=200,
                max_retries=0, allow_external=False, max_duration=120)
    base.update(kw)
    return ScanConfig(**base)


async def test_catch_all_single_page_app_produces_no_exposure_false_positives():
    """Every path answers 200 with the same HTML shell — the classic SPA/soft-404 trap."""
    async def handler(request):
        if request.path == "/static/main.js":
            return web.Response(text="fetch('/api/me').then(r=>r.json());", content_type="application/javascript")
        return web.Response(text=SPA, content_type="text/html")
    runner, port = await _serve(handler)
    try:
        r = await asyncio.wait_for(run_scan(_cfg(port)), 120)
    finally:
        await runner.cleanup()
    assert r.status.value == "completed" and r.module_errors == {}
    assert len(r.modules_run) >= 25 and r.stats["requests"] > 100, (r.modules_run, r.stats)
    noisy = [f.title for f in r.findings
             if f.module in ("paths", "debug_mode", "dir_listing", "graphql_introspection", "info_disclosure")]
    assert noisy == [], noisy
    assert "http://127.0.0.1:%d/api/me" % port in r.urls          # found through JavaScript


async def test_hostile_server_redirect_loops_huge_bodies_hangs_and_errors():
    async def handler(request):
        p = request.path
        if p == "/":
            return web.Response(text='<a href="/loop">l</a><a href="/big">b</a><a href="/hang">h</a>'
                                     '<a href="/boom">x</a><a href="/search?q=1">s</a>', content_type="text/html")
        if p == "/loop":
            raise web.HTTPFound("/loop")
        if p == "/big":
            return web.Response(body=b"<html>" + b"A" * (20 * 1024 * 1024), content_type="text/html")
        if p == "/hang":
            await asyncio.sleep(30)
        if p == "/boom":
            return web.Response(status=500, text="Internal Server Error")
        if p == "/search":
            return web.Response(text=f"<p>results for {request.query.get('q', '')!s:.0}</p>", content_type="text/html")
        return web.Response(status=404, text="not found")
    runner, port = await _serve(handler)
    try:
        t0 = time.monotonic()
        r = await asyncio.wait_for(run_scan(_cfg(port)), 150)
        took = time.monotonic() - t0
    finally:
        await runner.cleanup()
    assert r.status.value == "completed", r.error
    assert r.module_errors == {}, r.module_error_samples if hasattr(r, "module_error_samples") else r.module_errors
    assert took < 20, took                       # one hanging URL costs one timeout, not one per module
    assert r.stats["unresponsive_urls"] == [f"http://127.0.0.1:{port}/hang"]
    assert r.stats["bytes_in"] < 40 * 1024 * 1024          # bodies are capped, never buffered whole


@pytest.mark.skipif(os.environ.get("CI_SLOW") is None, reason="set CI_SLOW=1 for the concurrency soak")
async def test_many_concurrent_scans_share_nothing():
    async def handler(request):
        return web.Response(text="<html><a href='/a'>a</a></html>", content_type="text/html")
    runner, port = await _serve(handler)
    try:
        results = await asyncio.gather(*(run_scan(_cfg(port, max_urls=5)) for _ in range(8)))
    finally:
        await runner.cleanup()
    assert len({r.scan_id for r in results}) == 8 and all(r.status.value == "completed" for r in results)


# ── proxy ────────────────────────────────────────────────────────────────────

async def test_scan_through_a_proxy_reaches_a_host_only_the_proxy_can_resolve():
    """The target name does not exist in DNS; only the proxy knows it — so success proves every
    request went through the proxy (corporate networks, sandboxes)."""
    seen_hosts = set()

    async def proxy(request):
        seen_hosts.add(request.host)
        if request.path == "/":
            return web.Response(text="<html><a href='/about'>a</a></html>", content_type="text/html",
                                headers={"Server": "Apache/2.2.15"})
        return web.Response(text="<html>about</html>", content_type="text/html")
    runner, port = await _serve(proxy)
    try:
        cfg = _cfg(port, target="http://only-via-proxy.fsv.invalid", proxy=f"http://127.0.0.1:{port}")
        r = await asyncio.wait_for(run_scan(cfg), 120)
    finally:
        await runner.cleanup()
    assert r.status.value == "completed", r.error
    assert "http://only-via-proxy.fsv.invalid/about" in r.urls
    assert seen_hosts == {"only-via-proxy.fsv.invalid"}
    assert any(f.title == "Server Version Disclosure" for f in r.findings)


def test_resolve_proxy_env_no_proxy_and_shared_deployment(monkeypatch):
    from fsv.core import engine
    cfg = lambda p, t="https://site.test": ScanConfig(target=t, proxy=p)
    assert engine.resolve_proxy(cfg("")) is None
    monkeypatch.setenv("HTTPS_PROXY", "http://corp-proxy:3128")
    monkeypatch.delenv("https_proxy", raising=False)
    assert engine.resolve_proxy(cfg("env")) == "http://corp-proxy:3128"
    monkeypatch.delenv("no_proxy", raising=False)
    monkeypatch.setenv("NO_PROXY", "site.test")
    assert engine.resolve_proxy(cfg("env")) is None
    with pytest.raises(ValueError):
        engine.resolve_proxy(cfg("socks5://x:1"))
    monkeypatch.setattr(engine, "BLOCK_PRIVATE", True)
    with pytest.raises(ValueError, match="FSV_BLOCK_PRIVATE"):
        engine.resolve_proxy(cfg("http://p:1"))
