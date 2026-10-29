"""End to end, real engine: deep vs full against a local site with things only an exhaustive scan reaches."""
import re

import pytest
from aiohttp import web

from fsv.core import engine
from fsv.core.models import ScanConfig, ScanProfile

HOME = """<html><body><a href="/legacy.php">old</a><a href="/item?id=5">item</a>
<div data-href="/spa/route">go</div><link rel="next" href="/page/2"></body></html>"""


@pytest.fixture
async def site():
    async def handler(request):
        p, q = request.path, request.query
        if p == "/":
            return web.Response(text=HOME, content_type="text/html")
        if p == "/legacy.php":
            return web.Response(text="<html>legacy page " + "x" * 80 + "</html>", content_type="text/html")
        if p == "/legacy.php.bak":                                     # the web server hands out the source of the original
            return web.Response(text="<?php\n$password = 'Hunter2Hunter2';\n", content_type="text/plain")
        if p == "/spa/route":                                           # only reachable through a data-href
            return web.Response(text="<html>spa page " + "y" * 80 + "</html>", content_type="text/html")
        if p == "/page/2":
            return web.Response(text="<html>page two " + "z" * 80 + "</html>", content_type="text/html")
        if p == "/staging":                                             # nothing links here
            return web.Response(text="<html>staging copy " + "s" * 120 + "</html>", content_type="text/html")
        if p == "/item":
            rows = 0 if re.search(r"AND\s*(['\"]?)1\1\s*=\s*(['\"]?)2", q.get("id", "")) else 3
            return web.Response(text="<html>" + "<tr>a row of product data for sale</tr>" * rows + "</html>", content_type="text/html")
        return web.Response(status=404, text="not found")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", handler)
    runner = web.AppRunner(app); await runner.setup()
    s = web.TCPSite(runner, "127.0.0.1", 0); await s.start()
    yield f"http://127.0.0.1:{list(runner.addresses)[0][1]}"
    await runner.cleanup()


def run(site, profile):
    return engine.run_scan(ScanConfig(target=site, profile=profile, timeout=5, rate_per_sec=200, allow_external=False))


def titles(r):
    return {f.title for f in r.findings}


async def test_full_reaches_what_deep_does_not_and_never_loses_a_finding(site):
    deep, full = await run(site, ScanProfile.DEEP), await run(site, ScanProfile.FULL)
    assert not deep.module_errors and not full.module_errors, (deep.module_errors, full.module_errors)
    assert full.profile == "full" and full.stats["requests"] > deep.stats["requests"]
    # pages only reachable through link kinds a plain <a href> crawl ignores
    assert any(u.endswith("/spa/route") for u in full.urls) and any(u.endswith("/page/2") for u in full.urls)
    assert not any(u.endswith("/spa/route") for u in deep.urls)
    t = titles(full)
    assert any(x.startswith("Backup Copy Exposes Source or Configuration") and "legacy.php.bak" in x for x in t)
    assert any(x.startswith("Unlinked Administrative or Internal Paths Found") for x in t)          # /staging
    assert "SQL Injection (Boolean-Based)" in t
    for x in ("SQL Injection (Boolean-Based)",):
        assert x not in titles(deep)
    assert not any(x.startswith("Backup Copy") for x in titles(deep))
    assert titles(deep) <= t


async def test_full_report_never_contains_the_leaked_source(site):
    import json
    r = await run(site, ScanProfile.FULL)
    assert "Hunter2Hunter2" not in json.dumps([f.model_dump(mode="json") for f in r.findings])
