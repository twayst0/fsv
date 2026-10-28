"""End to end through the real engine: a local app with the issues the newer modules look for, balanced vs deep."""
import json

import pytest
from aiohttp import web

from fsv.core import engine
from fsv.core.models import ScanConfig, ScanProfile

SPEC = {"openapi": "3.0.0", "info": {"title": "shop"}, "paths": {"/admin/export": {"post": {}}, "/items": {"get": {}}}}
JWKS = {"keys": [{"kty": "RSA", "kid": "k1", "n": "AQAB", "e": "AQAB", "d": "PRIVATEPART", "p": "x", "q": "y"}]}
OIDC = {"issuer": "http://id.shop.test", "authorization_endpoint": "http://id.shop.test/auth", "token_endpoint": "https://id.shop.test/t",
        "response_types_supported": ["code"], "code_challenge_methods_supported": ["S256"]}
HOME = """<html><head><title>Shop</title></head><body>
<!-- build note: db at 10.1.2.3, password: Spring2024Secret! -->
<a href="/results">results</a>
<form><input type="hidden" name="price" value="19.99"><input type="password" name="p" value="StoredPassw0rd"></form>
<script>document.getElementById('out').innerHTML = location.hash.slice(1);</script>
</body></html>"""


@pytest.fixture
async def site():
    async def handler(request):
        p, q = request.path, request.query
        if p == "/":
            return web.Response(text=HOME, content_type="text/html")
        if p == "/results":
            # reflects ?lang= unescaped although no link mentions it; ?q= is escaped properly
            import html
            return web.Response(text=f"<html><p>Language: {q.get('lang', '')}</p><p>{html.escape(q.get('q', ''))}</p></html>", content_type="text/html")
        if p == "/openapi.json":
            return web.json_response(SPEC)
        if p == "/.well-known/jwks.json":
            return web.json_response(JWKS)
        if p == "/.well-known/openid-configuration":
            return web.json_response(OIDC)
        if p == "/robots.txt":
            return web.Response(text="User-agent: *\nDisallow: /backup-old/\n", content_type="text/plain")
        if p == "/backup-old/":
            return web.Response(text="<html>" + "archive listing " * 40 + "</html>", content_type="text/html")
        if p == "/db.sqlite3":
            return web.Response(body=b"SQLite format 3\x00" + b"\x00" * 100, content_type="application/octet-stream")
        return web.Response(status=404, text="not found")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", handler)
    runner = web.AppRunner(app); await runner.setup()
    s = web.TCPSite(runner, "127.0.0.1", 0); await s.start()
    yield f"http://127.0.0.1:{list(runner.addresses)[0][1]}"
    await runner.cleanup()


def run(site, profile):
    return engine.run_scan(ScanConfig(target=site, profile=profile, max_urls=20, timeout=5, rate_per_sec=200, allow_external=False))


def titles(r):
    return {f.title for f in r.findings}


async def test_balanced_finds_the_page_level_and_well_known_issues(site):
    r = await run(site, ScanProfile.BALANCED)
    assert r.status.value == "completed" and not r.module_errors, r.module_errors
    t = titles(r)
    assert "DOM-Based XSS: URL Data Reaches an HTML Sink" in t
    assert "Credentials or Secrets in HTML Comments" in t
    assert "Internal Hostnames, IP Addresses or Paths in HTML Comments" in t
    assert "Password Field Is Pre-Filled" in t
    assert "Hidden Form Field Carries Data the Server Should Not Trust" in t
    assert "Private Key Material Published in JWKS" in t
    assert "OAuth/OIDC Endpoints Advertised Over HTTP" in t
    assert any(x.startswith("Public API Specification Lists") for x in t)
    assert "robots.txt Points Out Sensitive Paths" in t
    # not in a normal scan
    assert not any("db.sqlite3" in x for x in t)
    assert not any(f.module == "xss" for f in r.findings), "the hidden parameter is only found by the deep profile"


async def test_deep_adds_hidden_parameters_extra_files_and_reachability(site):
    balanced, deep = await run(site, ScanProfile.BALANCED), await run(site, ScanProfile.DEEP)
    assert not deep.module_errors, deep.module_errors
    xss = [f for f in deep.findings if f.module == "xss"]
    assert [f.parameter for f in xss] == ["lang"] and xss[0].extra["hidden_parameter"] is True       # `q` is escaped → not reported
    assert any("db.sqlite3" in f.title for f in deep.findings)
    assert "Path Listed in robots.txt Is Open: `/backup-old/`" in titles(deep)
    assert deep.stats["requests"] > balanced.stats["requests"] + 60
    assert titles(balanced) <= titles(deep)                                     # deep never loses a finding
    assert deep.profile == "deep"


async def test_secrets_in_the_report_are_masked_everywhere(site):
    r = await run(site, ScanProfile.DEEP)
    blob = json.dumps([f.model_dump(mode="json") for f in r.findings])
    for secret in ("Spring2024Secret!", "StoredPassw0rd", "PRIVATEPART"):
        assert secret not in blob, f"{secret} leaked into findings"
