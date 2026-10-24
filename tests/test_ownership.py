import pytest
from aiohttp import web

from fsv.core import dnsutil, ownership, database as db, engine
from fsv.core.models import ScanConfig
from helpers import FakeDNS

SECRET = "s" * 64


@pytest.fixture(autouse=True)
def _restore():
    yield
    dnsutil.set_backend(None)


def test_token_is_domain_specific_and_secret_dependent():
    a = ownership.token_for("example.com", SECRET)
    assert a == ownership.token_for("EXAMPLE.com", SECRET) and len(a) == 32
    assert a != ownership.token_for("other.com", SECRET)
    assert a != ownership.token_for("example.com", "t" * 64)       # another install can't reuse it


def test_instructions_use_registrable_domain():
    i = ownership.instructions("shop.example.co.uk", SECRET)
    assert i["domain"] == "example.co.uk" and i["dns"]["name"] == "_fsv-challenge.example.co.uk"
    assert i["http"]["url"] == "https://shop.example.co.uk/.well-known/fsv-verification.txt"
    assert i["token"] == i["dns"]["value"] == i["http"]["body"]


def test_coverage_rules():
    assert ownership.covers("example.com", "dns", "app.example.com")
    assert ownership.covers("example.com", "dns", "example.com")
    assert not ownership.covers("example.com", "dns", "example.com.evil.net")
    assert not ownership.covers("example.com", "dns", "notexample.com")
    assert ownership.covers("app.example.com", "http", "app.example.com")
    assert not ownership.covers("app.example.com", "http", "api.example.com")   # HTTP proof = exact host only


async def test_dns_proof(no_http_proof):
    tok = ownership.token_for("example.com", SECRET)
    FakeDNS({"_fsv-challenge.example.com": {"TXT": [f"fsv-verify={tok}"]}}).install()
    assert await ownership.check_proof("www.example.com", SECRET) == "dns"
    FakeDNS({"_fsv-challenge.example.com": {"TXT": ["fsv-verify=" + "0" * 32]}}).install()   # someone else's token
    assert await ownership.check_proof("www.example.com", SECRET, timeout=1) is None


async def test_http_proof_requires_exact_token_and_refuses_redirects():
    FakeDNS({}).install()
    state = {"body": None, "redirect": False}

    async def h(r):
        if r.path == "/.well-known/fsv-verification.txt":
            if state["redirect"]:
                raise web.HTTPFound("http://elsewhere.invalid/x")
            return web.Response(text=state["body"] or "")
        return web.Response(status=404)
    app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
    rn = web.AppRunner(app); await rn.setup()
    s = web.TCPSite(rn, "127.0.0.1", 0); await s.start()
    netloc = f"127.0.0.1:{list(rn.addresses)[0][1]}"
    try:
        tok = f"fsv-verify={ownership.token_for('127.0.0.1', SECRET)}"
        state["body"] = tok + "\n"
        assert await ownership.check_proof("127.0.0.1", SECRET, netloc=netloc) == "http"
        state["body"] = tok + " extra"
        assert await ownership.check_proof("127.0.0.1", SECRET, netloc=netloc) is None
        state["body"], state["redirect"] = tok, True
        assert await ownership.check_proof("127.0.0.1", SECRET, netloc=netloc) is None
    finally:
        await rn.cleanup()


async def test_is_local_target():
    assert await ownership.is_local_target("http://127.0.0.1:8080/")
    assert await ownership.is_local_target("http://192.168.1.10/")
    assert not await ownership.is_local_target("http://93.184.216.34/")


def test_expiry():
    assert not ownership.expired("2999-01-01T00:00:00+00:00")
    assert ownership.expired("2000-01-01T00:00:00+00:00") and ownership.expired("garbage")


async def test_install_secret_is_stable_and_verified_hosts_roundtrip():
    s1 = await db.get_install_secret()
    assert s1 == await db.get_install_secret() and len(s1) == 64
    await db.add_verified("example.com", "dns")
    assert await db.is_host_verified("app.example.com")
    assert not await db.is_host_verified("example.org")
    await db.add_verified("api.shop.org", "http")
    assert await db.is_host_verified("api.shop.org") and not await db.is_host_verified("www.shop.org")


# ── enforcement in the engine ────────────────────────────────────────────────

async def _site():
    async def h(r):
        return web.Response(text="<html></html>", content_type="text/html")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", h)
    rn = web.AppRunner(app); await rn.setup()
    s = web.TCPSite(rn, "127.0.0.1", 0); await s.start()
    return rn, f"http://127.0.0.1:{list(rn.addresses)[0][1]}"


async def test_enforcement_blocks_active_scans_of_unverified_public_hosts(monkeypatch):
    rn, url = await _site()
    monkeypatch.setattr(engine, "REQUIRE_VERIFICATION", True)

    async def not_local(_): return False                    # pretend the target is a public host
    monkeypatch.setattr(ownership, "is_local_target", not_local)
    try:
        r = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1, modules=["xss", "headers"]))
        assert r.status.value == "failed" and "not verified" in r.error and "_fsv-challenge" in r.error
        assert r.findings == []                                  # no request was sent

        passive = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1,
                                                   modules=["headers"], profile="passive"))
        assert passive.status.value == "completed"               # read-only is allowed without proof
        only_passive_modules = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1,
                                                                modules=["headers", "cookies"]))
        assert only_passive_modules.status.value == "completed"  # nothing in the set sends payloads

        await db.add_verified("127.0.0.1", "http")
        ok = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1, modules=["xss"]))
        assert ok.status.value == "completed"
    finally:
        await rn.cleanup()


async def test_enforcement_exempts_local_targets_and_is_off_by_default(monkeypatch):
    rn, url = await _site()
    try:
        monkeypatch.setattr(engine, "REQUIRE_VERIFICATION", True)
        r = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1, modules=["xss"]))
        assert r.status.value == "completed"                     # 127.0.0.1 = local development
        monkeypatch.setattr(engine, "REQUIRE_VERIFICATION", False)

        async def not_local(_): return False
        monkeypatch.setattr(ownership, "is_local_target", not_local)
        r2 = await engine.run_scan(ScanConfig(target=url, crawl=False, max_urls=1, modules=["xss"]))
        assert r2.status.value == "completed"                    # feature is opt-in
    finally:
        await rn.cleanup()
