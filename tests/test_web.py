"""Web API + request guard (CSRF / DNS rebinding / token)."""
import asyncio
import httpx
import pytest
from httpx import ASGITransport

from fsv.web.security import RequestGuard, allowed_hosts, _split_host


def test_split_host():
    assert _split_host("example.com:7474") == "example.com"
    assert _split_host("[::1]:7474") == "::1"
    assert _split_host("localhost") == "localhost"


def test_allowed_hosts():
    assert "localhost" in allowed_hosts("127.0.0.1", "")
    assert "fsv.internal" in allowed_hosts("127.0.0.1", "fsv.internal")
    assert allowed_hosts("0.0.0.0", "") is None           # wildcard w/o allowlist → any
    assert "box" in allowed_hosts("0.0.0.0", "box")
    assert allowed_hosts("127.0.0.1", "*") is None


def _client(app, host="127.0.0.1:7474"):
    return httpx.AsyncClient(transport=ASGITransport(app=app), base_url=f"http://{host}")


@pytest.fixture
def app():
    import fsv.web.app as webapp
    return webapp.app


async def test_rebinding_host_rejected(app):
    async with _client(app, host="attacker.example:7474") as c:
        r = await c.get("/api/info")
    assert r.status_code == 403
    assert "DNS-rebinding" in r.json()["detail"]


async def test_loopback_host_allowed(app):
    async with _client(app) as c:
        r = await c.get("/api/info")
    assert r.status_code == 200
    from fsv.core import registry
    assert len(r.json()["modules"]) == len(registry.load_registry()) >= 30


async def test_cross_origin_post_blocked(app):
    async with _client(app) as c:
        r = await c.post("/api/scan", json={"target": "http://127.0.0.1:1", "authorized": True},
                         headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


async def test_sec_fetch_site_cross_site_blocked(app):
    async with _client(app) as c:
        r = await c.post("/api/scan/x/cancel", headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403


async def test_non_json_body_blocked(app):
    async with _client(app) as c:
        r = await c.post("/api/scan", content=b'{"target":"x","authorized":true}',
                         headers={"Content-Type": "text/plain"})
    assert r.status_code == 403


async def test_same_origin_post_allowed(app):
    async with _client(app) as c:
        r = await c.post("/api/scan", json={"target": "ftp://nope", "authorized": True},
                         headers={"Origin": "http://127.0.0.1:7474"})
    assert r.status_code == 400   # reached the handler → validation error, not guard


async def test_authorization_required(app):
    async with _client(app) as c:
        r = await c.post("/api/scan", json={"target": "http://127.0.0.1:1"})
    assert r.status_code == 403
    assert "Authorization required" in r.json()["detail"]


async def test_token_enforced(app, monkeypatch):
    import fsv.web.app as webapp
    monkeypatch.setattr(webapp, "API_TOKEN", "s3cret")
    async with _client(app) as c:
        assert (await c.get("/api/scans")).status_code == 401
        assert (await c.get("/api/scans", headers={"X-FSV-Token": "wrong"})).status_code == 401
        assert (await c.get("/api/scans", headers={"X-FSV-Token": "s3cret"})).status_code == 200
        assert (await c.get("/api/scans?token=s3cret")).status_code == 200


async def test_scan_lifecycle_delta_and_active(app, unused_tcp_port_factory=None):
    from aiohttp import web
    async def handler(request):
        return web.Response(text='<html><form><input name="q"></form></html>',
                            content_type="text/html")
    site = web.Application(); site.router.add_route("*", "/{t:.*}", handler)
    runner = web.AppRunner(site); await runner.setup()
    tcp = web.TCPSite(runner, "127.0.0.1", 0); await tcp.start()
    port = list(runner.addresses)[0][1]
    target = f"http://127.0.0.1:{port}"
    try:
        async with _client(app) as c:
            ids = []
            for _ in range(2):
                r = await c.post("/api/scan", json={
                    "target": target, "authorized": True, "profile": "passive",
                    "crawl": False, "max_urls": 1, "timeout": 5, "rate_per_sec": 100})
                assert r.status_code == 200
                sid = r.json()["scan_id"]; ids.append(sid)
                for _ in range(200):
                    g = await c.get(f"/api/scan/{sid}")
                    if g.status_code == 200 and g.json()["status"] != "running":
                        break
                    await asyncio.sleep(0.05)
                assert g.json()["status"] == "completed"
            d = (await c.get(f"/api/scan/{ids[1]}/delta")).json()
            assert d["previous"] == ids[0]
            assert d["verdict"] in ("improved", "regressed", "unchanged")
            for _ in range(100):               # the pending entry is dropped just after the scan is persisted
                if (await c.get("/api/active")).json() == []:
                    break
                await asyncio.sleep(0.05)
            assert (await c.get("/api/active")).json() == []
            rep = await c.get(f"/api/scan/{ids[1]}/report?format=html")
            assert rep.status_code == 200 and "attachment" not in rep.headers["content-disposition"]
            assert (await c.delete(f"/api/scan/{ids[0]}")).status_code == 200
            assert (await c.get(f"/api/scan/{ids[0]}")).status_code == 404
    finally:
        await runner.cleanup()


async def test_cancel_while_queued(app, monkeypatch):
    import fsv.web.app as webapp
    monkeypatch.setattr(webapp, "_scan_sem", asyncio.Semaphore(0))   # no free slot
    async with _client(app) as c:
        r = await c.post("/api/scan", json={"target": "http://127.0.0.1:1", "authorized": True})
        sid = r.json()["scan_id"]
        await asyncio.sleep(0.05)
        active = (await c.get("/api/active")).json()
        assert [a["scan_id"] for a in active] == [sid]
        assert active[0]["latest"]["phase"] == "queued"
        res = (await c.post(f"/api/scan/{sid}/cancel")).json()
        assert res == {"cancelled": True, "queued": True}
        await asyncio.sleep(0.05)
        assert (await c.get("/api/active")).json() == []
        assert webapp.hub.latest(sid)["type"] == "complete"
        assert webapp.hub.latest(sid)["status"] == "cancelled"


async def test_verify_endpoints_issue_challenge_and_record_proof(app, no_http_proof):
    from fsv.core import dnsutil, ownership
    from helpers import FakeDNS
    async with _client(app) as c:
        r = await c.post("/api/verify", json={"host": "https://Shop.Example.com/path"})
        assert r.status_code == 200
        info = r.json()
        assert info["domain"] == "example.com" and info["dns"]["name"] == "_fsv-challenge.example.com"
        assert (await c.post("/api/verify", json={"host": "  "})).status_code == 400

        FakeDNS({}).install()                                        # no proof published yet
        try:
            none = await c.post("/api/verify/check", json={"host": "shop.example.com"})
            assert none.json() == {"verified": False, "method": None}
            FakeDNS({"_fsv-challenge.example.com": {"TXT": [info["dns"]["value"]]}}).install()
            ok = await c.post("/api/verify/check", json={"host": "shop.example.com"})
            assert ok.json() == {"verified": True, "method": "dns"}
        finally:
            dnsutil.set_backend(None)
        listed = (await c.get("/api/verified")).json()
        assert [(v["domain"], v["method"], v["expired"]) for v in listed] == [("example.com", "dns", False)]
        assert (await c.get("/api/info")).json()["verification_required"] is False


async def test_healthz_needs_no_token_but_everything_else_does(app, monkeypatch):
    import fsv.web.app as webapp
    monkeypatch.setattr(webapp, "API_TOKEN", "s3cret")
    async with _client(app) as c:
        h = await c.get("/healthz")
        assert h.status_code == 200 and h.json() == {"ok": True}
        assert (await c.get("/api/info")).status_code == 401              # counts of scans/targets are not public
        assert (await c.get("/api/info", headers={"X-FSV-Token": "s3cret"})).status_code == 200
        assert (await c.get("/api/scans")).status_code == 401
    async with _client(app, host="evil.test") as c:                         # the Host guard still applies to /healthz
        assert (await c.get("/healthz")).status_code == 403


async def test_every_api_route_requires_the_token(app, monkeypatch):
    """Walk the real route table so a route added tomorrow can't ship unprotected."""
    import fsv.web.app as webapp
    from fastapi.routing import APIRoute
    monkeypatch.setattr(webapp, "API_TOKEN", "s3cret")
    checked = []
    async with _client(app) as c:
        for route in app.routes:
            if not isinstance(route, APIRoute) or not route.path.startswith("/api/"):
                continue
            path = route.path.replace("{scan_id}", "x")
            for method in route.methods - {"HEAD", "OPTIONS"}:
                r = await c.request(method, path, json={} if method in ("POST", "PUT", "PATCH") else None)
                assert r.status_code == 401, f"{method} {route.path} answered {r.status_code} without a token"
                checked.append((method, route.path))
    assert len(checked) >= 15 and ("GET", "/api/info") in checked and ("POST", "/api/scan") in checked
    async with _client(app) as c:                                             # and the public ones stay public
        assert (await c.get("/")).status_code == 200 and (await c.get("/healthz")).status_code == 200
