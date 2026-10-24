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
    assert len(r.json()["modules"]) == 26


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
