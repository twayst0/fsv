import pytest
from aiohttp import web

from fsv.core.netsafety import (
    registrable_domain, is_blocked_address, check_target, BlockedTarget,
    make_connector, make_trace_config,
)


@pytest.mark.parametrize("host,expected", [
    ("shop.example.co.uk", "example.co.uk"),
    ("www.example.com", "example.com"),
    ("a.b.example.com.tr", "example.com.tr"),
    ("foo.github.io", "foo.github.io"),       # private-suffix aware
    ("example.org", "example.org"),
    ("localhost", None), ("10.0.0.1", None), ("", None),
])
def test_registrable_domain(host, expected):
    assert registrable_domain(host) == expected


@pytest.mark.parametrize("addr,allow_private,blocked", [
    ("169.254.169.254", True, True),     # cloud metadata — never allowed
    ("169.254.169.254", False, True),
    ("fe80::1", True, True),
    ("::ffff:169.254.169.254", True, True),   # v4-mapped bypass attempt
    ("100.100.100.200", True, True),
    ("127.0.0.1", True, False),          # local dev is allowed by default…
    ("127.0.0.1", False, True),          # …and blocked in shared-service mode
    ("10.1.2.3", False, True),
    ("192.168.1.5", False, True),
    ("93.184.216.34", False, False),
    ("not-an-ip", True, True),
])
def test_blocked_address(addr, allow_private, blocked):
    assert is_blocked_address(addr, allow_private=allow_private) is blocked


async def test_check_target():
    await check_target("http://127.0.0.1:80/", allow_private=True)
    with pytest.raises(BlockedTarget):
        await check_target("http://127.0.0.1/", allow_private=False)
    with pytest.raises(BlockedTarget):
        await check_target("http://169.254.169.254/latest/meta-data/", allow_private=True)


async def test_redirect_to_metadata_is_refused():
    """A public-looking target must not be able to bounce FSV to the metadata IP."""
    import aiohttp
    async def handler(request):
        raise web.HTTPFound("http://169.254.169.254/latest/meta-data/")
    app = web.Application(); app.router.add_route("*", "/{t:.*}", handler)
    runner = web.AppRunner(app); await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0); await site.start()
    port = list(runner.addresses)[0][1]
    try:
        async with aiohttp.ClientSession(
            connector=make_connector(10, allow_private=True),
            trace_configs=[make_trace_config(True)],
        ) as s:
            with pytest.raises(BlockedTarget):
                await s.get(f"http://127.0.0.1:{port}/", allow_redirects=True)
    finally:
        await runner.cleanup()


async def test_scan_of_metadata_ip_fails_cleanly():
    from fsv.core.models import ScanConfig
    from fsv.core import engine
    r = await engine.run_scan(ScanConfig(target="http://169.254.169.254/", crawl=False,
                                         max_urls=1, modules=["headers"]))
    assert r.status.value == "failed"
    assert "will not scan" in (r.error or "")
