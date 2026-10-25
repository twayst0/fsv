"""Regressions found by scanning real applications (OWASP PyGoat / Django) — each was a false
positive or a miss on a real site."""
from fsv.core import discovery
from fsv.core.engine import Crawler
from fsv.core.http_client import Response
from fsv.core.models import ScanConfig, Severity
from fsv.modules.cookie_analyzer import CookieScanner
from fsv.modules.csrf_checker import CSRFScanner
from fsv.modules.debug_mode import DebugModeScanner
from fsv.modules.headers import HeadersScanner
from fsv.modules.host_header import HostHeaderScanner
from fsv.modules.http_methods import HTTPMethodsScanner
from fsv.modules.open_redirect import OpenRedirectScanner, browser_destination
from fsv.modules.path_scanner import PathScanner
from helpers import FakeHTTP

CFG = ScanConfig(target="http://app.test")

DJANGO_404 = """<html><title>Page not found at /x</title><body>
<p>Using the URLconf defined in <code>app.urls</code>, Django tried these URL patterns, in this order:</p>
<ol><li> admin/ </li><li> accounts/ login/ [name='account_login'] </li><li> xss [name='xss'] </li>
<li> ^static/(?P&lt;path&gt;.*)$ </li><li> labs/start/ [name='start'] </li></ol>
<p>You&#x27;re seeing this error because you have <code>DEBUG = True</code> in your Django settings file.</p>
</body></html>"""


class Routes(FakeHTTP):
    """FakeHTTP with per-method routes, Set-Cookie lists and a fallback for unknown paths."""
    def __init__(self, routes=None, fallback=None, methods=None):
        super().__init__(routes)
        self.fallback = fallback
        self.methods = methods or {}

    async def request(self, url, method="GET", **kw):
        self.requested.append((method, url))
        hit = self.methods.get((method, url)) or self.routes.get(url)
        if hit is None and self.fallback and method == "GET":
            hit = self.fallback
        if hit is None:
            return Response(status=404, headers={}, body="", url=url)
        status, body, *rest = hit
        headers = rest[0] if rest else {}
        cookies = rest[1] if len(rest) > 1 else []
        return Response(status=status, headers=headers, body=body, url=url, set_cookies=cookies)


# ── cookies ───────────────────────────────────────────────────────────────────

async def test_csrf_cookie_is_not_a_session_cookie():
    http = Routes({"http://app.test/": (200, "<html></html>", {"Content-Type": "text/html"},
                                        ["csrftoken=abc; Path=/; SameSite=Lax",
                                         "XSRF-TOKEN=def; Path=/; SameSite=Lax"])})
    out = await CookieScanner(http, CFG).scan("http://app.test/")
    titles = [f.title for f in out]
    assert not any("HttpOnly" in t for t in titles), "anti-CSRF cookies must stay script-readable"
    secure = [f for f in out if "Secure" in f.title]
    assert secure and all(f.severity == Severity.LOW and not f.extra["session_like"] for f in secure)


async def test_real_session_cookie_still_flagged():
    http = Routes({"http://app.test/": (200, "", {}, ["sessionid=abc; Path=/"])})
    out = await CookieScanner(http, CFG).scan("http://app.test/")
    assert any(f.title == "Cookie Missing HttpOnly Flag: `sessionid`" and f.severity == Severity.HIGH for f in out)


# ── headers ───────────────────────────────────────────────────────────────────

async def test_hsts_not_demanded_over_plain_http_and_no_xxp_noise():
    http = Routes({"http://app.test/": (200, "<html></html>", {"Content-Type": "text/html"})})
    titles = [f.title for f in await HeadersScanner(http, CFG).scan("http://app.test/")]
    assert "Missing Security Header: Strict-Transport-Security" not in titles
    assert not any("X-XSS-Protection" in t or "X-Frame-Options" in t for t in titles)
    assert "Missing Security Header: Content-Security-Policy" in titles


async def test_document_headers_not_demanded_on_json():
    http = Routes({"https://app.test/api": (200, "{}", {"Content-Type": "application/json"})})
    titles = [f.title for f in await HeadersScanner(http, CFG).scan("https://app.test/api")]
    assert "Missing Security Header: Content-Security-Policy" not in titles
    assert "Missing Security Header: Strict-Transport-Security" in titles


async def test_csp_wildcard_detected():
    http = Routes({"https://app.test/": (200, "<p>", {"Content-Type": "text/html",
                                                       "Content-Security-Policy": "default-src *",
                                                       "Strict-Transport-Security": "max-age=63072000"})})
    titles = [f.title for f in await HeadersScanner(http, CFG).scan("https://app.test/")]
    assert "CSP Wildcard Source Detected" in titles


# ── methods ───────────────────────────────────────────────────────────────────

async def test_allow_header_alone_is_not_a_dangerous_method():
    http = Routes(methods={("OPTIONS", "http://app.test/"): (200, "", {"Allow": "GET, POST, PUT, DELETE, OPTIONS"})})
    out = await HTTPMethodsScanner(http, CFG).scan("http://app.test/")
    assert [f.severity for f in out] == [Severity.INFO]
    assert "PUT" in out[0].description


async def test_trace_reported_only_when_it_echoes():
    echo = (200, "TRACE / HTTP/1.1\r\nX-FSV-Probe: fsv-trace-probe\r\n", {"Content-Type": "message/http"})
    http = Routes(methods={("TRACE", "http://app.test/"): echo})
    out = await HTTPMethodsScanner(http, CFG).scan("http://app.test/")
    assert [f.title for f in out] == ["Dangerous HTTP Method Enabled: TRACE"]


# ── redirects, host header, csrf ─────────────────────────────────────────────

def test_browser_destination_handles_backslash_and_same_site_paths():
    assert browser_destination("http://app.test/a", "/\\evil.example.com").startswith("http://evil.example.com")
    assert browser_destination("http://app.test/a", "/login/?next=/%5Cevil.example.com").startswith("http://app.test/")


async def test_redirect_back_to_own_login_is_not_open_redirect():
    def loc(u):
        return (302, "", {"Location": "/admin/login/?next=" + u.split("next=")[1]})
    base = "http://app.test/admin/login?next=%2Fadmin%2F"
    routes = {}
    for p in ("https%3A%2F%2Fevil.example.com", "%2F%2Fevil.example.com", "%2F%5Cevil.example.com"):
        u = f"http://app.test/admin/login?next={p}"
        routes[u] = loc(u)
    out = await OpenRedirectScanner(Routes(routes), CFG).scan(base)
    assert out == []


async def test_real_open_redirect_found_without_requesting_evil_host():
    u = "http://app.test/go?url=https%3A%2F%2Fevil.example.com"
    http = Routes({u: (302, "", {"Location": "https://evil.example.com"})})
    out = await OpenRedirectScanner(http, CFG).scan("http://app.test/go?url=%2Fhome")
    assert [f.title for f in out] == ["Open Redirect"]
    assert not any("evil.example.com" in url.split("?")[0] for _, url in http.requested)


async def test_rejected_host_header_is_not_injection():
    http = Routes({"http://app.test/": (400, "Invalid HTTP_HOST header: 'fsv-injected.example.net'")})
    assert await HostHeaderScanner(http, CFG).scan("http://app.test/") == []


async def test_form_posting_to_another_site_needs_no_csrf_token():
    body = '<form method="post" action="https://dpaste.com/"><input name="content"></form>'
    http = Routes({"http://app.test/err": (200, body, {"Content-Type": "text/html"})})
    assert await CSRFScanner(http, CFG).scan("http://app.test/err") == []


# ── debug mode & paths ───────────────────────────────────────────────────────

async def test_django_debug_mode_detected_from_404():
    http = Routes(fallback=None)
    http.fallback = None

    async def request(url, method="GET", **kw):
        if "fsv-debug-probe" in url:
            return Response(status=404, headers={"Content-Type": "text/html"}, body=DJANGO_404, url=url)
        return Response(status=404, headers={}, body="", url=url)
    http.request = request
    out = await DebugModeScanner(http, CFG).scan("http://app.test/")
    assert [f.title for f in out] == ["Django Debug Mode Enabled"]
    assert "/admin/" in out[0].extra["routes"]


async def test_plain_404_is_not_debug_mode():
    http = Routes(fallback=(404, "<h1>Not Found</h1>"))
    assert await DebugModeScanner(http, CFG).scan("http://app.test/") == []


async def test_admin_aliases_merge_and_robots_is_not_sensitive():
    page = "<html><title>Log in | Django site admin</title>" + "x" * 200 + "</html>"

    class AdminHTTP(Routes):
        async def request(self, url, method="GET", **kw):
            if url.endswith(("/admin", "/admin/")):
                return Response(status=200, headers={"Content-Type": "text/html"}, body=page,
                                url="http://app.test/admin/login/?next=/admin/")
            if url.endswith("/robots.txt"):
                return Response(status=200, headers={}, body="User-agent: *\nDisallow: /x\n", url=url)
            return Response(status=404, headers={}, body="", url=url)
    out = await PathScanner(AdminHTTP(), CFG).scan("http://app.test/")
    titles = [f.title for f in out]
    assert titles.count("Admin Interface Publicly Reachable") == 1
    assert not any("robots" in t for t in titles)


# ── discovery ────────────────────────────────────────────────────────────────

def test_discovery_parsers():
    assert discovery.django_debug_routes(DJANGO_404) == ["/admin/", "/accounts/login/", "/xss"]
    js = "fetch('/api/items');fetch(`/labs/start/${x}/`);a='/challenge/list-labs/';b='/static/app.js';c='//cdn.x/y'"
    assert discovery.js_routes(js) == ["/api/items", "/challenge/list-labs/"]
    paths, maps = discovery.robots_entries("Disallow: /private/\nDisallow: /*.pdf$\nSitemap: https://a.test/s.xml")
    assert paths == ["/private/"] and maps == ["https://a.test/s.xml"]
    pages, nested = discovery.sitemap_locs('<urlset><url><loc>https://a.test/p</loc></url></urlset>')
    assert pages == ["https://a.test/p"] and nested == []
    assert discovery.is_action_path("/cart/clear") and not discovery.is_action_path("/settings")


async def test_crawler_seeds_from_sitemap_scripts_and_debug_page():
    home = '<html><script src="/static/app.js"></script><a href="/about">a</a></html>'

    class Site(Routes):
        async def request(self, url, method="GET", **kw):
            self.requested.append(url)
            html = {"Content-Type": "text/html"}
            table = {
                "http://app.test": (200, home, html),
                "http://app.test/static/app.js": (200, "fetch('/api/me');fetch('/api/delete-all')", {}),
                "http://app.test/sitemap.xml": (200, "<urlset><url><loc>http://app.test/hidden</loc></url>"
                                                     "<url><loc>https://other.test/x</loc></url></urlset>", {}),
            }
            if "fsv-discovery-" in url:
                return Response(status=404, headers=html, body=DJANGO_404, url=url)
            st, body, h = table.get(url, (200, "<html></html>", html))
            return Response(status=st, headers=h, body=body, url=url)

    http = Site()
    cr = Crawler(http, ScanConfig(target="http://app.test", max_urls=50, depth=2))
    urls = await cr.run()
    for want in ("http://app.test/hidden", "http://app.test/xss", "http://app.test/api/me", "http://app.test/about"):
        assert want in urls, want
    assert not any("delete-all" in u or "other.test" in u or "labs/start" in u for u in urls)
    assert cr.discovered["sitemap"] == 1 and cr.discovered["javascript"] == 1


# ── supply chain ─────────────────────────────────────────────────────────────

from fsv.modules.supply_chain import SupplyChainScanner  # noqa: E402
from helpers import FakeDNS  # noqa: E402


async def test_polyfill_io_and_expired_script_domain_found():
    FakeDNS({"cdnjs.cloudflare.com": {"A": ["1.1.1.1"]}, "cloudflare.com": {"NS": ["ns.cloudflare.com"], "SOA": ["x"]},
             "app.test": {"A": ["10.0.0.1"]}}).install()
    try:
        page = ('<html><script src="https://cdn.polyfill.io/v3/polyfill.min.js"></script>'
                '<script src="https://cdnjs.cloudflare.com/ajax/libs/x.js"></script>'
                '<script src="https://widgets.expired-vendor.com/w.js"></script>'
                '<link rel="stylesheet" href="https://fonts.gone-vendor.net/f.css">'
                '<script src="/static/own.js"></script></html>')
        http = Routes({"https://app.test/": (200, page, {"Content-Type": "text/html"})})
        out = await SupplyChainScanner(http, CFG).scan("https://app.test/")
        got = {(f.extra["domain"], f.severity) for f in out}
        assert got == {("polyfill.io", Severity.CRITICAL), ("expired-vendor.com", Severity.CRITICAL),
                       ("gone-vendor.net", Severity.HIGH)}
    finally:
        from fsv.core import dnsutil
        dnsutil.set_backend(None)


async def test_resolver_errors_never_claim_a_domain_is_unregistered():
    from fsv.core import dnsutil
    from fsv.core.dnsutil import Answer
    dnsutil.set_backend(lambda name, rtype, timeout: Answer("error"))
    try:
        page = '<script src="https://widgets.some-vendor.com/w.js"></script>'
        http = Routes({"https://app.test/": (200, page, {"Content-Type": "text/html"})})
        assert await SupplyChainScanner(http, CFG).scan("https://app.test/") == []
    finally:
        dnsutil.set_backend(None)


async def test_resolver_that_denies_everything_claims_nothing():
    FakeDNS({}, internet=False).install()     # every name NXDOMAIN — a filtered/sandboxed resolver
    try:
        page = '<script src="https://code.jquery.com/jquery.js"></script>'
        http = Routes({"https://app.test/": (200, page, {"Content-Type": "text/html"})})
        assert await SupplyChainScanner(http, CFG).scan("https://app.test/") == []
    finally:
        from fsv.core import dnsutil
        dnsutil.set_backend(None)


# ── performance: hostile bodies must not stall a module ─────────────────────

async def test_info_disclosure_is_linear_on_adversarial_bodies():
    import time
    from fsv.modules.info_disclosure import InfoDisclosureScanner
    for body in ("A" * 2_000_000, "a@" * 1_000_000, ("x" * 60 + "@") * 30_000):
        http = Routes({"https://app.test/": (200, body, {"Content-Type": "text/html"})})
        t = time.monotonic()
        await InfoDisclosureScanner(http, CFG).scan("https://app.test/")
        assert time.monotonic() - t < 2, "regex backtracking on a large body"


async def test_email_detection_still_works():
    from fsv.modules.info_disclosure import InfoDisclosureScanner
    http = Routes({"https://app.test/": (200, "<p>write to security@example.co.uk</p>", {"Content-Type": "text/html"})})
    out = await InfoDisclosureScanner(http, CFG).scan("https://app.test/")
    assert any("security@example.co.uk" in f.evidence for f in out)
