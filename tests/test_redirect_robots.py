"""HTTP→HTTPS upgrade path, HSTS reach, robots.txt and sitemap review."""
from fsv.core.http_client import Response
from fsv.core.models import ScanConfig, ScanProfile, Severity
from fsv.modules.https_redirect import HTTPSRedirectScanner
from fsv.modules.robots_review import RobotsReviewScanner, parse_robots, sensitive_entries
from helpers import HTML, FakeHTTP


class Routes:
    """Responds per exact URL; honours allow_redirects by simply returning the raw response."""
    def __init__(self, routes):
        self.routes, self.requested = routes, []

    async def request(self, url, method="GET", **kw):
        self.requested.append(url)
        hit = self.routes.get(url)
        if hit is None:
            return Response(status=-1, headers={}, body="", url=url, error="connection refused") if self.routes.get("__refuse__") else Response(404, {}, "", url)
        status, body, *rest = hit
        return Response(status=status, headers=(rest[0] if rest else {}), body=body, url=url)


def titles(fs):
    return [f.title for f in fs]


def cfg(**kw):
    return ScanConfig(target="https://x.test", **kw)


async def redirect(routes, url="https://x.test/"):
    return await HTTPSRedirectScanner(Routes(routes), cfg()).scan(url)


async def test_http_that_serves_content_is_reported():
    out = await redirect({"http://x.test/": (200, "<html>site</html>", HTML), "https://x.test/": (200, "ok", {})})
    assert titles(out) == ["HTTP Version of the Site Does Not Redirect to HTTPS"] and out[0].severity == Severity.MEDIUM


async def test_clean_301_to_https_is_silent():
    assert await redirect({"http://x.test/": (301, "", {"Location": "https://x.test/"}),
                           "https://x.test/": (200, "ok", {"Strict-Transport-Security": "max-age=63072000; includeSubDomains"})}) == []


async def test_hop_through_another_host_over_http():
    out = await redirect({"http://x.test/": (301, "", {"Location": "http://www.x.test/"}),
                          "http://www.x.test/": (301, "", {"Location": "https://www.x.test/"}), "https://x.test/": (200, "ok", {})})
    assert titles(out) == ["HTTP Redirect Passes Through Another Host Before HTTPS"]
    assert "http://www.x.test/" in out[0].evidence


async def test_chain_that_never_reaches_https():
    out = await redirect({"http://x.test/": (301, "", {"Location": "http://x.test/home"}), "http://x.test/home": (200, "page", HTML),
                          "https://x.test/": (200, "ok", {})})
    assert titles(out) == ["HTTP Redirect Chain Never Reaches HTTPS"]


async def test_temporary_redirect_is_info():
    out = await redirect({"http://x.test/": (302, "", {"Location": "https://x.test/"}), "https://x.test/": (200, "ok", {})})
    assert [(f.title, f.severity) for f in out] == [("HTTP→HTTPS Redirect Is Temporary", Severity.INFO)]


async def test_closed_port_80_is_fine_and_hsts_without_subdomains_is_noted():
    out = await redirect({"__refuse__": True, "https://x.test/": (200, "ok", {"Strict-Transport-Security": "max-age=31536000"})})
    assert titles(out) == ["HSTS Does Not Cover Subdomains"]


async def test_custom_port_and_plain_http_targets_are_skipped():
    assert await redirect({}, url="https://x.test:8443/") == []
    assert await redirect({}, url="http://x.test/") == []


# ── robots / sitemap ──
ROBOTS = "User-agent: *\nDisallow: /admin/\nDisallow: /backup/db\nDisallow: /wp-admin/\nDisallow: /blog/\nSitemap: https://x.test/sitemap.xml\n"


def test_parse_and_filter():
    dis, sm = parse_robots(ROBOTS)
    assert dis == ["/admin/", "/backup/db", "/wp-admin/", "/blog/"] and sm == ["https://x.test/sitemap.xml"]
    assert sensitive_entries(dis) == ["/admin/", "/backup/db"]                 # /wp-admin/ is a harmless default, /blog/ isn't sensitive


async def test_robots_hint_is_info_and_only_reads_robots_when_not_deep():
    http = FakeHTTP({"https://x.test/robots.txt": (200, ROBOTS, {"Content-Type": "text/plain"})})
    out = await RobotsReviewScanner(http, cfg()).scan("https://x.test/")
    assert [(f.title, f.severity) for f in out] == [("robots.txt Points Out Sensitive Paths", Severity.INFO)]
    assert "https://x.test/admin/" not in http.requested


async def test_deep_checks_whether_listed_paths_really_answer_and_skips_login_pages():
    http = FakeHTTP({"https://x.test/robots.txt": (200, ROBOTS, {}),
                     "https://x.test/admin/": (200, "<html><form><input type=password></form></html>" + "x" * 300, HTML),
                     "https://x.test/backup/db": (200, "<html>" + "dump " * 100 + "</html>", HTML)})
    out = await RobotsReviewScanner(http, cfg(profile=ScanProfile.DEEP)).scan("https://x.test/")
    assert [f.title for f in out if f.title.startswith("Path Listed")] == ["Path Listed in robots.txt Is Open: `/backup/db`"]


async def test_deep_does_not_probe_when_robots_are_respected():
    http = FakeHTTP({"https://x.test/robots.txt": (200, ROBOTS, {})})
    await RobotsReviewScanner(http, cfg(profile=ScanProfile.DEEP, respect_robots=True)).scan("https://x.test/")
    assert "https://x.test/admin/" not in http.requested


async def test_sitemap_with_staging_hosts():
    sm = "<urlset><url><loc>https://x.test/a</loc></url><url><loc>https://staging.x.test/b</loc></url></urlset>"
    http = FakeHTTP({"https://x.test/robots.txt": (200, "User-agent: *\nSitemap: https://x.test/sitemap.xml\n", {}),
                     "https://x.test/sitemap.xml": (200, sm, {"Content-Type": "application/xml"})})
    out = await RobotsReviewScanner(http, cfg()).scan("https://x.test/")
    assert titles(out) == ["Sitemap Lists Non-Production Hosts"] and "staging.x.test" in out[0].evidence


async def test_html_answer_to_robots_txt_is_a_catch_all_not_a_robots_file():
    http = FakeHTTP({"https://x.test/robots.txt": (200, "<html><body>app</body></html>", HTML)})
    assert await RobotsReviewScanner(http, cfg()).scan("https://x.test/") == []
