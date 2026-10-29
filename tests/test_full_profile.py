"""Full profile: exhaustive extras (boolean SQLi, content discovery, backup copies, extra link kinds), all off in other profiles."""
import re

from bs4 import BeautifulSoup

from fsv.core import engine, reflect as R
from fsv.core.models import Confidence, ScanConfig, ScanProfile, Severity
from fsv.modules import backup_files as B
from fsv.modules import content_discovery as C
from fsv.modules.sqli_scanner import SQLiScanner
from helpers import HTML, DynamicHTTP, FakeHTTP, query


def cfg(profile):
    return ScanConfig(target="https://x.test", profile=ScanProfile(profile))


# ── profile semantics ──
def test_full_is_a_superset_of_deep():
    assert cfg("full").deep and cfg("full").full
    assert cfg("deep").deep and not cfg("deep").full
    assert not cfg("balanced").deep and not cfg("balanced").full


def test_parameter_list_grows_in_full():
    assert len(R.candidate_names([])) < 50 < len(R.candidate_names([], full=True))
    assert "q" not in R.candidate_names(["q"], full=True)


# ── boolean-based SQLi ──
def boolean_app(vulnerable=True, noise=0, reflect=False):
    """?id=…: a page of 3 rows; `AND 1=2` (or '1'='2) empties it when injectable."""
    state = {"n": 0}

    def handler(url):
        v = query(url).get("id", "")
        state["n"] += 1
        rows = 3
        if vulnerable and re.search(r"AND\s*(['\"]?)1\1\s*=\s*(['\"]?)2", v):
            rows = 0
        body = "<html>" + "<tr>row of the table with some product data</tr>" * rows + "<p>footer</p>"
        if noise:
            body += "x" * (state["n"] % (noise + 1))
        if reflect:
            body += f"<!-- you asked for {v} -->"
        return 200, body + "</html>", HTML
    return DynamicHTTP(handler)


async def test_boolean_sqli_is_reported_in_full_only():
    out = await SQLiScanner(boolean_app(), cfg("full")).scan("https://x.test/item?id=5")
    assert len(out) == 1
    f = out[0]
    assert f.title == "SQL Injection (Boolean-Based)" and f.confidence == Confidence.TENTATIVE and f.severity == Severity.HIGH
    assert f.parameter == "id" and f.extra["technique"] == "boolean"
    assert await SQLiScanner(boolean_app(), cfg("deep")).scan("https://x.test/item?id=5") == []
    assert await SQLiScanner(boolean_app(), cfg("balanced")).scan("https://x.test/item?id=5") == []


async def test_boolean_sqli_not_reported_for_a_safe_parameter():
    assert await SQLiScanner(boolean_app(vulnerable=False), cfg("full")).scan("https://x.test/item?id=5") == []


async def test_reflection_of_the_payload_is_not_mistaken_for_injection():
    assert await SQLiScanner(boolean_app(vulnerable=False, reflect=True), cfg("full")).scan("https://x.test/item?id=5") == []


async def test_a_noisy_page_is_not_mistaken_for_injection():
    assert await SQLiScanner(boolean_app(vulnerable=False, noise=30), cfg("full")).scan("https://x.test/item?id=5") == []


async def test_error_based_finding_suppresses_the_boolean_probe_for_that_parameter():
    def handler(url):
        v = query(url).get("id", "")
        return 200, ("You have an error in your SQL syntax" if "'" in v else "<html>ok</html>"), HTML
    out = await SQLiScanner(DynamicHTTP(handler), cfg("full")).scan("https://x.test/item?id=5")
    assert [f.title for f in out] == ["SQL Injection (Error-Based)"]


# ── content discovery ──
class Site(DynamicHTTP):
    """Unknown paths 404; `routes` answer with (status, body)."""
    def __init__(self, routes, catch_all=None):
        def handler(url):
            path = re.sub(r"^https://x\.test", "", url)
            if path in routes:
                return routes[path]
            if catch_all:
                return catch_all
            return 404, "Not Found"
        super().__init__(handler)


async def test_content_discovery_is_a_noop_unless_full():
    http = Site({"/admin": (200, "<html>Admin " + "x" * 100 + "</html>")})
    assert await C.ContentDiscoveryScanner(http, cfg("deep")).scan("https://x.test/") == []
    assert http.requested == []


async def test_unlinked_admin_and_pages_are_reported_in_two_findings():
    http = Site({"/admin": (200, "<html>Dashboard " + "x" * 100 + "</html>"), "/admin/": (200, "<html>Dashboard " + "x" * 100 + "</html>"),
                 "/backup": (401, ""), "/blog": (200, "<html>Blog index " + "y" * 200 + "</html>"), "/staging": (403, "forbidden")})
    out = await C.ContentDiscoveryScanner(http, cfg("full")).scan("https://x.test/")
    titles = [f.title for f in out]
    assert any(t.startswith("Unlinked Administrative or Internal Paths Found") for t in titles)
    assert any(t.startswith("Unlinked Pages and Directories Discovered") for t in titles)
    sens = next(f for f in out if f.title.startswith("Unlinked Administrative"))
    assert "/admin" in sens.evidence and "/backup" in sens.evidence and sens.severity == Severity.LOW
    assert sens.evidence.count("/admin") == 1                         # /admin and /admin/ are one page
    assert "/staging" not in sens.evidence                            # a 403 on a sensitive name is still just forbidden, not "reachable"


async def test_catch_all_servers_produce_nothing():
    page = (200, "<html>app shell " + "z" * 300 + "</html>")
    assert await C.ContentDiscoveryScanner(Site({}, catch_all=page), cfg("full")).scan("https://x.test/") == []
    assert await C.ContentDiscoveryScanner(Site({}, catch_all=(403, "forbidden")), cfg("full")).scan("https://x.test/") == []


def test_wordlist_is_bounded_and_unique():
    paths = C.candidate_paths()
    assert 400 < len(paths) <= C.MAX_PROBES and len(paths) == len(set(paths))
    assert "/admin" in paths and "/phpmyadmin/" in paths and "/staging" in paths


# ── backup copies ──
def test_backup_variants_only_for_scripts_and_config():
    v = B.variants("/shop/config.php")
    assert "/shop/config.php.bak" in v and "/shop/config.php~" in v and "/shop/.config.php.swp" in v and "/shop/config.bak" in v
    assert B.variants("/index.html") == [] and B.variants("/app.js") == [] and B.variants("/logo.png") == []


async def test_php_source_served_as_text_is_reported_and_withheld():
    src = "<?php\n$db_pass = 'Sup3rS3cret!';\n"
    http = FakeHTTP({"https://x.test/config.php.bak": (200, src, {"Content-Type": "text/plain"})})
    out = await B.BackupFilesScanner(http, cfg("full")).scan("https://x.test/config.php")
    assert len(out) == 1 and out[0].severity == Severity.HIGH and out[0].confidence == Confidence.CERTAIN
    assert "Sup3rS3cret" not in out[0].evidence and "withheld" in out[0].evidence


async def test_html_error_pages_and_other_modes_are_ignored():
    html = (200, "<html><body>nice page " + "x" * 50 + "</body></html>", HTML)
    http = FakeHTTP({"https://x.test/a.php.bak": html})
    assert await B.BackupFilesScanner(http, cfg("full")).scan("https://x.test/a.php") == []
    src = FakeHTTP({"https://x.test/a.php.bak": (200, "<?php echo 1;", {"Content-Type": "text/plain"})})
    assert await B.BackupFilesScanner(src, cfg("deep")).scan("https://x.test/a.php") == []
    assert src.requested == []


async def test_vim_swap_file_and_budget():
    http = FakeHTTP({"https://x.test/.login.php.swp": (200, "b0VIM 8.2\x00\x00 rest", {})})
    out = await B.BackupFilesScanner(http, cfg("full")).scan("https://x.test/login.php")
    assert len(out) == 1 and ".swp" in out[0].title
    s = B.BackupFilesScanner(FakeHTTP({}), cfg("full"))
    for i in range(30):
        await s.scan(f"https://x.test/p{i}.php")
    assert s._spent <= B.BUDGET


# ── crawler: more link kinds ──
def _crawler(profile):
    return engine.Crawler(FakeHTTP({}), cfg(profile))


HTML_LINKS = """<html><head>
<link rel="next" href="/page/2"><link rel="canonical" href="/main"><link rel="stylesheet" href="/s.css">
<meta http-equiv="refresh" content="5; url=/moved">
</head><body><div data-href="/spa/route"></div><button onclick="location.href='/clicked'">x</button>
<a href="/normal">n</a><frame src="/frame1"><a data-url="javascript:void(0)"></a></body></html>"""


def test_full_crawler_reads_more_link_kinds_than_plain_anchors():
    soup = BeautifulSoup(HTML_LINKS, "lxml")
    found = {u.replace("https://x.test", "") for u in _crawler("full")._extra_link_kinds(soup, "https://x.test/")}
    assert found == {"/page/2", "/main", "/moved", "/spa/route", "/clicked", "/frame1"}


async def test_plain_scan_does_not_use_the_extra_kinds():
    http = FakeHTTP({"https://x.test/": (200, HTML_LINKS, HTML)})
    links = await engine.Crawler(http, cfg("deep")).links("https://x.test/")
    assert not any(u.endswith(("/page/2", "/clicked", "/spa/route")) for u in links)
    full_links = await engine.Crawler(http, cfg("full")).links("https://x.test/")
    assert any(u.endswith("/clicked") for u in full_links)


def test_full_limits():
    assert engine.Crawler(FakeHTTP({}), cfg("full")).script_cap == 150 and engine.Crawler(FakeHTTP({}), cfg("deep")).script_cap == 40
    assert engine.FULL_MIN_URLS > engine.DEEP_MIN_URLS and engine.FULL_MIN_DEPTH > engine.DEEP_MIN_DEPTH


# ── dashboard: never serve stale JS/CSS ──
async def test_static_assets_and_the_page_are_served_with_no_cache():
    import httpx
    from httpx import ASGITransport
    import fsv.web.app as webapp
    async with httpx.AsyncClient(transport=ASGITransport(app=webapp.app), base_url="http://127.0.0.1:7474") as c:
        for path in ("/static/app.js", "/static/style.css", "/"):
            r = await c.get(path)
            assert r.status_code == 200 and "no-cache" in r.headers.get("cache-control", ""), path
