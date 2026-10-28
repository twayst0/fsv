import json

from fsv.core.content import find_bucket_refs, script_refs, same_site
from fsv.core.models import ScanConfig
from fsv.core.secrets import find_secrets, shannon_entropy
from fsv.modules.cloud_storage import CloudStorageScanner
from fsv.modules.js_analysis import JSAnalysisScanner, _is_internal_host
from fsv.modules.js_libs import JSLibsScanner, parse_version, assess
from helpers import FakeDNS, FakeHTTP

PAGE = "https://www.example.com/"
HTML = {"Content-Type": "text/html"}


def cfg():
    return ScanConfig(target=PAGE)


def page(*script_srcs, inline="", extra=""):
    tags = "".join(f'<script src="{s}"></script>' for s in script_srcs)
    return (200, f"<html><body>{extra}{tags}<script>{inline}</script></body></html>", HTML)


# NOTE: credential-shaped test data is assembled at runtime so no real-looking secret
# literal exists in the repository (and repository secret scanners stay quiet).
STRIPE = "sk_" + "live_" + "A1b2C3d4E5f6G7h8I9j0K1l2"
GOOGLE = "AIza" + "SyA-1234567890abcdefghijklmnopqrstu"         # exactly 35 chars after AIza
DBURL = "postgres://app:" + "Tr0ub4dor" + "@db.corp:5432/x"


# ── secrets ──────────────────────────────────────────────────────────────────

def test_secret_rules_and_masking():
    hits = {h.rule.key: h for h in find_secrets(f"a='{STRIPE}'; b='{GOOGLE}'; c='{DBURL}'")}
    assert {"stripe_secret", "google_api", "db_url"} <= set(hits)
    for h in hits.values():
        assert STRIPE not in h.masked and "Tr0ub4dor" not in h.masked and GOOGLE not in h.masked
    assert hits["stripe_secret"].rule.severity.value == "critical"
    assert hits["google_api"].rule.severity.value == "low"


def test_generic_rule_needs_entropy_and_rejects_placeholders():
    assert find_secrets('{apiKey:"q8Zx2LmN7vB4tYw9RcE1"}')
    for ok_text in ("apiKey: 'YOUR_API_KEY_HERE_1234'", "password: 'enter_your_password_here'",
                    "secret: 'aaaaaaaaaaaaaaaaaaaa'", "token: process.env.TOKEN_VALUE_X",
                    "password: 'correct-horse-battery'"):
        assert find_secrets(ok_text) == [], ok_text
    assert shannon_entropy("aaaa") == 0 and shannon_entropy("abcd") == 2


def test_aws_id_suppressed_when_secret_present():
    secret = "wJalrXUtnFEMI" + "/K7MDENG/bPxRfiCY" + "EXAMPLEKEY"      # 40 chars
    text = f"aws_secret_access_key = '{secret}'; id='" + "AKIA" + "ABCDEFGHIJKLMNOP'"
    keys = [h.rule.key for h in find_secrets(text)]
    assert "aws_secret" in keys and "aws_key_id" not in keys


# ── content helpers ──────────────────────────────────────────────────────────

def test_script_refs_and_same_site():
    urls, inline = script_refs('<script src="/a.js"></script><script src="//cdn.x.net/b.js"></script>'
                               '<script>var x = 1; var y = 2; var z = 3;</script>', "https://www.example.com/p")
    assert urls == ["https://www.example.com/a.js", "https://cdn.x.net/b.js"]
    assert len(inline) == 1
    assert same_site("https://static.example.com/a.js", "https://www.example.com/")
    assert not same_site("https://cdn.x.net/b.js", "https://www.example.com/")


def test_find_bucket_refs():
    text = ("https://assets-prod.s3.amazonaws.com/a.png  https://s3.us-west-2.amazonaws.com/uploads-x/f.js "
            "https://storage.googleapis.com/my-bucket/x https://acct1.blob.core.windows.net/pub/a.css "
            "https://s3.amazonaws.com/")
    got = find_bucket_refs(text)
    assert ("s3", "assets-prod", None) in got and ("s3", "uploads-x", None) in got
    assert ("gcs", "my-bucket", None) in got and ("azure", "acct1", "pub") in got
    assert not any(n in ("s3", "www") for _, n, _ in got)


# ── js_analysis ──────────────────────────────────────────────────────────────

async def test_js_analysis_secret_sourcemap_and_internal_hosts():
    sm = json.dumps({"version": 3, "sources": ["webpack:///src/app.js", "webpack:///node_modules/x/i.js"],
                     "sourcesContent": [f"const DEBUG_KEY='{STRIPE}'; // original comment", "x"]})
    http = FakeHTTP({
        PAGE: page("/static/app.js"),
        "https://www.example.com/static/app.js": (200,
            f"var cfg={{api:'https://api-staging.example.com',db:'http://10.2.3.4:8080'}};var g='{GOOGLE}';\n"
            "//# sourceMappingURL=app.js.map", {}),
        "https://www.example.com/static/app.js.map": (200, sm, {}),
    })
    s = JSAnalysisScanner(http, cfg())
    out = await s.scan(PAGE)
    t = [f.title for f in out]
    assert "Source Map Exposes Original Source Code" in t
    assert any("Google API key" in x for x in t)
    assert any("Stripe live secret key" in x for x in t)          # found INSIDE sourcesContent
    assert "Internal or Non-Production Hosts Referenced in Client Code" in t
    smf = next(f for f in out if f.title.startswith("Source Map"))
    assert smf.severity.value == "medium" and "sourcesContent" in smf.evidence
    assert "node_modules" not in smf.evidence
    assert all(STRIPE not in f.evidence and GOOGLE not in f.evidence for f in out)  # masked


async def test_js_analysis_analyses_each_script_once():
    http = FakeHTTP({PAGE: page("/a.js"), "https://www.example.com/p2": page("/a.js"),
                     "https://www.example.com/a.js": (200, f"var k='{STRIPE}'", {})})
    s = JSAnalysisScanner(http, cfg())
    first = await s.scan(PAGE)
    second = await s.scan("https://www.example.com/p2")
    assert len(first) == 1 and second == []


async def test_js_analysis_ignores_third_party_scripts_and_non_html():
    http = FakeHTTP({PAGE: page("https://cdn.other.net/lib.js"),
                     "https://cdn.other.net/lib.js": (200, f"var k='{STRIPE}'", {}),
                     "https://www.example.com/data": (200, '{"a":1}', {"Content-Type": "application/json"})})
    s = JSAnalysisScanner(http, cfg())
    assert await s.scan(PAGE) == []
    assert await s.scan("https://www.example.com/data") == []


def test_internal_host_classifier():
    d = "example.com"
    assert _is_internal_host("db.corp", d) and _is_internal_host("10.0.0.5", d)
    assert _is_internal_host("api-staging.example.com", d) and _is_internal_host("dev.example.com", d)
    assert not _is_internal_host("api.example.com", d) and not _is_internal_host("cdn.vendor.com", d)
    assert not _is_internal_host("staging.other.com", d)


# ── js_libs ──────────────────────────────────────────────────────────────────

def test_version_compare_and_ranges():
    assert parse_version("3.4.1") == (3, 4, 1) and parse_version("v1.12") == (1, 12)
    assert parse_version("2.0.0-beta.1") == (2, 0, 0)
    assert {i for a in assess("jquery", "3.4.1") for i in a.ids} == {"CVE-2020-11022", "CVE-2020-11023"}
    assert assess("jquery", "3.5.0") == [] and assess("jquery", "3.7.1") == []
    assert any("CVE-2019-11358" in a.ids for a in assess("jquery", "3.3.1"))
    assert any(a.eol for a in assess("angularjs", "1.8.3"))
    assert any(a.eol for a in assess("vue", "2.7.16")) and assess("vue", "3.4.0") == []
    # range edges: 4.0.0 is affected by the bootstrap 4 range, 4.3.1 is fixed
    assert any("CVE-2019-8331" in a.ids for a in assess("bootstrap", "4.0.0"))
    assert not any("CVE-2019-8331" in a.ids for a in assess("bootstrap", "4.3.1"))


async def test_js_libs_reports_third_party_cdn_and_dedupes():
    http = FakeHTTP({
        PAGE: page("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js",
                   "/vendor/angular.min.js", "/vendor/ok.js"),
        "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js": (200, "/*! x */", {}),
        "https://www.example.com/vendor/angular.min.js": (200, "/* AngularJS v1.5.8 (c) Google */", {}),
        "https://www.example.com/vendor/ok.js": (200, "/*! jQuery v3.7.1 */", {}),
    })
    s = JSLibsScanner(http, cfg())
    out = await s.scan(PAGE)
    titles = sorted(f.title for f in out)
    assert titles == ["Vulnerable JavaScript Library: AngularJS 1.5.8",
                      "Vulnerable JavaScript Library: jQuery 3.3.1"]
    jq = next(f for f in out if "jQuery" in f.title)
    assert jq.severity.value == "medium" and "CVE-2019-11358" in jq.evidence
    assert "not that the vulnerable code path is reachable" in jq.description


async def test_js_libs_eol_only_title_and_user_advisories(tmp_path, monkeypatch):
    http = FakeHTTP({PAGE: page("/vue.js"), "https://www.example.com/vue.js": (200, "/*! Vue.js v2.6.10 */", {})})
    out = await JSLibsScanner(http, cfg()).scan(PAGE)
    assert out[0].title == "End-of-Life JavaScript Framework: Vue.js 2.6.10"
    assert out[0].severity.value == "low"


# ── cloud_storage ────────────────────────────────────────────────────────────

S3_LIST = "<?xml version='1.0'?><ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'><Name>pub</Name></ListBucketResult>"
S3_MISSING = "<Error><Code>NoSuchBucket</Code><Message>The specified bucket does not exist</Message></Error>"
S3_DENIED = "<Error><Code>AccessDenied</Code></Error>"


async def test_cloud_storage_public_orphaned_and_script_escalation():
    FakeDNS({"deadacct.blob.core.windows.net": {}}).zone.pop("deadacct.blob.core.windows.net")
    FakeDNS({}).install()           # every azure account name resolves NXDOMAIN
    http = FakeHTTP({
        PAGE: page("https://gone-assets.s3.amazonaws.com/app.js",
                   extra='<img src="https://open-bucket.s3.amazonaws.com/a.png">'
                         '<img src="https://private-bucket.s3.amazonaws.com/b.png">'
                         '<img src="https://deadacct.blob.core.windows.net/pics/c.png">'),
        "https://gone-assets.s3.amazonaws.com/?max-keys=1": (404, S3_MISSING),
        "https://open-bucket.s3.amazonaws.com/?max-keys=1": (200, S3_LIST),
        "https://private-bucket.s3.amazonaws.com/?max-keys=1": (403, S3_DENIED),
    })
    out = await CloudStorageScanner(http, cfg()).scan(PAGE)
    by = {f.extra["bucket"]: f for f in out}
    assert set(by) == {"gone-assets", "open-bucket", "deadacct"}           # private bucket: no finding
    assert by["gone-assets"].severity.value == "critical"                    # used as <script src>
    assert by["gone-assets"].extra["used_as_script"] is True
    assert by["open-bucket"].title.startswith("Publicly Listable") and by["open-bucket"].severity.value == "high"
    assert by["deadacct"].severity.value == "high" and by["deadacct"].extra["used_as_script"] is False
    # only listing requests with max-keys=1 — never an object download
    assert all("max-keys=1" in u or u == PAGE for u in http.requested if "amazonaws" in u)


async def test_cloud_storage_checks_each_bucket_once():
    http = FakeHTTP({PAGE: page(extra='<img src="https://b-one.s3.amazonaws.com/a.png">'),
                     "https://www.example.com/2": page(extra='<img src="https://b-one.s3.amazonaws.com/z.png">'),
                     "https://b-one.s3.amazonaws.com/?max-keys=1": (200, S3_LIST)})
    s = CloudStorageScanner(http, cfg())
    a = await s.scan(PAGE); b = await s.scan("https://www.example.com/2")
    assert len(a) == 1 and b == []
    assert http.requested.count("https://b-one.s3.amazonaws.com/?max-keys=1") == 1


async def test_allow_external_false_drops_external_modules():
    from fsv.core.engine import _select_modules
    c = ScanConfig(target=PAGE, allow_external=False)
    mods = _select_modules(c)
    assert "takeover" not in mods and "cloud_storage" not in mods and "headers" in mods
    assert "takeover" in _select_modules(ScanConfig(target=PAGE))


async def test_js_libs_needs_no_download_when_the_version_is_in_the_url():
    cdn = "https://cdnjs.cloudflare.com/ajax/libs/jquery/3.3.1/jquery.min.js"
    http = FakeHTTP({PAGE: page(cdn)})                          # the CDN file itself is NOT served (404)
    out = await JSLibsScanner(http, cfg()).scan(PAGE)
    assert [f.title for f in out] == ["Vulnerable JavaScript Library: jQuery 3.3.1"]
    assert cdn not in http.requested                            # never contacted the third-party CDN


async def test_js_libs_fetches_only_when_the_url_has_no_version():
    http = FakeHTTP({PAGE: page("/js/lib.js"), "https://www.example.com/js/lib.js": (200, "/*! jQuery v1.12.4 */", {})})
    out = await JSLibsScanner(http, cfg()).scan(PAGE)
    assert out and "jQuery 1.12.4" in out[0].title
    assert "https://www.example.com/js/lib.js" in http.requested
