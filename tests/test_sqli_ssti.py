"""SQLi precision (new errors only, no 'ora-' noise) and deep parameter discovery for sqli/ssti."""
from fsv.core.models import ScanConfig, ScanProfile
from fsv.modules.sqli_scanner import SQLiScanner, db_error
from fsv.modules.ssti_detection import SSTIScanner
from helpers import HTML, DynamicHTTP, query


def cfg(deep=False):
    return ScanConfig(target="https://x.test", profile=ScanProfile.DEEP if deep else ScanProfile.BALANCED)


def test_oracle_signature_needs_a_real_error_code():
    assert db_error("explore flora-bloom and decora-tions") is None
    assert db_error("error: ora-00933: sql command not properly ended") == "ora-00933"
    assert db_error("you have an error in your sql syntax near") == "you have an error in your sql syntax"


async def test_error_after_injection_is_reported():
    def app(url):
        v = query(url).get("id", "")
        return 200, ("You have an error in your SQL syntax" if "'" in v else "<html>ok</html>"), HTML
    out = await SQLiScanner(DynamicHTTP(app), cfg()).scan("https://x.test/item?id=5")
    assert len(out) == 1 and out[0].parameter == "id"


async def test_page_that_always_prints_a_db_error_is_not_reported():
    always = DynamicHTTP(lambda url: (200, "<html>Docs: SQLSTATE[42000] means syntax error</html>", HTML))
    assert await SQLiScanner(always, cfg()).scan("https://x.test/docs?id=5") == []


async def test_hidden_id_parameter_is_tried_only_when_deep():
    def app(url):
        v = query(url).get("id", "")
        return 200, ("Warning: mysql_num_rows() expects" if "'" in v else "<html>ok</html>"), HTML
    assert await SQLiScanner(DynamicHTTP(app), cfg()).scan("https://x.test/item") == []
    out = await SQLiScanner(DynamicHTTP(app), cfg(deep=True)).scan("https://x.test/item")
    assert [f.parameter for f in out] == ["id"]


async def test_deep_sqli_discovery_runs_once_per_path():
    http = DynamicHTTP(lambda url: (200, "<html>ok</html>", HTML))
    s = SQLiScanner(http, cfg(deep=True))
    await s.scan("https://x.test/a")
    n = len(http.requested)
    await s.scan("https://x.test/a")
    assert len(http.requested) == n                         # nothing to test the second time (no params, discovery done)


async def test_ssti_deep_finds_hidden_reflected_parameter():
    from fsv.modules.ssti_detection import A, B

    def app(url):
        v = query(url).get("name", "")
        if v.startswith("{{") and f"{A}*{B}" in v:
            v = str(A * B)                                   # a Jinja-like engine evaluating the marker
        return 200, f"<html><p>Hello {v}</p></html>", HTML
    assert await SSTIScanner(DynamicHTTP(app), cfg()).scan("https://x.test/hi") == []
    out = await SSTIScanner(DynamicHTTP(app), cfg(deep=True)).scan("https://x.test/hi")
    assert [f.parameter for f in out] == ["name"]


def test_every_ssti_probe_contains_the_syntax_it_claims_to_test():
    """Regression: the Jinja2/Twig probe was sent as {7331*7} (single braces) and never matched."""
    from fsv.modules.ssti_detection import PROBES, A, B
    rendered = [t.replace("A", str(A)).replace("B", str(B)) for t in PROBES]
    assert "{{7331*7}}" in rendered and "${7331*7}" in rendered and "<%= 7331*7 %>" in rendered


async def test_jinja_style_double_brace_injection_is_detected_on_an_existing_parameter():
    from fsv.modules.ssti_detection import A, B

    def app(url):
        v = query(url).get("name", "")
        if v == f"{{{{{A}*{B}}}}}":                          # only the real double-brace syntax is evaluated
            v = str(A * B)
        return 200, f"<html><p>Hello {v}</p></html>", HTML
    out = await SSTIScanner(DynamicHTTP(app), cfg()).scan("https://x.test/hi?name=bob")
    assert len(out) == 1 and out[0].title.startswith("Server-Side Template Injection") and out[0].parameter == "name"


async def test_a_page_that_merely_echoes_the_marker_is_not_ssti():
    out = await SSTIScanner(DynamicHTTP(lambda u: (200, "<html>%s</html>" % query(u).get("name", ""), HTML)), cfg()).scan(
        "https://x.test/hi?name=bob")
    assert out == []
