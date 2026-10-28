"""XSS module: context-aware reflection, precision (no noise from JSON / escaped output), deep parameter discovery."""
import html

from fsv.core.models import Confidence, ScanConfig, ScanProfile, Severity
from fsv.modules.xss_scanner import XSSScanner
from helpers import HTML, DynamicHTTP, query


def cfg(deep=False):
    return ScanConfig(target="https://x.test", profile=ScanProfile.DEEP if deep else ScanProfile.BALANCED)


def app(render, param="q", ctype=HTML):
    """A page that renders `render(value)` for ?param=value."""
    return DynamicHTTP(lambda url: (200, render(query(url).get(param, "")), ctype))


async def run(http, url="https://x.test/s?q=a", deep=False):
    return await XSSScanner(http, cfg(deep)).scan(url)


async def test_reflected_in_html_text_is_confirmed():
    out = await run(app(lambda v: f"<html><body><p>Results for {v}</p></body></html>"))
    assert len(out) == 1
    f = out[0]
    assert (f.title, f.severity, f.confidence, f.parameter) == ("Reflected Cross-Site Scripting (XSS)", Severity.HIGH, Confidence.FIRM, "q")
    assert f.extra["context"] == "html" and "onload" in f.extra["payload"]


async def test_escaped_output_is_not_reported():
    assert await run(app(lambda v: f"<html><p>Results for {html.escape(v)}</p></html>")) == []


async def test_json_echo_is_not_reported():
    http = app(lambda v: '{"echo": "%s"}' % v, ctype={"Content-Type": "application/json"})
    assert await run(http) == []


async def test_comment_reflection_is_not_reported():
    assert await run(app(lambda v: f"<html><!-- q={v} --><p>hi</p></html>")) == []


async def test_double_quoted_attribute_breakout():
    out = await run(app(lambda v: f'<html><input name="q" value="{v}"></html>'))
    assert [f.extra["context"] for f in out] == ["attr-dq"]
    assert out[0].confidence == Confidence.FIRM


async def test_attribute_with_encoded_quotes_is_safe_even_though_angle_brackets_pass():
    enc = lambda v: v.replace('"', "&quot;")
    assert await run(app(lambda v: f'<html><input value="{enc(v)}"></html>')) == []


async def test_js_string_context():
    out = await run(app(lambda v: f'<html><script>var q = "{v}";</script></html>'))
    assert [f.extra["context"] for f in out] == ["js-string-dq"]


async def test_link_target_is_a_separate_medium_finding():
    out = await run(app(lambda v: f'<html><a href="{html.escape(v)}">back</a></html>'))
    assert len(out) == 1 and out[0].title.startswith("Reflected Input Controls a Link Target")
    assert out[0].severity == Severity.MEDIUM


async def test_filtered_payload_is_reported_tentatively():
    """Dangerous characters pass but a naive filter strips the concrete payload → a hint, not a verdict."""
    strip = lambda v: v.replace("svg", "").replace("onload", "").replace("onerror", "").replace("script", "")
    out = await run(app(lambda v: f"<html><p>{strip(v)}</p></html>"))
    assert len(out) == 1 and out[0].confidence == Confidence.TENTATIVE and out[0].severity == Severity.MEDIUM


async def test_hidden_parameter_is_found_only_when_deep():
    # the page has no query string in any link, but reads ?search=
    render = lambda v: f"<html><p>Searched: {v}</p></html>"
    http = lambda: app(render, param="search")
    assert await run(http(), url="https://x.test/s", deep=False) == []
    out = await run(http(), url="https://x.test/s", deep=True)
    assert len(out) == 1 and out[0].parameter == "search" and out[0].extra["hidden_parameter"] is True
    assert "deep scan" in out[0].description


async def test_deep_tries_more_payload_shapes_than_balanced():
    # a filter that drops anything containing "<svg": the first payload shape is blocked, the attribute-style one is not
    def render(v):
        return f'<html><input value="{"" if "<svg" in v else v}"></html>'
    balanced = await run(app(render), deep=False)
    assert len(balanced) == 1 and balanced[0].confidence == Confidence.TENTATIVE
    deep_out = await run(app(render), deep=True)
    assert deep_out[0].confidence == Confidence.FIRM and "autofocus" in deep_out[0].extra["payload"]


async def test_no_parameters_means_no_requests_unless_deep():
    http = app(lambda v: "<html></html>")
    assert await run(http, url="https://x.test/plain") == []
    assert http.requested == []


async def test_page_without_html_body_is_skipped():
    http = DynamicHTTP(lambda url: (404, ""))
    assert await run(http) == []
