"""DOM XSS / message-handler static analysis: flags real flows, ignores sanitised code and libraries."""
from fsv.core.models import Confidence, ScanConfig, Severity
from fsv.modules import dom_sinks as D
from helpers import HTML, FakeHTTP


def sinks(code):
    return {(k, n): c for k, n, c, _ in D.analyze_script(code, "t")}


def test_direct_source_to_innerhtml_is_firm():
    r = sinks("document.getElementById('x').innerHTML = decodeURIComponent(location.hash.slice(1));")
    assert r[("html", "innerHTML / outerHTML")] == Confidence.FIRM


def test_flow_through_a_variable_is_tentative():
    r = sinks("var q = new URLSearchParams(location.search).get('q'); render(); box.innerHTML = '<b>' + q + '</b>';")
    assert r[("html", "innerHTML / outerHTML")] == Confidence.TENTATIVE


def test_sanitised_or_text_sinks_are_ignored():
    assert sinks("el.innerHTML = DOMPurify.sanitize(location.hash);") == {}
    assert sinks("el.textContent = location.hash;") == {}
    assert sinks("el.innerHTML = encodeURIComponent(location.search);") == {}


def test_constant_html_and_unrelated_location_use_are_ignored():
    assert sinks("el.innerHTML = '<p>Loading…</p>'; var base = location.pathname;") == {}
    assert sinks("location.href = '/login?next=' + location.pathname;") == {}


def test_eval_and_document_write_and_jquery():
    assert ("code", "eval / Function") in sinks("eval(location.hash.substr(1))")
    assert ("html", "document.write") in sinks("document.write('<a href=\"' + document.referrer + '\">back</a>')")
    assert ("html", "jQuery .html()/.append()") in sinks("$('#out').html(location.search)")
    assert ("html", "jQuery selector from the URL") in sinks("$(location.hash).show()")


def test_dom_open_redirect_uses_only_attacker_controlled_sources():
    assert ("redirect", "location / window.open") in sinks("window.location = new URLSearchParams(location.search).get('next');")
    assert ("redirect", "location / window.open") in sinks("location.href = location.hash.slice(1)")


def test_message_handler_without_origin_check():
    out = dict(D.analyze_messages("window.addEventListener('message', function(e){ run(e.data); });"))
    assert "message" in out
    ok = D.analyze_messages("window.addEventListener('message', function(e){ if (e.origin !== 'https://a.example') return; run(e.data); });")
    assert ok == []


def test_message_handler_feeding_a_sink_is_escalated():
    kinds = [k for k, _ in D.analyze_messages("addEventListener('message', e => { box.innerHTML = e.data; })")]
    assert kinds == ["message-sink"]


def test_wildcard_target_origin_and_document_domain():
    kinds = [k for k, _ in D.analyze_messages("parent.postMessage(token, '*'); document.domain = 'example.com';")]
    assert kinds == ["star", "domain"]


async def test_module_reads_inline_and_first_party_scripts_but_not_libraries():
    html = ('<html><script src="/app.js"></script><script src="/js/jquery.min.js"></script>'
            '<script>window.addEventListener("message", function(e){ go(e.data); });</script></html>')
    http = FakeHTTP({
        "https://x.test/": (200, html, HTML),
        "https://x.test/app.js": (200, "document.body.innerHTML = location.hash;", {"Content-Type": "application/javascript"}),
        "https://x.test/js/jquery.min.js": (200, "x.innerHTML = location.hash;", {"Content-Type": "application/javascript"}),
    })
    out = await D.DOMSinksScanner(http, ScanConfig(target="https://x.test")).scan("https://x.test/")
    titles = [f.title for f in out]
    assert "DOM-Based XSS: URL Data Reaches an HTML Sink" in titles
    assert "postMessage Handler Does Not Check the Sender's Origin" in titles
    assert not any("jquery" in f.evidence for f in out)
    assert next(f for f in out if f.title.startswith("DOM-Based XSS")).severity == Severity.HIGH


async def test_each_script_is_analysed_once_across_pages():
    html = '<html><script src="/app.js"></script></html>'
    http = FakeHTTP({"https://x.test/a": (200, html, HTML), "https://x.test/b": (200, html, HTML),
                     "https://x.test/app.js": (200, "el.innerHTML = location.hash;", {})})
    s = D.DOMSinksScanner(http, ScanConfig(target="https://x.test"))
    assert len(await s.scan("https://x.test/a")) == 1
    assert await s.scan("https://x.test/b") == []
