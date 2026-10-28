"""Reflection analysis: classify where an input lands and whether it can break out. Pure functions, no network."""
import html

import pytest

from fsv.core import reflect as R

PROBE = R.probe_for("q")
T1, T2 = R.tokens_for("q")


def page(template: str, encode=lambda s: s) -> str:
    """What an app would send back: `template` with the probe (optionally encoded) dropped in at {}."""
    return template.replace("{}", encode(PROBE))


def kinds(body):
    return [R.exploit_kind(r) for r in R.find_reflections(body, "q")]


# ── contexts ──
def test_html_text_with_raw_angle_bracket_is_exploitable():
    assert kinds(page("<html><body><p>You searched for {}</p></body></html>")) == ["html"]


def test_html_text_escaped_is_safe():
    body = page("<p>You searched for {}</p>", html.escape)
    assert kinds(body) == [None]


def test_double_quoted_attribute_needs_the_double_quote():
    raw = page('<input type="text" value="{}">')
    assert kinds(raw) == ["attr-dq"]
    only_quote_escaped = page('<input value="{}">', lambda s: s.replace('"', "&quot;"))
    assert kinds(only_quote_escaped) == [None]                  # < and > are raw but irrelevant inside the quotes


def test_single_quoted_attribute():
    assert kinds(page("<a title='{}'>x</a>")) == ["attr-sq"]
    assert kinds(page("<a title='{}'>x</a>", lambda s: s.replace("'", "&#39;"))) == [None]


def test_unquoted_attribute_is_always_breakable():
    assert kinds(page("<div class={} id=x>")) == ["attr-unquoted"]


def test_url_attribute_start_allows_javascript_scheme_even_when_quotes_are_escaped():
    body = page('<a href="{}">go</a>', html.escape)
    r = R.find_reflections(body, "q")[0]
    assert r.attr == "href" and r.at_value_start
    assert R.exploit_kind(r) == "url"


def test_url_attribute_with_a_prefix_is_not_javascript_scheme():
    body = page('<a href="/search?x={}">go</a>', html.escape)
    assert kinds(body) == [None]


def test_event_handler_attribute_is_already_script():
    body = page('<button onclick="go(\'{}\')">x</button>', html.escape)
    assert kinds(body) == ["js-attr"]


def test_script_string_double_quote():
    body = page('<script>var q = "{}";</script>')
    assert kinds(body) == ["js-string-dq"]


def test_script_string_escaped_quote_but_raw_lt_still_closes_the_script():
    body = page('<script>var q = "{}";</script>', lambda s: s.replace('"', '\\"').replace("'", "\\'"))
    assert kinds(body) == ["script-close"]


def test_script_string_fully_escaped_is_safe():
    enc = lambda s: s.replace('"', '\\"').replace("'", "\\'").replace("<", "\\u003c").replace(">", "\\u003e")
    assert kinds(page('<script>var q = "{}";</script>', enc)) == [None]


def test_script_code_context():
    assert kinds(page("<script>var q = {};</script>")) == ["js-code"]


def test_inside_comment_is_inert():
    assert kinds(page("<div><!-- debug: {} --></div>")) == [None]


def test_textarea_and_title_are_rcdata():
    assert kinds(page("<textarea>{}</textarea>")) == ["html"]
    assert kinds(page("<title>{}</title>", html.escape)) == [None]


def test_after_a_closed_script_block_we_are_back_in_text():
    body = page("<script>var a = 'x';</script><p>{}</p>")
    assert [r.context for r in R.find_reflections(body, "q")] == ["text"]


def test_gt_inside_a_quoted_attribute_does_not_end_the_tag():
    body = page('<a title="1 > 0" href="/x?y={}">z</a>', html.escape)
    r = R.find_reflections(body, "q")[0]
    assert (r.context, r.attr) == ("attr", "href")


def test_js_comment_and_string_lexing():
    body = page("<script>// it's fine\nvar a = '{}';</script>")
    assert [r.context for r in R.find_reflections(body, "q")] == ["script-string"]


def test_multiple_reflections_are_all_reported():
    body = page('<title>{}</title><p>{}</p>', html.escape).replace(PROBE, PROBE, 1)
    # title escaped (safe), second one escaped too → both safe
    assert kinds(body) == [None, None]
    mixed = page("<title>{}</title>", html.escape) + page("<p>{}</p>")
    assert kinds(mixed) == [None, "html"]


def test_non_reflection_returns_nothing():
    assert R.find_reflections("<p>nothing here</p>", "q") == []


# ── payloads ──
def test_payloads_one_normally_all_when_deep():
    assert len(R.payloads_for("attr-dq", deep=False)) == 1
    assert len(R.payloads_for("attr-dq", deep=True)) >= 2
    assert R.payloads_for("nonsense", deep=True) == []


@pytest.mark.parametrize("kind", ["html", "attr-dq", "attr-sq", "attr-unquoted", "attr-new", "url", "js-code",
                                  "js-string-dq", "js-string-sq", "script-close"])
def test_every_exploit_kind_has_a_payload(kind):
    assert R.payloads_for(kind, deep=False)


# ── tokens & discovery ──
def test_tokens_are_deterministic_and_distinct_per_name():
    assert R.tokens_for("q") == R.tokens_for("q")
    assert R.tokens_for("q") != R.tokens_for("s")
    assert R.tokens_for("q")[0].isalnum()


def test_candidate_names_skip_existing_and_reflected_names_are_found():
    names = R.candidate_names(["Q", "page"])
    assert "q" not in names and "page" not in names and "search" in names
    body = f"<p>{R.canary_for('search')}</p><p>{R.canary_for('lang')}</p>"
    assert R.reflected_names(body, names) == ["search", "lang"] or set(R.reflected_names(body, names)) == {"search", "lang"}
