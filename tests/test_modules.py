"""Unit tests for individual scan-module logic that needs no network."""
import pytest
from fsv.core.models import ScanConfig
from fsv.core.scanner import BaseScanner
from fsv.modules.csp_analyzer import parse_csp, CSPAnalyzerScanner
from fsv.modules.cookie_analyzer import _SENSITIVE_NAME


class FakeHTTP:
    """Return a canned Response for every request."""
    def __init__(self, status=200, headers=None, body=""):
        from fsv.core.http_client import Response
        self._r = Response(status=status, headers=headers or {}, body=body,
                           url="https://x.com")
    async def request(self, *a, **k):
        return self._r


def _cfg():
    return ScanConfig(target="https://x.com")


def test_parse_csp():
    d = parse_csp("default-src 'self'; script-src 'self' https://cdn.x; object-src 'none'")
    assert d["default-src"] == ["'self'"]
    assert "https://cdn.x" in d["script-src"]
    assert d["object-src"] == ["'none'"]


@pytest.mark.asyncio
async def test_csp_analyzer_flags_wildcard_script_src():
    http = FakeHTTP(headers={"Content-Security-Policy": "default-src 'self'; script-src *"})
    s = CSPAnalyzerScanner(http, _cfg())
    findings = await s.scan("https://x.com")
    titles = {f.title for f in findings}
    assert any("Allows Any Host" in t for t in titles)


@pytest.mark.asyncio
async def test_csp_analyzer_clean_policy_minimal_findings():
    good = ("default-src 'none'; script-src 'self'; object-src 'none'; "
            "base-uri 'self'; frame-ancestors 'none'; report-to csp")
    http = FakeHTTP(headers={"Content-Security-Policy": good})
    s = CSPAnalyzerScanner(http, _cfg())
    findings = await s.scan("https://x.com")
    assert findings == []


@pytest.mark.parametrize("name,sensitive", [
    ("PHPSESSID", True), ("auth_token", True), ("XSRF-TOKEN", True),
    ("theme", False), ("lang", False), ("sidebar_pref", False),
])
def test_sensitive_cookie_name_matching(name, sensitive):
    assert bool(_SENSITIVE_NAME.search(name)) == sensitive


@pytest.mark.asyncio
async def test_sri_flags_third_party_scripts():
    from fsv.modules.sri_checker import SRIScanner
    html = ('<html><script src="https://cdn.other.com/a.js"></script>'
            '<script src="/local.js"></script></html>')
    http = FakeHTTP(headers={"Content-Type": "text/html"}, body=html)
    s = SRIScanner(http, _cfg())
    findings = await s.scan("https://x.com")
    assert len(findings) == 1
    assert "cdn.other.com" in findings[0].evidence
    assert "/local.js" not in findings[0].evidence
