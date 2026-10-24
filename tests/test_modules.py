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


# ── path scanner: content validators + redaction ─────────────────────────────

from fsv.modules.path_scanner import VALIDATORS, redact_preview, PathScanner


@pytest.mark.parametrize("path,body,ctype,ok", [
    ("/.git/HEAD", "ref: refs/heads/main\n", "text/plain", True),
    ("/.git/HEAD", "<html>catch-all page</html>", "text/html", False),
    ("/.env", "DB_HOST=x\nDB_PASS=y", "text/plain", True),
    ("/.env", "<!doctype html><div>APP=1</div>", "text/html", False),
    ("/backup.sql", "CREATE TABLE users (id int);", "application/sql", True),
    ("/backup.sql", "error: you have an error in your sql syntax", "text/html", False),
    ("/swagger.json", '{"openapi":"3.1.0"}', "application/json", True),
    ("/swagger.json", '<html>docs</html>', "text/html", False),
    ("/id_rsa", "-----BEGIN OPENSSH PRIVATE KEY-----\nabc", "text/plain", True),
])
def test_path_validators(path, body, ctype, ok):
    assert VALIDATORS[path](body, ctype) is ok


def test_redaction_masks_values_keeps_keys():
    out = redact_preview("/.env", "DB_USER=admin\nDB_PASS=hunter2\n# comment")
    assert "hunter2" not in out and "admin" not in out
    assert "DB_PASS=****" in out and "# comment" in out
    assert "PRIVATE KEY" in redact_preview("/id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE")
    assert "MIIE" not in redact_preview("/id_rsa", "-----BEGIN RSA PRIVATE KEY-----\nMIIE")


async def test_catch_all_server_does_not_report_git_head():
    class CatchAll:
        async def request(self, *a, **k):
            from fsv.core.http_client import Response
            return Response(status=200, headers={"Content-Type": "text/html"},
                            body="<html><body>Welcome to our shop</body></html>" * 3)
    s = PathScanner(CatchAll(), _cfg())
    findings = await s.scan("https://x.com")
    assert not any(".git" in f.title or ".env" in f.title for f in findings)


def test_mask_secret():
    from fsv.core.scanner import mask_secret
    assert "IOSFODNN7EXAMP" not in mask_secret("AKIAIOSFODNN7EXAMPLE")
    m = mask_secret("password = 'hunter22'")
    assert m.startswith("password = '") and "hunter22" not in m
