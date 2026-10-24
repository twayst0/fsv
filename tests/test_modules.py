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


# ── every content-validated path accepts its real file and rejects a catch-all page ──

from fsv.modules.path_scanner import ALL_PATHS, _EXTRA_CHECKS

REAL = {
    "/.git/config": "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = x",
    "/.svn/wc.db": "SQLite format 3\x00",
    "/.npmrc": "//registry.npmjs.org/:_authToken=abc",
    "/.docker/config.json": '{"auths": {"r.io": {}}}',
    "/.ssh/id_rsa": "-----BEGIN OPENSSH PRIVATE KEY-----\nabc",
    "/appsettings.json": '{"ConnectionStrings": {"Default": "x"}}',
    "/appsettings.Development.json": '{"Logging": {}}',
    "/application.properties": "spring.datasource.url=jdbc:x\n",
    "/application.yml": "spring:\n  datasource: x\n",
    "/config/database.yml": "production:\n  adapter: mysql2\n  password: x\n",
    "/settings.py": "SECRET_KEY = 'x'\nINSTALLED_APPS = []",
    "/wp-config.php.bak": "<?php\ndefine('DB_PASSWORD','x');",
    "/wp-config.php~": "<?php\ndefine('DB_PASSWORD','x');",
    "/wp-config.php.old": "<?php\ndefine('DB_PASSWORD','x');",
    "/config.php.bak": "<?php\n$x=1;",
    "/.env.bak": "APP_KEY=base64:abc\nDB_PASSWORD=x",
    "/.env.backup": "APP_KEY=base64:abc\nDB_PASSWORD=x",
    "/terraform.tfstate": '{"terraform_version": "1.5", "resources": []}',
    "/terraform.tfvars": 'region = "eu-west-1"\n',
    "/actuator": '{"_links": {"self": {}}}',
    "/actuator/env": '{"activeProfiles": [], "propertySources": []}',
    "/actuator/heapdump": "JAVA PROFILE 1.0.2\x00",
    "/actuator/configprops": '{"contexts": {}}',
    "/actuator/mappings": '{"contexts": {}}',
    "/actuator/httptrace": '{"traces": []}',
    "/metrics": "# HELP http_requests_total x\n# TYPE http_requests_total counter\n",
    "/debug/pprof/": "<html>Types of profiles available:</html>",
    "/debug/vars": '{"cmdline": ["a"], "memstats": {}}',
    "/_profiler/": "<html><title>Symfony Profiler</title></html>",
    "/telescope": "<html><title>Laravel Telescope</title></html>",
    "/storage/logs/laravel.log": "[2026-01-01 10:00:00] production.ERROR: boom",
    "/elmah.axd": "<html>Error Log for / on HOST</html>",
    "/trace.axd": "<html>Application Trace</html>",
    "/phpmyadmin/": "<html>phpMyAdmin 5.2</html>",
    "/pma/": "<html>phpMyAdmin 5.2</html>",
    "/adminer.php": "<html>Adminer 4.8</html>",
    "/_cluster/health": '{"cluster_name": "x", "status": "green"}',
    "/wp-json/wp/v2/users": '[{"id": 1, "slug": "admin"}]',
    "/xmlrpc.php": "XML-RPC server accepts POST requests only.",
    "/wp-content/debug.log": "[24-Oct-2026 10:00:00 UTC] PHP Warning: x",
    "/WEB-INF/web.xml": "<?xml version='1.0'?><web-app></web-app>",
    "/info.php": "<html>phpinfo() PHP Version 8.2</html>",
    "/test.php": "<html>PHP Version 8.2.1</html>",
    "/backup.tar.gz": "\x1f�\x08\x00",
    "/backup.tgz": "\x1f�\x08\x00",
    "/site.zip": "PK\x03\x04abc", "/www.zip": "PK\x03\x04abc", "/web.zip": "PK\x03\x04abc",
    "/public_html.zip": "PK\x03\x04abc",
    "/v2/api-docs": '{"swagger": "2.0"}', "/v3/api-docs": '{"openapi": "3.0.1"}',
    "/swagger-ui.html": "<html><title>Swagger UI</title></html>",
    "/swagger-ui/index.html": "<html><title>Swagger UI</title></html>",
    "/composer.lock": '{"packages": []}',
    "/.gitlab-ci.yml": "stages:\n  - build\n",
    "/Jenkinsfile": "pipeline {\n agent any\n}",
    "/.idea/workspace.xml": "<?xml version='1.0'?><project version=\"4\"></project>",
    "/nginx_status": "Active connections: 3\n",
}
SPA = "<!doctype html><html><head><title>My App</title></head><body><div id=root></div><script src=/a.js></script></body></html>"


def test_every_extra_check_has_a_real_sample():
    assert {c[0] for c in _EXTRA_CHECKS} == set(REAL), set(REAL) ^ {c[0] for c in _EXTRA_CHECKS}


@pytest.mark.parametrize("path", sorted(REAL))
def test_extra_check_accepts_real_content(path):
    assert VALIDATORS[path](REAL[path], "text/plain"), path


@pytest.mark.parametrize("path", sorted(REAL))
def test_extra_check_rejects_spa_catch_all(path):
    assert not VALIDATORS[path](SPA, "text/html"), path


async def test_spa_server_yields_no_path_findings_at_all():
    class SPAServer:
        async def request(self, url, **kw):
            from fsv.core.http_client import Response
            return Response(status=200, headers={"Content-Type": "text/html"}, body=SPA, url=url)
    out = await PathScanner(SPAServer(), _cfg()).scan("https://x.com")
    # only the few unvalidated legacy probes (/admin …) may report, and only as tentative-or-lower
    assert all(f.confidence.value != "certain" for f in out)
    assert not [f for f in out if f.severity.value in ("critical", "high")]


async def test_real_exposure_is_certain_and_masked():
    class Server:
        async def request(self, url, **kw):
            from fsv.core.http_client import Response
            if url.endswith("/actuator/env"):
                return Response(200, {"Content-Type": "application/json"},
                                '{"propertySources":[{"properties":{"db.password":"hunter2"}}],"activeProfiles":[]}', url)
            return Response(404, {}, "", url)
    out = await PathScanner(Server(), _cfg()).scan("https://x.com")
    f = next(x for x in out if "/actuator/env" in x.title)
    assert f.confidence.value == "certain" and f.severity.value == "high"
    assert "hunter2" not in f.evidence and "****" in f.evidence
