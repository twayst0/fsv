import pytest

from fsv.core import fixes, report
from fsv.core.models import Confidence, Finding, ScanResult, ScanStatus, Severity

T = "https://www.example.com"


def F(title, module, sev=Severity.MEDIUM, url=T + "/", **extra):
    return Finding(title=title, severity=sev, url=url, module=module, description="d", extra=extra)


def scan(*findings):
    return ScanResult(scan_id="abcdef123456", target=T, status=ScanStatus.COMPLETED,
                      started_at="2026-01-01T00:00:00+00:00", findings=list(findings))


FINDINGS = [
    F("Missing Security Header: Strict-Transport-Security", "headers", Severity.HIGH),
    F("Missing Security Header: X-Content-Type-Options", "headers"),
    F("Missing Security Header: Content-Security-Policy", "headers", Severity.HIGH),
    F("Server Version Disclosure", "headers", Severity.LOW),
    F("Technology Stack Disclosure via X-Powered-By", "headers", Severity.LOW),
    F("Cookie Missing HttpOnly Flag: `SID`", "cookies", cookie="SID", session_like=True, flag="httponly"),
    F("Sensitive File Exposed: `/.env`", "paths", Severity.CRITICAL, url=T + "/.env"),
    F("Sensitive File Exposed: `/actuator/`", "paths", Severity.HIGH, url=T + "/actuator/"),
    F("Source Map Exposes Original Source Code", "js_analysis"),
    F("Directory Listing Enabled: `/uploads/`", "dir_listing"),
    F("Missing DMARC Record", "dns_security", url="dns://_dmarc.example.com"),
    F("SPF References a Non-Existent Domain: old.net", "dns_security", Severity.HIGH,
      url="dns://example.com", dangling_domain="old.net"),
    F("No CAA Record", "dns_security", Severity.LOW, url="dns://example.com"),
    F("Dangling DNS Record (Takeover Risk): old.example.com", "takeover", Severity.HIGH,
      url="dns://old.example.com", host="old.example.com", kind="dangling"),
]


def test_nginx_pack_contains_only_what_was_found():
    out = fixes.generate(scan(*FINDINGS), "nginx")
    assert 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' in out
    assert 'add_header X-Content-Type-Options "nosniff" always;' in out
    assert "Content-Security-Policy-Report-Only" in out and "add_header Content-Security-Policy " not in out
    assert "server_tokens off;" in out and "proxy_hide_header X-Powered-By;" in out
    assert "proxy_cookie_flags ~ httponly;" in out
    assert "location = /.env { return 404; }" in out and "location ^~ /actuator/ { return 404; }" in out
    assert "autoindex off;" in out and "\\.map$" in out
    assert "X-Frame-Options" not in out and "Referrer-Policy" not in out      # not found → not emitted


def test_apache_caddy_express_packs():
    s = scan(*FINDINGS)
    ap = fixes.generate(s, "apache")
    assert 'Header always set X-Content-Type-Options "nosniff"' in ap and "ServerTokens Prod" in ap
    assert "Options -Indexes" in ap and "Require all denied" in ap
    cd = fixes.generate(s, "caddy")
    assert "header {" in cd and "-X-Powered-By" in cd and "respond @exposed 404" in cd
    ex = fixes.generate(s, "express")
    assert "helmet" in ex and "httpOnly: true" in ex and "reportOnly: true" in ex


def test_dns_pack():
    out = fixes.generate(scan(*FINDINGS), "dns")
    assert '_dmarc.example.com.  IN TXT  "v=DMARC1; p=quarantine' in out
    assert "delete  include:old.net" in out
    assert "IN CAA  0 issue" in out
    assert "remove the DNS record for old.example.com" in out


def test_clean_scan_and_unknown_server():
    assert "Nothing in this scan" in fixes.generate(scan(), "nginx")
    with pytest.raises(ValueError):
        fixes.generate(scan(), "iis")


def test_triaged_findings_do_not_generate_fixes():
    from fsv.core.models import FindingStatus
    f = F("Missing Security Header: X-Content-Type-Options", "headers")
    f.status = FindingStatus.FALSE_POSITIVE
    assert "Nothing in this scan" in fixes.generate(scan(f), "nginx")


def test_render_supports_fix_formats():
    for srv in fixes.SERVERS:
        content, media = report.render(scan(*FINDINGS), f"fix-{srv}")
        assert content.startswith("# FSV fix pack") and media.startswith("text/markdown")
    assert "fix-nginx" in report.FORMATS
    with pytest.raises(ValueError):
        report.render(scan(), "fix-iis")
