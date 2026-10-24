import pytest
from fsv.core.engine import (
    aggregate_findings, sort_findings, same_origin, canonical_url, Crawler,
)
from fsv.core.models import Finding, Severity, Confidence, ScanConfig


def _f(title, url, sev=Severity.LOW, conf=Confidence.FIRM, module="headers", param=None):
    return Finding(title=title, severity=sev, url=url, module=module, description="d",
                   confidence=conf, parameter=param)


def test_aggregate_collapses_same_issue_across_urls():
    fs = [_f("Missing CSP", "https://x.com/a"),
          _f("Missing CSP", "https://x.com/b"),
          _f("Missing CSP", "https://x.com/c")]
    out = aggregate_findings(fs)
    assert len(out) == 1
    assert len(out[0].affected_urls) == 3


def test_aggregate_keeps_most_severe_representative():
    fs = [_f("X", "https://x.com/a", sev=Severity.LOW, conf=Confidence.TENTATIVE),
          _f("X", "https://x.com/b", sev=Severity.HIGH, conf=Confidence.CERTAIN)]
    out = aggregate_findings(fs)
    assert len(out) == 1
    assert out[0].severity == Severity.HIGH
    assert out[0].confidence == Confidence.CERTAIN


def test_different_params_stay_separate():
    fs = [_f("XSS", "https://x.com/s", sev=Severity.HIGH, module="xss", param="q"),
          _f("XSS", "https://x.com/s", sev=Severity.HIGH, module="xss", param="r")]
    assert len(aggregate_findings(fs)) == 2


def test_sort_by_severity_then_confidence():
    fs = [_f("a", "https://x.com/1", sev=Severity.LOW),
          _f("b", "https://x.com/2", sev=Severity.CRITICAL),
          _f("c", "https://x.com/3", sev=Severity.MEDIUM)]
    out = sort_findings(fs)
    assert [f.severity for f in out][:3] == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_same_origin_rejects_lookalike_hosts():
    assert same_origin("https://site.com/a", "site.com")
    assert not same_origin("https://site.com.evil.net/a", "site.com")
    assert not same_origin("https://evil.net/site.com", "site.com")
    assert not same_origin("ftp://site.com/a", "site.com")


def test_canonical_url_drops_fragment_and_trailing_slash():
    assert canonical_url("https://x.com/a/#frag") == "https://x.com/a"
    assert canonical_url("https://x.com/") == "https://x.com/"


def test_crawler_excludes_logout_and_assets_and_globs():
    cfg = ScanConfig(target="https://x.com", exclude_paths=["/admin/*"])
    cr = Crawler(http=None, cfg=cfg)
    assert cr.excluded("https://x.com/logout")
    assert cr.excluded("https://x.com/app.js")
    assert cr.excluded("https://x.com/admin/users")
    assert not cr.excluded("https://x.com/products?id=1")
