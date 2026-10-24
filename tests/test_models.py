import pytest
from fsv.core.models import (
    Finding, Severity, Confidence, FindingStatus, ScanConfig, ScanResult,
    ScanStatus, normalize_target, finding_fingerprint,
)


def test_normalize_target_adds_scheme():
    assert normalize_target("example.com") == "https://example.com"
    assert normalize_target("http://example.com/x") == "http://example.com/x"
    assert normalize_target("HTTPS://Example.COM/A") == "https://example.com/A"


@pytest.mark.parametrize("bad", ["", "ftp://x", "https://", "not a url", "javascript:alert(1)"])
def test_normalize_target_rejects(bad):
    with pytest.raises(ValueError):
        normalize_target(bad)


def test_config_clamps_limits():
    c = ScanConfig(target="x.com", max_urls=99999, threads=999, depth=-4, timeout=0)
    assert c.max_urls == 2000
    assert c.threads == 64
    assert c.depth == 0
    assert c.timeout == 1


def test_fingerprint_is_host_scoped_not_path():
    a = finding_fingerprint("headers", "Missing CSP", None, "https://a.com/x")
    b = finding_fingerprint("headers", "Missing CSP", None, "https://a.com/y")
    c = finding_fingerprint("headers", "Missing CSP", None, "https://other.com/x")
    assert a == b          # same host, different path → same issue
    assert a != c          # different host → different issue


def _f(sev, conf=Confidence.FIRM, status=FindingStatus.OPEN, cwe=None, title="t"):
    return Finding(title=title, severity=sev, url="https://x.com", module="m",
                   description="d", confidence=conf, status=status, cwe=cwe)


def test_owasp_autofilled_from_cwe():
    assert _f(Severity.HIGH, cwe="CWE-79").owasp == "A03"
    assert _f(Severity.HIGH, cwe="CWE-319").owasp == "A02"
    assert _f(Severity.HIGH, cwe=None).owasp is None


def test_risk_score_diminishing_and_triage():
    r = ScanResult(scan_id="s", target="https://x.com", status=ScanStatus.COMPLETED,
                   started_at="2020")
    r.findings = [_f(Severity.CRITICAL, title=f"c{i}") for i in range(3)]
    score_all = r.risk_score
    assert score_all > 40 and r.grade == "F"
    # mark two as false positive → score drops, criticals no longer counted
    r.findings[0].status = FindingStatus.FALSE_POSITIVE
    r.findings[1].status = FindingStatus.FIXED
    assert r.critical_count == 1
    assert r.risk_score < score_all
    assert r.suppressed_count == 2


def test_tentative_counts_half():
    r = ScanResult(scan_id="s", target="https://x.com", status=ScanStatus.COMPLETED, started_at="2020")
    r.findings = [_f(Severity.HIGH, conf=Confidence.TENTATIVE)]
    firm = ScanResult(scan_id="s2", target="https://x.com", status=ScanStatus.COMPLETED, started_at="2020")
    firm.findings = [_f(Severity.HIGH, conf=Confidence.CERTAIN)]
    assert r.risk_score < firm.risk_score
