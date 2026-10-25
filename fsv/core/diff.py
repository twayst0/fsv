"""FSV — Compare two scans (before/after a fix, or week over week)."""

from __future__ import annotations

from fsv.core.models import Finding, ScanResult, SEVERITY_ORDER


def _brief(f: Finding) -> dict:
    return {
        "fingerprint": f.fingerprint,
        "title":       f.title,
        "severity":    f.severity.value,
        "module":      f.module,
        "parameter":   f.parameter,
        "url":         f.url,
        "affected":    len(f.affected_urls),
    }


def compare(baseline: ScanResult, current: ScanResult) -> dict:
    """
    Diff by finding fingerprint (module + title + parameter + host). Only
    findings that still count toward risk are compared, so a finding marked
    false-positive between the scans is not reported as "resolved".
    """
    a = {f.fingerprint: f for f in baseline.active_findings}
    b = {f.fingerprint: f for f in current.active_findings}

    resolved  = [a[k] for k in a if k not in b]
    new       = [b[k] for k in b if k not in a]
    persisted = [b[k] for k in b if k in a]
    changed   = [
        {**_brief(b[k]), "previous_severity": a[k].severity.value}
        for k in b if k in a and a[k].severity != b[k].severity
    ]

    def by_sev(fs: list[Finding]) -> list[dict]:
        return [_brief(f) for f in sorted(fs, key=lambda f: -SEVERITY_ORDER[f.severity])]

    return {
        "baseline": {**_side(baseline)},
        "current":  {**_side(current)},
        "same_host": baseline.target.split("/")[2:3] == current.target.split("/")[2:3],
        "risk_delta": current.risk_score - baseline.risk_score,
        "verdict": _verdict(current.risk_score - baseline.risk_score, len(new), len(resolved)),
        "resolved":  by_sev(resolved),
        "new":       by_sev(new),
        "persisted": by_sev(persisted),
        "severity_changed": changed,
        "counts": {"resolved": len(resolved), "new": len(new), "persisted": len(persisted)},
    }


def _side(r: ScanResult) -> dict:
    return {"scan_id": r.scan_id, "target": r.target, "started_at": r.started_at,
            "grade": r.grade, "risk_score": r.risk_score, "findings": len(r.active_findings)}


def _verdict(delta: int, new: int, resolved: int) -> str:
    if delta < 0 or (delta == 0 and resolved > new):
        return "improved"
    if delta > 0 or new > resolved:
        return "regressed"
    return "unchanged"
