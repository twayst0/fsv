"""
FSV — baselines for CI
──────────────────────
Adopting a scanner on an existing site fails on day one: the first scan reports
forty things and nobody can merge. A baseline records "these are known and
accepted for now" so the pipeline only breaks on what is NEW.

    fsv scan example.com --authorize --write-baseline .fsv-baseline.json
    fsv scan example.com --authorize --baseline .fsv-baseline.json --fail-on high

Findings are matched by fingerprint (module + title + parameter + host), so the
same missing header on a different page is still the same baselined issue.
"""

from __future__ import annotations
import json
from datetime import datetime, timezone
from urllib.parse import urlparse

from fsv.core.models import Finding, ScanResult

VERSION = 1


def make_baseline(result: ScanResult) -> dict:
    return {
        "version": VERSION,
        "target": result.target,
        "host": urlparse(result.target).netloc.lower(),
        "created": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "note": "Findings listed here are known/accepted; FSV only gates on findings NOT listed. "
                "Review this file in code review like any other security exception.",
        "findings": [
            {"fingerprint": f.fingerprint, "title": f.title, "severity": f.severity.value,
             "module": f.module, "reason": ""}
            for f in result.active_findings
        ],
    }


def load_baseline(path: str) -> dict:
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict) or data.get("version") != VERSION or "findings" not in data:
        raise ValueError(f"{path}: not an FSV baseline (version {VERSION}) file")
    return data


def split_new(result: ScanResult, baseline: dict) -> tuple[list[Finding], list[Finding]]:
    """(new findings, baselined findings) among those still counting toward risk."""
    known = {row["fingerprint"] for row in baseline.get("findings", []) if "fingerprint" in row}
    new, old = [], []
    for f in result.active_findings:
        (old if f.fingerprint in known else new).append(f)
    return new, old


def host_mismatch(result: ScanResult, baseline: dict) -> bool:
    return bool(baseline.get("host")) and baseline["host"] != urlparse(result.target).netloc.lower()
