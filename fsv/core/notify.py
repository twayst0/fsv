"""
FSV — webhook notification when a scan finishes.

    FSV_WEBHOOK_URL            where to POST (Slack / Discord / Teams-style incoming webhook, or your own endpoint)
    FSV_WEBHOOK_MIN_SEVERITY   only notify if a finding at or above this exists (default: high)

The payload carries `text` (Slack) and `content` (Discord) plus an `fsv` object with the machine-readable summary.
It is sent by the engine, so CLI, dashboard, MCP and CI scans all behave the same. Only open findings count, and
evidence is never included — a notification must not become a second copy of a leak. Delivery is best-effort:
a dead webhook can never fail or slow down a scan (10 s cap, every error swallowed and logged at debug).
"""

from __future__ import annotations
import logging
import os
from urllib.parse import urlparse

import aiohttp

from fsv.config import WEBHOOK_MIN_SEVERITY_ENV, WEBHOOK_URL_ENV
from fsv.core.models import SEVERITY_ORDER, ScanResult, ScanStatus, Severity

log = logging.getLogger("fsv.notify")

_TIMEOUT_S = 10
_TOP = 5


def webhook_url() -> str:
    url = os.getenv(WEBHOOK_URL_ENV, "").strip()
    return url if urlparse(url).scheme in ("http", "https") and urlparse(url).netloc else ""


def min_severity() -> Severity:
    try:
        return Severity(os.getenv(WEBHOOK_MIN_SEVERITY_ENV, "high").strip().lower())
    except ValueError:
        return Severity.HIGH


def build_payload(result: ScanResult, threshold: Severity | None = None) -> dict | None:
    """The message for this scan, or None when there is nothing worth interrupting anyone for."""
    if result.status not in (ScanStatus.COMPLETED, ScanStatus.CANCELLED):
        return None
    floor = SEVERITY_ORDER[threshold or min_severity()]
    open_findings = [f for f in result.findings if f.status.counts_toward_risk]
    hits = [f for f in open_findings if SEVERITY_ORDER[f.severity] >= floor]
    if not hits:
        return None
    hits.sort(key=lambda f: -SEVERITY_ORDER[f.severity])
    counts = result.counts()
    host = urlparse(result.target).netloc or result.target
    lines = [f"FSV: {host} — grade {result.grade} ({result.risk_score}/100) · "
             f"{counts.get('critical', 0)} critical, {counts.get('high', 0)} high, {counts.get('medium', 0)} medium"]
    lines += [f"• [{f.severity.value.upper()}] {f.title}" for f in hits[:_TOP]]
    if len(hits) > _TOP:
        lines.append(f"… and {len(hits) - _TOP} more")
    text = "\n".join(lines)
    return {
        "text": text, "content": text,
        "fsv": {
            "scan_id": result.scan_id, "target": result.target, "status": result.status.value,
            "grade": result.grade, "risk_score": result.risk_score, "counts": counts,
            "top": [{"severity": f.severity.value, "title": f.title, "url": f.url, "module": f.module} for f in hits[:_TOP]],
        },
    }


async def notify_scan(result: ScanResult) -> bool:
    """POST the summary if a webhook is configured and the scan found something at/above the threshold."""
    url = webhook_url()
    if not url:
        return False
    try:
        payload = build_payload(result)
        if payload is None:
            return False
        timeout = aiohttp.ClientTimeout(total=_TIMEOUT_S)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=payload) as resp:
                ok = resp.status < 300
                if not ok:
                    log.debug("webhook answered HTTP %s", resp.status)
                return ok
    except Exception as exc:                       # noqa: BLE001 — a notification must never break a scan
        log.debug("webhook failed: %s: %s", type(exc).__name__, exc)
        return False
