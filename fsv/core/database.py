"""FSV — SQLite persistence layer (aiosqlite)"""

from __future__ import annotations
import json
import os
import aiosqlite
from fsv.config import DB_PATH
from fsv.core.models import ScanResult, ScanStatus


def _connect() -> aiosqlite.Connection:
    """Return an aiosqlite connection object (async context manager — do NOT await)."""
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    return aiosqlite.connect(DB_PATH)


async def init_db() -> None:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        await db.execute("""
            CREATE TABLE IF NOT EXISTS scans (
                scan_id     TEXT PRIMARY KEY,
                target      TEXT NOT NULL,
                status      TEXT NOT NULL DEFAULT 'pending',
                started_at  TEXT NOT NULL,
                finished_at TEXT,
                duration_s  REAL DEFAULT 0,
                urls_scanned INTEGER DEFAULT 0,
                tech_stack  TEXT DEFAULT '[]',
                findings    TEXT DEFAULT '[]',
                error       TEXT,
                config      TEXT DEFAULT '{}'
            )
        """)
        await db.commit()


async def upsert_scan(result: ScanResult, config_raw: dict | None = None) -> None:
    async with _connect() as db:
        await db.execute("""
            INSERT INTO scans
                (scan_id, target, status, started_at, finished_at, duration_s,
                 urls_scanned, tech_stack, findings, error, config)
            VALUES (?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status       = excluded.status,
                finished_at  = excluded.finished_at,
                duration_s   = excluded.duration_s,
                urls_scanned = excluded.urls_scanned,
                tech_stack   = excluded.tech_stack,
                findings     = excluded.findings,
                error        = excluded.error
        """, (
            result.scan_id,
            result.target,
            result.status.value,
            result.started_at,
            result.finished_at or None,
            result.duration_s,
            result.urls_scanned,
            json.dumps(result.tech_stack),
            json.dumps([f.model_dump() for f in result.findings]),
            result.error,
            json.dumps(config_raw or {}),
        ))
        await db.commit()


async def get_scan(scan_id: str) -> ScanResult | None:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
        ) as cur:
            row = await cur.fetchone()
    if row is None:
        return None
    return _row_to_result(row)


async def list_scans(limit: int = 50) -> list[dict]:
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT scan_id, target, status, started_at, finished_at, "
            "duration_s, urls_scanned, tech_stack, findings, error "
            "FROM scans ORDER BY started_at DESC LIMIT ?",
            (limit,),
        ) as cur:
            rows = await cur.fetchall()
    results = []
    for row in rows:
        r = _row_to_result(row)
        results.append(r.summary_dict())
    return results


async def delete_scan(scan_id: str) -> bool:
    async with _connect() as db:
        cur = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.commit()
        return cur.rowcount > 0


def _row_to_result(row) -> ScanResult:
    from fsv.core.models import Finding
    findings_raw = json.loads(row["findings"] or "[]")
    findings = [Finding(**f) for f in findings_raw]
    return ScanResult(
        scan_id      = row["scan_id"],
        target       = row["target"],
        status       = ScanStatus(row["status"]),
        started_at   = row["started_at"],
        finished_at  = row["finished_at"] or "",
        duration_s   = row["duration_s"] or 0.0,
        urls_scanned = row["urls_scanned"] or 0,
        tech_stack   = json.loads(row["tech_stack"] or "[]"),
        findings     = findings,
        error        = row["error"],
    )
