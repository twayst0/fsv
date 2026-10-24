"""
FSV — SQLite persistence layer (aiosqlite)

Tables
    scans   — one row per scan (findings stored as JSON)
    triage  — per-host triage decisions keyed by finding fingerprint, so a
              false positive marked once stays marked on every later scan
"""

from __future__ import annotations
import json
import os
import sqlite3
from datetime import datetime, timezone
from urllib.parse import urlparse

import aiosqlite

from fsv import config
from fsv.core.models import Finding, FindingStatus, ScanResult, ScanStatus


SCHEMA_VERSION = 2

# columns added after v1 — (name, DDL type/default)
_SCAN_COLUMNS_V2 = [
    ("stats",         "TEXT DEFAULT '{}'"),
    ("profile",       "TEXT DEFAULT 'balanced'"),
    ("modules_run",   "TEXT DEFAULT '[]'"),
    ("module_errors", "TEXT DEFAULT '{}'"),
    ("urls",          "TEXT DEFAULT '[]'"),
    ("tags",          "TEXT DEFAULT '[]'"),
]

_initialized: set[str] = set()


def _db_path() -> str:
    # read at call time so tests / FSV_DB overrides work after import
    return os.getenv("FSV_DB", config.DB_PATH)


def _connect() -> aiosqlite.Connection:
    """Return an aiosqlite connection object (async context manager — do NOT await)."""
    path = _db_path()
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    return aiosqlite.connect(path, timeout=15)


def host_of(target: str) -> str:
    return urlparse(target).netloc.lower()


async def init_db() -> None:
    path = _db_path()
    if path in _initialized:
        return
    async with _connect() as db:
        await db.execute("PRAGMA journal_mode=WAL")
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
        # forward-migrate v1 databases in place
        async with db.execute("PRAGMA table_info(scans)") as cur:
            have = {row[1] for row in await cur.fetchall()}
        for name, ddl in _SCAN_COLUMNS_V2:
            if name not in have:
                try:
                    await db.execute(f"ALTER TABLE scans ADD COLUMN {name} {ddl}")
                except sqlite3.OperationalError as exc:
                    # another coroutine/process migrated first — that's fine
                    if "duplicate column" not in str(exc).lower():
                        raise
        await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_scans_target  ON scans(target)")
        await db.execute("""
            CREATE TABLE IF NOT EXISTS triage (
                host        TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                status      TEXT NOT NULL,
                note        TEXT DEFAULT '',
                updated_at  TEXT NOT NULL,
                PRIMARY KEY (host, fingerprint)
            )
        """)
        await db.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
        await db.commit()
    _initialized.add(path)


async def upsert_scan(result: ScanResult, config_raw: dict | None = None) -> None:
    await init_db()
    async with _connect() as db:
        await db.execute("""
            INSERT INTO scans
                (scan_id, target, status, started_at, finished_at, duration_s,
                 urls_scanned, tech_stack, findings, error, config,
                 stats, profile, modules_run, module_errors, urls, tags)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ON CONFLICT(scan_id) DO UPDATE SET
                status        = excluded.status,
                finished_at   = excluded.finished_at,
                duration_s    = excluded.duration_s,
                urls_scanned  = excluded.urls_scanned,
                tech_stack    = excluded.tech_stack,
                findings      = excluded.findings,
                error         = excluded.error,
                stats         = excluded.stats,
                profile       = excluded.profile,
                modules_run   = excluded.modules_run,
                module_errors = excluded.module_errors,
                urls          = excluded.urls,
                tags          = excluded.tags
        """, (
            result.scan_id,
            result.target,
            result.status.value,
            result.started_at,
            result.finished_at or None,
            result.duration_s,
            result.urls_scanned,
            json.dumps(result.tech_stack),
            json.dumps([f.model_dump(mode="json") for f in result.findings]),
            result.error,
            json.dumps(config_raw or {}),
            json.dumps(result.stats),
            result.profile,
            json.dumps(result.modules_run),
            json.dumps(result.module_errors),
            json.dumps(result.urls),
            json.dumps(result.tags),
        ))
        await db.commit()


async def get_scan(scan_id: str) -> ScanResult | None:
    """Fetch a scan by full id or by an unambiguous prefix (≥ 6 chars)."""
    await init_db()
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)) as cur:
            row = await cur.fetchone()
        if row is None and len(scan_id) >= 6:
            async with db.execute(
                "SELECT * FROM scans WHERE scan_id LIKE ? LIMIT 2", (scan_id + "%",)
            ) as cur:
                rows = await cur.fetchall()
            row = rows[0] if len(rows) == 1 else None
    if row is None:
        return None
    result = _row_to_result(row)
    await apply_triage(result)
    return result


async def get_scan_config(scan_id: str) -> dict | None:
    await init_db()
    async with _connect() as db:
        async with db.execute("SELECT config FROM scans WHERE scan_id = ?", (scan_id,)) as cur:
            row = await cur.fetchone()
    return json.loads(row[0] or "{}") if row else None


async def list_scans(
    limit: int = 50,
    target: str | None = None,
    status: str | None = None,
    offset: int = 0,
) -> list[dict]:
    await init_db()
    where, args = [], []
    if target:
        where.append("target LIKE ?")
        args.append(f"%{target}%")
    if status:
        where.append("status = ?")
        args.append(status)
    sql = "SELECT * FROM scans"
    if where:
        sql += " WHERE " + " AND ".join(where)
    sql += " ORDER BY started_at DESC LIMIT ? OFFSET ?"
    args += [max(1, min(limit, 500)), max(0, offset)]

    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(sql, args) as cur:
            rows = await cur.fetchall()
        triage = await _all_triage(db)
    out = []
    for row in rows:
        r = _row_to_result(row)
        _overlay(r, triage.get(host_of(r.target), {}))
        out.append(r.summary_dict())
    return out


async def previous_scan(target: str, before: str) -> ScanResult | None:
    """Latest finished scan of the same host that started before `before`."""
    await init_db()
    async with _connect() as db:
        db.row_factory = aiosqlite.Row
        async with db.execute(
            "SELECT * FROM scans WHERE target LIKE ? AND started_at < ? "
            "AND status IN ('completed','cancelled') ORDER BY started_at DESC LIMIT 20",
            (f"%{host_of(target)}%", before),
        ) as cur:
            rows = await cur.fetchall()
    for row in rows:
        r = _row_to_result(row)
        if host_of(r.target) == host_of(target):
            await apply_triage(r)
            return r
    return None


async def delete_scan(scan_id: str) -> bool:
    await init_db()
    async with _connect() as db:
        cur = await db.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
        await db.commit()
        return cur.rowcount > 0


async def prune_scans(keep: int) -> int:
    """Delete all but the newest `keep` scans. Returns rows removed."""
    await init_db()
    async with _connect() as db:
        cur = await db.execute(
            "DELETE FROM scans WHERE scan_id NOT IN "
            "(SELECT scan_id FROM scans ORDER BY started_at DESC LIMIT ?)", (max(0, keep),))
        await db.commit()
        return cur.rowcount


async def mark_interrupted() -> int:
    """
    Scans left 'running' by a crashed/killed process can never finish —
    flag them so the UI doesn't show them as live forever.
    """
    await init_db()
    async with _connect() as db:
        cur = await db.execute(
            "UPDATE scans SET status='failed', error='interrupted (process exited)' "
            "WHERE status IN ('running','pending')")
        await db.commit()
        return cur.rowcount


# ── triage ────────────────────────────────────────────────────────────────────

async def set_triage(host: str, fingerprint: str, status: FindingStatus, note: str = "") -> None:
    await init_db()
    async with _connect() as db:
        if status == FindingStatus.OPEN and not note:
            await db.execute("DELETE FROM triage WHERE host=? AND fingerprint=?",
                             (host, fingerprint))
        else:
            await db.execute("""
                INSERT INTO triage (host, fingerprint, status, note, updated_at)
                VALUES (?,?,?,?,?)
                ON CONFLICT(host, fingerprint) DO UPDATE SET
                    status=excluded.status, note=excluded.note, updated_at=excluded.updated_at
            """, (host, fingerprint, status.value, note,
                  datetime.now(timezone.utc).isoformat()))
        await db.commit()


async def get_triage(host: str) -> dict[str, tuple[str, str]]:
    await init_db()
    async with _connect() as db:
        async with db.execute(
            "SELECT fingerprint, status, note FROM triage WHERE host=?", (host,)
        ) as cur:
            return {fp: (st, note) for fp, st, note in await cur.fetchall()}


async def _all_triage(db) -> dict[str, dict[str, tuple[str, str]]]:
    out: dict[str, dict[str, tuple[str, str]]] = {}
    async with db.execute("SELECT host, fingerprint, status, note FROM triage") as cur:
        for host, fp, st, note in await cur.fetchall():
            out.setdefault(host, {})[fp] = (st, note)
    return out


async def apply_triage(result: ScanResult) -> ScanResult:
    """Overlay stored triage decisions onto a result's findings (in place)."""
    _overlay(result, await get_triage(host_of(result.target)))
    return result


def _overlay(result: ScanResult, triage: dict[str, tuple[str, str]]) -> None:
    for f in result.findings:
        hit = triage.get(f.fingerprint)
        if hit:
            try:
                f.status = FindingStatus(hit[0])
            except ValueError:
                pass
            f.triage_note = hit[1] or ""


# ── stats ─────────────────────────────────────────────────────────────────────

async def overview() -> dict:
    """Aggregate numbers for the dashboard header."""
    await init_db()
    async with _connect() as db:
        async with db.execute(
            "SELECT COUNT(*), COUNT(DISTINCT target), COALESCE(SUM(urls_scanned),0) FROM scans"
        ) as cur:
            total, targets, urls = await cur.fetchone()
        async with db.execute("SELECT COUNT(*) FROM triage") as cur:
            (triaged,) = await cur.fetchone()
    return {"scans": total, "targets": targets, "urls_scanned": urls, "triaged": triaged}


async def target_history(target: str, limit: int = 20) -> list[dict]:
    """Risk-score trend for one host, oldest first."""
    rows = await list_scans(limit=200, target=host_of(target) or target)
    rows = [r for r in rows if host_of(r["target"]) == (host_of(target) or target)]
    rows = rows[:limit]
    return [
        {"scan_id": r["scan_id"], "started_at": r["started_at"], "risk_score": r["risk_score"],
         "grade": r["grade"], "counts": r["counts"], "status": r["status"]}
        for r in reversed(rows)
    ]


# ── row mapping ───────────────────────────────────────────────────────────────

def _col(row, name: str, default):
    try:
        v = row[name]
    except (IndexError, KeyError):
        return default
    return default if v is None else v


def _row_to_result(row) -> ScanResult:
    findings = []
    for raw in json.loads(row["findings"] or "[]"):
        try:
            findings.append(Finding(**raw))
        except Exception:
            continue   # one malformed legacy record shouldn't hide the scan
    return ScanResult(
        scan_id       = row["scan_id"],
        target        = row["target"],
        status        = ScanStatus(row["status"]),
        started_at    = row["started_at"],
        finished_at   = row["finished_at"] or "",
        duration_s    = row["duration_s"] or 0.0,
        urls_scanned  = row["urls_scanned"] or 0,
        tech_stack    = json.loads(row["tech_stack"] or "[]"),
        findings      = findings,
        error         = row["error"],
        stats         = json.loads(_col(row, "stats", "{}")),
        profile       = _col(row, "profile", "balanced"),
        modules_run   = json.loads(_col(row, "modules_run", "[]")),
        module_errors = json.loads(_col(row, "module_errors", "{}")),
        urls          = json.loads(_col(row, "urls", "[]")),
        tags          = json.loads(_col(row, "tags", "[]")),
    )
