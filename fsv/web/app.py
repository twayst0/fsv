"""
FSV Web Server (FastAPI)
────────────────────────
Serves the dashboard and a JSON/WebSocket API.

Hardening over the first version:
  • scan IDs are pre-allocated, so a client can open the WebSocket before the
    first progress event — no lost-event race
  • a bounded number of concurrent scans (FSV_MAX_SCANS)
  • optional shared-secret token (FSV_TOKEN) on every /api and /ws call
  • input validation surfaced as 400s instead of 500s
  • multi-format report download (md/json/html/sarif/csv)
  • triage, diff and target-trend endpoints
"""

from __future__ import annotations
import asyncio
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from fsv import __version__
from fsv.config import WEB_HOST, WEB_PORT, MAX_CONCURRENT_SCANS, API_TOKEN
from fsv.core.models import ScanConfig, ScanProfile, FindingStatus, normalize_target
from fsv.core import engine, database as db, registry
from fsv.core import report as report_mod
from fsv.core.diff import compare

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="FSV", version=__version__)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

_scan_sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)


# ── auth ────────────────────────────────────────────────────────────────────

def _check_token(request: Request) -> None:
    if not API_TOKEN:
        return
    sent = request.headers.get("X-FSV-Token") or request.query_params.get("token")
    if sent != API_TOKEN:
        raise HTTPException(401, "Invalid or missing API token.")


# ── request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:   str
    modules:  list[str] = []
    crawl:    bool      = True
    max_urls: int       = 50
    depth:    int       = 2
    timeout:  int       = 10
    threads:  int       = 10
    rate_per_sec: float = 20.0
    profile:  str       = "balanced"
    exclude_paths: list[str] = []
    tags:     list[str] = []
    respect_robots: bool = False
    authorized: bool    = False   # user must confirm authorization


class TriageRequest(BaseModel):
    finding: str = Field(..., description="finding id or fingerprint")
    status:  str
    note:    str = ""


# ── websocket progress hub ──────────────────────────────────────────────────

class ProgressHub:
    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue]] = {}
        self._last: dict[str, dict] = {}   # replay the latest event to late subscribers

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.setdefault(scan_id, []).append(q)
        if scan_id in self._last:
            q.put_nowait(self._last[scan_id])
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        if scan_id in self._queues and q in self._queues[scan_id]:
            self._queues[scan_id].remove(q)
            if not self._queues[scan_id]:
                self._queues.pop(scan_id, None)

    def publish(self, scan_id: str, payload: dict) -> None:
        if payload.get("type") == "complete":
            self._last[scan_id] = payload
        for q in list(self._queues.get(scan_id, [])):
            q.put_nowait(payload)


hub = ProgressHub()
_bg_tasks: set = set()


# ── lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    await db.init_db()
    await db.mark_interrupted()   # flush stale 'running' rows from a prior crash


# ── pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/info")
async def api_info() -> dict:
    return {
        "name": "FSV",
        "version": __version__,
        "modules": registry.describe(),
        "profiles": ["passive", "balanced", "aggressive"],
        "report_formats": list(report_mod.FORMATS),
        "auth_required": bool(API_TOKEN),
        "max_concurrent_scans": MAX_CONCURRENT_SCANS,
        "overview": await db.overview(),
    }


# ── scans ─────────────────────────────────────────────────────────────────────

@app.post("/api/scan")
async def api_scan(req: ScanRequest, request: Request) -> JSONResponse:
    _check_token(request)
    if not req.authorized:
        raise HTTPException(403, "Authorization required. Confirm you own or are "
                            "explicitly authorized to test this target.")
    try:
        target = normalize_target(req.target)
    except ValueError as exc:
        raise HTTPException(400, f"Invalid target: {exc}")

    try:
        prof = ScanProfile(req.profile)
    except ValueError:
        prof = ScanProfile.BALANCED

    try:
        config = ScanConfig(
            target=target, modules=req.modules, crawl=req.crawl, max_urls=req.max_urls,
            depth=req.depth, timeout=req.timeout, threads=req.threads,
            rate_per_sec=req.rate_per_sec, profile=prof, exclude_paths=req.exclude_paths,
            tags=req.tags, respect_robots=req.respect_robots,
        )
    except Exception as exc:
        raise HTTPException(400, f"Invalid scan configuration: {exc}")

    if _scan_sem.locked() and len(_bg_tasks) >= MAX_CONCURRENT_SCANS:
        raise HTTPException(429, f"Too many scans running (max {MAX_CONCURRENT_SCANS}). "
                            "Try again shortly.")

    scan_id = engine.new_scan_id()

    def _cb(p) -> None:
        hub.publish(scan_id, {
            "type": "progress", "phase": p.phase, "pct": p.pct,
            "current": p.current, "total": p.total, "message": p.message,
            "findings": p.findings,
        })

    async def _run() -> None:
        async with _scan_sem:
            result = await engine.run_scan(config, progress_cb=_cb, scan_id=scan_id)
        hub.publish(scan_id, {"type": "complete", "scan_id": result.scan_id,
                              "summary": result.summary_dict()})

    task = asyncio.get_event_loop().create_task(_run())
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return JSONResponse({"scan_id": scan_id, "status": "running"})


@app.post("/api/scan/{scan_id}/cancel")
async def api_cancel_scan(scan_id: str, request: Request) -> JSONResponse:
    _check_token(request)
    return JSONResponse({"cancelled": engine.cancel_scan(scan_id)})


@app.get("/api/scan/{scan_id}")
async def api_get_scan(scan_id: str, request: Request) -> JSONResponse:
    _check_token(request)
    result = engine.get_active_scan(scan_id) or await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    if engine.get_active_scan(scan_id) is not None:
        await db.apply_triage(result)
    return JSONResponse({
        **result.summary_dict(),
        "urls": result.urls,
        "findings": [f.model_dump(mode="json") for f in result.findings],
    })


@app.get("/api/scans")
async def api_list_scans(request: Request, limit: int = 50, target: str | None = None,
                         status: str | None = None) -> JSONResponse:
    _check_token(request)
    return JSONResponse(await db.list_scans(limit=limit, target=target, status=status))


@app.delete("/api/scan/{scan_id}")
async def api_delete_scan(scan_id: str, request: Request) -> JSONResponse:
    _check_token(request)
    if not await db.delete_scan(scan_id):
        raise HTTPException(404, "Scan not found")
    return JSONResponse({"deleted": True})


@app.get("/api/scan/{scan_id}/report")
async def api_report(scan_id: str, request: Request,
                     format: str = Query("md")) -> Response:
    _check_token(request)
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    try:
        content, media = report_mod.render(result, format)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    fname = f"fsv-{db.host_of(result.target) or 'scan'}-{scan_id[:8]}.{format}"
    return Response(content, media_type=media,
                    headers={"Content-Disposition": f'inline; filename="{fname}"'})


# legacy aliases kept so old links/bookmarks still work
@app.get("/api/scan/{scan_id}/report.md", response_class=PlainTextResponse)
async def api_report_md(scan_id: str, request: Request) -> str:
    _check_token(request)
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return report_mod.generate_markdown(result)


@app.get("/api/scan/{scan_id}/report.json")
async def api_report_json(scan_id: str, request: Request) -> PlainTextResponse:
    _check_token(request)
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return PlainTextResponse(report_mod.generate_json(result), media_type="application/json")


# ── triage / diff / trend ───────────────────────────────────────────────────

@app.post("/api/scan/{scan_id}/triage")
async def api_triage(scan_id: str, body: TriageRequest, request: Request) -> JSONResponse:
    _check_token(request)
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    match = [f for f in result.findings if f.id == body.finding or f.fingerprint == body.finding]
    if not match:
        raise HTTPException(404, f"No finding '{body.finding}' in this scan")
    try:
        st = FindingStatus(body.status)
    except ValueError:
        raise HTTPException(400, f"Invalid status '{body.status}'")
    f = match[0]
    await db.set_triage(db.host_of(result.target), f.fingerprint, st, body.note)
    return JSONResponse({"ok": True, "fingerprint": f.fingerprint, "status": st.value})


@app.get("/api/diff")
async def api_diff(request: Request, baseline: str, current: str) -> JSONResponse:
    _check_token(request)
    a = await db.get_scan(baseline)
    b = await db.get_scan(current)
    if a is None or b is None:
        raise HTTPException(404, "One or both scans not found")
    return JSONResponse(compare(a, b))


@app.get("/api/trend")
async def api_trend(request: Request, target: str, limit: int = 20) -> JSONResponse:
    _check_token(request)
    return JSONResponse(await db.target_history(target, limit=limit))


# ── websocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def ws_progress(websocket: WebSocket, scan_id: str) -> None:
    if API_TOKEN:
        token = websocket.query_params.get("token")
        if token != API_TOKEN:
            await websocket.close(code=4401)
            return
    await websocket.accept()
    q = hub.subscribe(scan_id)
    try:
        while True:
            payload = await q.get()
            await websocket.send_json(payload)
            if payload.get("type") == "complete":
                break
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        hub.unsubscribe(scan_id, q)


# ── entrypoint ────────────────────────────────────────────────────────────────

def run() -> None:
    import uvicorn
    scheme = "http"
    print(f"\n  FSV v{__version__} dashboard → {scheme}://{WEB_HOST}:{WEB_PORT}")
    if API_TOKEN:
        print("  API token required (FSV_TOKEN is set).")
    print()
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    run()
