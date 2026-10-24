"""
FSV Web Server (FastAPI)
────────────────────────
Serves the glassmorphism dashboard and a JSON/WebSocket API.
"""

from __future__ import annotations
import asyncio
import json
import os
from pathlib import Path

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from fsv import __version__
from fsv.config import WEB_HOST, WEB_PORT, MODULES_ENABLED
from fsv.core.models import ScanConfig
from fsv.core import engine, database as db
from fsv.core.report import generate_markdown, generate_json

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="FSV", version=__version__)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


# ── request models ────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target:   str
    modules:  list[str] = []
    crawl:    bool      = True
    max_urls: int       = 50
    depth:    int       = 2
    timeout:  int       = 10
    threads:  int       = 10
    profile:  str       = "balanced"
    authorized: bool    = False   # user must confirm authorization


# ── websocket progress hub ──────────────────────────────────────────────────

class ProgressHub:
    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue]] = {}

    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._queues.setdefault(scan_id, []).append(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        if scan_id in self._queues and q in self._queues[scan_id]:
            self._queues[scan_id].remove(q)

    def publish(self, scan_id: str, payload: dict) -> None:
        for q in self._queues.get(scan_id, []):
            q.put_nowait(payload)


hub = ProgressHub()

# strong refs to in-flight scan tasks (prevents premature GC)
_bg_tasks: set = set()


# ── lifecycle ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def _startup() -> None:
    await db.init_db()


# ── routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/api/info")
async def api_info() -> dict:
    return {
        "name":    "FSV",
        "version": __version__,
        "modules": list(MODULES_ENABLED.keys()),
    }


@app.post("/api/scan")
async def api_scan(req: ScanRequest) -> JSONResponse:
    if not req.authorized:
        raise HTTPException(
            status_code=403,
            detail=(
                "Authorization required. You must confirm you own or are explicitly "
                "authorized to test this target before scanning."
            ),
        )

    from fsv.core.models import ScanProfile
    try:
        prof = ScanProfile(req.profile)
    except ValueError:
        prof = ScanProfile.BALANCED

    scan_config = ScanConfig(
        target   = req.target,
        modules  = req.modules,
        crawl    = req.crawl,
        max_urls = req.max_urls,
        depth    = req.depth,
        timeout  = req.timeout,
        threads  = req.threads,
        profile  = prof,
    )

    loop = asyncio.get_event_loop()
    scan_id_holder: dict[str, str] = {}

    def _progress_cb(progress) -> None:
        scan_id_holder["id"] = progress.scan_id
        hub.publish(progress.scan_id, {
            "type":    "progress",
            "phase":   progress.phase,
            "pct":     progress.pct,
            "current": progress.current,
            "total":   progress.total,
            "message": progress.message,
        })

    async def _run() -> None:
        result = await engine.run_scan(scan_config, progress_cb=_progress_cb)
        hub.publish(result.scan_id, {
            "type":   "complete",
            "scan_id": result.scan_id,
            "summary": result.summary_dict(),
        })

    task = loop.create_task(_run())
    # Keep a strong reference so the task isn't garbage-collected mid-scan
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    # Wait briefly for scan_id to be assigned
    for _ in range(50):
        if scan_id_holder.get("id"):
            break
        await asyncio.sleep(0.02)

    return JSONResponse({
        "scan_id": scan_id_holder.get("id", ""),
        "status":  "running",
    })


@app.post("/api/scan/{scan_id}/cancel")
async def api_cancel_scan(scan_id: str) -> JSONResponse:
    ok = engine.cancel_scan(scan_id)
    return JSONResponse({"cancelled": ok})


@app.get("/api/scan/{scan_id}")
async def api_get_scan(scan_id: str) -> JSONResponse:
    result = engine.get_active_scan(scan_id) or await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return JSONResponse({
        **result.summary_dict(),
        "findings": [f.model_dump() for f in result.findings],
        "error":    result.error,
    })


@app.get("/api/scans")
async def api_list_scans(limit: int = 50) -> JSONResponse:
    return JSONResponse(await db.list_scans(limit=limit))


@app.delete("/api/scan/{scan_id}")
async def api_delete_scan(scan_id: str) -> JSONResponse:
    ok = await db.delete_scan(scan_id)
    if not ok:
        raise HTTPException(404, "Scan not found")
    return JSONResponse({"deleted": True})


@app.get("/api/scan/{scan_id}/report.md", response_class=PlainTextResponse)
async def api_report_md(scan_id: str) -> str:
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return generate_markdown(result)


@app.get("/api/scan/{scan_id}/report.json")
async def api_report_json(scan_id: str) -> PlainTextResponse:
    result = await db.get_scan(scan_id)
    if result is None:
        raise HTTPException(404, "Scan not found")
    return PlainTextResponse(generate_json(result), media_type="application/json")


@app.websocket("/ws/{scan_id}")
async def ws_progress(websocket: WebSocket, scan_id: str) -> None:
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
    finally:
        hub.unsubscribe(scan_id, q)


# ── entrypoint ────────────────────────────────────────────────────────────────

def run() -> None:
    import uvicorn
    print(f"\n  FSV dashboard → http://{WEB_HOST}:{WEB_PORT}\n")
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    run()
