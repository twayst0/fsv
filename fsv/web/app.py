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
  • triage, diff, delta-vs-previous and target-trend endpoints
  • RequestGuard: Host allowlist (DNS rebinding) + same-origin / JSON-only
    writes (CSRF) — see fsv/web/security.py
  • reconnectable progress: the latest event per scan is replayed, so a
    reloaded dashboard re-attaches to a running scan
"""

from __future__ import annotations
import asyncio
import hmac
import re
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.requests import HTTPConnection
from pydantic import BaseModel, Field

from fsv import __version__
from fsv.config import (
    WEB_HOST, WEB_PORT, MAX_CONCURRENT_SCANS, API_TOKEN, ALLOWED_HOSTS, REQUIRE_VERIFICATION,
)
from fsv.core.models import ScanConfig, ScanProfile, FindingStatus, normalize_target
from fsv.core import engine, database as db, registry, ownership
from fsv.core import report as report_mod
from fsv.core.diff import compare
from fsv.web.security import RequestGuard, allowed_hosts

STATIC_DIR = Path(__file__).parent / "static"

_scan_sem = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
_HOSTS = allowed_hosts(WEB_HOST, ALLOWED_HOSTS)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    await db.init_db()
    await db.mark_interrupted()   # flush stale 'running' rows from a prior crash
    yield
    for t in list(_bg_tasks):     # stop in-flight scans cleanly on shutdown
        t.cancel()


async def _auth_for_api(conn: HTTPConnection) -> None:
    """
    App-wide: EVERY /api/* route requires the token when one is configured. Doing this in a
    dependency (instead of a call at the top of each handler) means a route added later cannot
    forget it — /api/info did exactly that. It also runs before request-body validation, so
    an unauthenticated caller learns nothing from 422 messages.

    Typed as HTTPConnection, not Request: an app-wide dependency also runs for the /ws route, and a
    WebSocket has no Request — asking for one made every live-progress handshake fail with HTTP 500
    (the dashboard then silently fell back to polling). The WebSocket checks its token itself.
    """
    if conn.url.path.startswith("/api/"):
        _check_token(conn)


app = FastAPI(title="FSV", version=__version__, lifespan=_lifespan,
              dependencies=[Depends(_auth_for_api)])
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
app.add_middleware(RequestGuard, hosts=_HOSTS)


# ── auth ────────────────────────────────────────────────────────────────────

def _check_token(request: HTTPConnection) -> None:
    if not API_TOKEN:
        return
    sent = request.headers.get("X-FSV-Token") or request.query_params.get("token") or ""
    if not hmac.compare_digest(sent, API_TOKEN):
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
    seed_urls: list[str] = []     # same-origin pages no link points to
    tags:     list[str] = []
    respect_robots: bool = False
    max_duration: int   = 0       # seconds, 0 = unlimited
    use_ct_logs: bool   = False   # ask crt.sh for subdomains (sends the domain to a third party)
    allow_external: bool = True   # allow modules that contact hosts other than the target
    headers:  dict[str, str] = {} # e.g. Authorization for authenticated scans
    cookies:  dict[str, str] = {}
    authorized: bool    = False   # user must confirm authorization


class VerifyRequest(BaseModel):
    host: str


class TriageRequest(BaseModel):
    finding: str = Field(..., description="finding id or fingerprint")
    status:  str
    note:    str = ""


# ── websocket progress hub ──────────────────────────────────────────────────

class ProgressHub:
    """Fan-out of progress events; remembers the latest event per scan for replay."""
    MAX_REMEMBERED = 200

    def __init__(self) -> None:
        self._queues: dict[str, list[asyncio.Queue]] = {}
        self._last: OrderedDict[str, dict] = OrderedDict()

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

    def latest(self, scan_id: str) -> dict | None:
        return self._last.get(scan_id)

    def publish(self, scan_id: str, payload: dict) -> None:
        self._last[scan_id] = payload
        self._last.move_to_end(scan_id)
        while len(self._last) > self.MAX_REMEMBERED:   # bounded memory
            self._last.popitem(last=False)
        for q in list(self._queues.get(scan_id, [])):
            q.put_nowait(payload)


hub = ProgressHub()
_bg_tasks: set = set()
_pending: dict[str, dict] = {}      # scan_id → {"task", "target"} until it finishes


# ── pages ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index() -> str:
    return (STATIC_DIR / "index.html").read_text(encoding="utf-8")


@app.get("/healthz")
async def healthz() -> dict:
    """Liveness probe for containers / load balancers. No token, and nothing in it worth protecting."""
    return {"ok": True}


@app.get("/api/info")
async def api_info(request: Request) -> dict:
    _check_token(request)          # includes scan/target counts — not for the public
    return {
        "name": "FSV",
        "version": __version__,
        "modules": registry.describe(),
        "profiles": ["passive", "balanced", "aggressive"],
        "report_formats": list(report_mod.FORMATS),
        "auth_required": bool(API_TOKEN),
        "verification_required": REQUIRE_VERIFICATION,
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
            seed_urls=req.seed_urls, tags=req.tags, respect_robots=req.respect_robots,
            max_duration=req.max_duration, headers=req.headers, cookies=req.cookies,
            use_ct_logs=req.use_ct_logs, allow_external=req.allow_external,
        )
    except Exception as exc:
        raise HTTPException(400, f"Invalid scan configuration: {exc}")

    # allow a short queue behind the running scans, then push back
    if len(_pending) >= MAX_CONCURRENT_SCANS * 2:
        raise HTTPException(429, f"Too many scans running or queued "
                            f"(max {MAX_CONCURRENT_SCANS} at once). Try again shortly.")

    scan_id = engine.new_scan_id()

    def _cb(p) -> None:
        hub.publish(scan_id, {
            "type": "progress", "phase": p.phase, "pct": p.pct,
            "current": p.current, "total": p.total, "message": p.message,
            "findings": p.findings,
        })

    async def _run() -> None:
        try:
            if _scan_sem.locked():
                hub.publish(scan_id, {"type": "progress", "phase": "queued", "pct": 0,
                                      "current": 0, "total": 0, "findings": 0,
                                      "message": "Waiting for a free scan slot …"})
            async with _scan_sem:
                result = await engine.run_scan(config, progress_cb=_cb, scan_id=scan_id)
            hub.publish(scan_id, {"type": "complete", "scan_id": result.scan_id,
                                  "summary": result.summary_dict()})
        except asyncio.CancelledError:
            # cancelled while still queued (never reached the engine) or at shutdown
            hub.publish(scan_id, {"type": "complete", "scan_id": scan_id,
                                  "summary": None, "status": "cancelled"})
        except Exception as exc:   # engine persists its own failures; this is a safety net
            hub.publish(scan_id, {"type": "complete", "scan_id": scan_id,
                                  "summary": None, "status": "failed", "error": str(exc)})
        finally:
            _pending.pop(scan_id, None)

    task = asyncio.get_running_loop().create_task(_run())
    _pending[scan_id] = {"task": task, "target": target}
    _bg_tasks.add(task)
    task.add_done_callback(_bg_tasks.discard)
    return JSONResponse({"scan_id": scan_id, "status": "running"})


@app.post("/api/scan/{scan_id}/cancel")
async def api_cancel_scan(scan_id: str, request: Request) -> JSONResponse:
    _check_token(request)
    if engine.cancel_scan(scan_id):
        return JSONResponse({"cancelled": True})
    queued = _pending.get(scan_id)
    if queued:                    # still waiting for a slot — just drop it
        queued["task"].cancel()
        return JSONResponse({"cancelled": True, "queued": True})
    return JSONResponse({"cancelled": False})


@app.get("/api/active")
async def api_active(request: Request) -> JSONResponse:
    """Scans running or queued in this process — lets a reloaded UI re-attach."""
    _check_token(request)
    return JSONResponse([
        {"scan_id": sid, "target": info["target"], "latest": hub.latest(sid)}
        for sid, info in _pending.items()
    ])


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
    host = re.sub(r"[^A-Za-z0-9._-]", "_", db.host_of(result.target) or "scan")
    ext = "md" if format.startswith("fix-") else format
    fname = f"fsv-{host}-{result.scan_id[:8]}{'-' + format if ext == 'md' and format != 'md' else ''}.{ext}"
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


# ── ownership verification ───────────────────────────────────────────────────

def _clean_host(raw: str) -> str:
    h = (raw or "").strip().lower()
    h = h.split("://", 1)[-1].split("/", 1)[0]
    if not h or any(c.isspace() for c in h):
        raise HTTPException(400, "Provide a host name, e.g. example.com")
    return h


@app.post("/api/verify")
async def api_verify_start(body: VerifyRequest, request: Request) -> JSONResponse:
    """Issue the challenge a site owner publishes to prove control (see core/ownership.py)."""
    _check_token(request)
    host = _clean_host(body.host)
    return JSONResponse(ownership.instructions(host, await db.get_install_secret()))


@app.post("/api/verify/check")
async def api_verify_check(body: VerifyRequest, request: Request) -> JSONResponse:
    _check_token(request)
    host = _clean_host(body.host)
    method = await ownership.check_proof(host.split(":")[0], await db.get_install_secret(),
                                         netloc=host)
    if method:
        await db.add_verified(ownership.verification_domain(host.split(":")[0]) if method == "dns"
                              else host.split(":")[0], method)
    return JSONResponse({"verified": bool(method), "method": method})


@app.get("/api/verified")
async def api_verified(request: Request) -> JSONResponse:
    _check_token(request)
    return JSONResponse(await db.list_verified())


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
        if st not in FindingStatus.user_settable():
            raise ValueError
    except ValueError:
        raise HTTPException(400, f"Invalid status '{body.status}' "
                                 f"(use: {', '.join(s.value for s in FindingStatus.user_settable())})")
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


@app.get("/api/scan/{scan_id}/delta")
async def api_delta(scan_id: str, request: Request) -> JSONResponse:
    """Compare a scan with the previous finished scan of the same host."""
    _check_token(request)
    cur = await db.get_scan(scan_id)
    if cur is None:
        raise HTTPException(404, "Scan not found")
    prev = await db.previous_scan(cur.target, cur.started_at)
    if prev is None:
        return JSONResponse({"previous": None})
    return JSONResponse({"previous": prev.scan_id, **compare(prev, cur)})


@app.get("/api/trend")
async def api_trend(request: Request, target: str, limit: int = 20) -> JSONResponse:
    _check_token(request)
    return JSONResponse(await db.target_history(target, limit=limit))


# ── websocket ─────────────────────────────────────────────────────────────────

@app.websocket("/ws/{scan_id}")
async def ws_progress(websocket: WebSocket, scan_id: str) -> None:
    if API_TOKEN:
        token = websocket.query_params.get("token") or ""
        if not hmac.compare_digest(token, API_TOKEN):
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
    if _HOSTS is None and not API_TOKEN:
        print("  ⚠ Listening on a wildcard address with no FSV_TOKEN and no FSV_ALLOWED_HOSTS:\n"
              "    anyone who can reach this port can start scans. Set FSV_TOKEN.")
    print()
    uvicorn.run(app, host=WEB_HOST, port=WEB_PORT, log_level="info")


if __name__ == "__main__":
    run()
