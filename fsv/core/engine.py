"""
FSV Scan Engine
───────────────
Orchestrates crawling + all modules for a given target.

Pipeline
    1. crawl      — same-origin BFS through the shared HTTPClient (rate-limited,
                    cached: pages fetched here are reused by every module)
    2. recon      — site-wide modules, concurrently, once against the target
    3. scan       — per-URL modules over every crawled URL, bounded concurrency
    4. aggregate  — identical issues on many URLs collapse into one finding
                    carrying `affected_urls`
    5. persist    — SQLite, plus progress events for live UIs
"""

from __future__ import annotations
import asyncio
import fnmatch
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse

import aiohttp
from bs4 import BeautifulSoup

from fsv.config import USER_AGENT, MODULES_ENABLED
from fsv.core.models import (
    Finding, ScanConfig, ScanResult, ScanStatus, ScanProgress, ScanProfile,
    SEVERITY_ORDER, Confidence,
)
from fsv.core import database as db
from fsv.core import registry
from fsv.core.http_client import HTTPClient


ProgressCallback = Callable[[ScanProgress], None]


# Backwards-compatible alias (some callers import these from engine)
def _load_modules() -> dict[str, type]:
    return registry.load_registry()


SITE_WIDE = {n for n in registry.META if registry.is_site_wide(n)}


# ── active scans in memory ────────────────────────────────────────────────────

_active:    dict[str, ScanResult] = {}
_tasks:     dict[str, asyncio.Task] = {}
_cancelled: set[str] = set()


def get_active_scan(scan_id: str) -> ScanResult | None:
    return _active.get(scan_id)


def active_scan_ids() -> list[str]:
    return list(_active)


def cancel_scan(scan_id: str) -> bool:
    """Request cancellation of a running scan. In-flight requests are aborted."""
    if scan_id not in _active:
        return False
    _cancelled.add(scan_id)
    task = _tasks.get(scan_id)
    if task is not None and not task.done():
        task.cancel()
    return True


def new_scan_id() -> str:
    return str(uuid.uuid4())


# ── engine ────────────────────────────────────────────────────────────────────

def _profile_tuning(cfg: ScanConfig) -> tuple[float, int]:
    """Apply profile presets on top of explicit config."""
    rate, threads = cfg.rate_per_sec, cfg.threads
    if cfg.profile == ScanProfile.AGGRESSIVE:
        rate, threads = max(rate, 40.0), max(threads, 20)
    elif cfg.profile == ScanProfile.PASSIVE:
        rate = min(rate, 15.0)
    return rate, threads


def _select_modules(cfg: ScanConfig) -> list[str]:
    all_modules = registry.load_registry()
    wanted = cfg.modules or [m for m in all_modules if MODULES_ENABLED.get(m, True)]
    wanted = [m for m in dict.fromkeys(wanted) if m in all_modules]
    return registry.select_modules(cfg.profile, wanted)


async def run_scan(
    scan_config: ScanConfig,
    progress_cb: ProgressCallback | None = None,
    scan_id: str | None = None,
) -> ScanResult:
    """
    Run a full scan and persist the result.

    `scan_id` may be supplied by the caller (the web API pre-allocates one so
    clients can subscribe before the first event fires). `progress_cb` receives
    ScanProgress updates throughout.
    """
    await db.init_db()
    scan_id    = scan_id or new_scan_id()
    started_at = datetime.now(timezone.utc).isoformat()

    result = ScanResult(
        scan_id    = scan_id,
        target     = scan_config.target,
        status     = ScanStatus.RUNNING,
        started_at = started_at,
        profile    = scan_config.profile.value,
        tags       = list(scan_config.tags),
    )
    _active[scan_id] = result
    task = asyncio.current_task()
    if task is not None:
        _tasks[scan_id] = task
    await db.upsert_scan(result, scan_config.model_dump(mode="json"))

    def _emit(phase: str, current: int, total: int, message: str) -> None:
        if progress_cb:
            try:
                progress_cb(ScanProgress(
                    scan_id=scan_id, phase=phase, current=current, total=total,
                    message=message, findings=len(result.findings),
                ))
            except Exception:
                pass   # a broken UI callback must never kill the scan

    rate, threads = _profile_tuning(scan_config)
    http: HTTPClient | None = None

    try:
        connector  = aiohttp.TCPConnector(ssl=False, limit=max(20, threads * 2))
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        hdrs = {"User-Agent": scan_config.user_agent or USER_AGENT, **scan_config.headers}
        async with aiohttp.ClientSession(
            connector=connector, cookie_jar=cookie_jar,
            headers=hdrs, cookies=scan_config.cookies,
        ) as session:
            http = HTTPClient(
                session,
                rate_per_sec = rate,
                max_retries  = scan_config.max_retries,
                timeout      = scan_config.timeout,
                rotate_ua    = scan_config.rotate_ua,
                default_ua   = scan_config.user_agent or USER_AGENT,
            )

            # 1) CRAWL
            _emit("crawl", 0, 1, f"Crawling {scan_config.target} …")
            crawler = Crawler(http, scan_config)
            urls = await crawler.run(
                on_page=lambda n: _emit("crawl", n, scan_config.max_urls,
                                        f"Discovered {n} URL(s) …"),
            )
            result.urls = urls
            result.urls_scanned = len(urls)
            _emit("crawl", 1, 1, f"Found {len(urls)} URL(s)")

            # 2) SELECT MODULES
            all_modules = registry.load_registry()
            want = _select_modules(scan_config)
            result.modules_run = want
            scanners = {name: all_modules[name](http, scan_config) for name in want}
            site_modules    = [k for k in scanners if registry.is_site_wide(k)]
            per_url_modules = [k for k in scanners if not registry.is_site_wide(k)]

            def _module_failed(name: str) -> None:
                result.module_errors[name] = result.module_errors.get(name, 0) + 1

            # 3) SITE-WIDE MODULES — concurrently, once on the base target
            site_done = 0

            async def _run_site(name: str) -> None:
                nonlocal site_done
                try:
                    findings = await scanners[name].scan(scan_config.target)
                except asyncio.CancelledError:
                    raise
                except Exception:
                    _module_failed(name)
                    findings = []
                result.findings.extend(findings)
                if name == "tech":
                    for f in findings:
                        if f.extra.get("technologies"):
                            result.tech_stack = list(f.extra["technologies"])
                site_done += 1
                _emit("recon", site_done, len(site_modules), f"[{name}] done")

            if site_modules:
                _emit("recon", 0, len(site_modules),
                      f"Running {len(site_modules)} site-wide module(s) …")
                await asyncio.gather(*(_run_site(m) for m in site_modules))

            # 4) PER-URL MODULES — bounded concurrency across URL×module pairs
            jobs = [(u, m) for u in urls for m in per_url_modules]
            total_work, done = len(jobs), 0
            sem = asyncio.Semaphore(max(2, threads))

            async def _run_job(url: str, name: str) -> None:
                nonlocal done
                async with sem:
                    try:
                        found = await scanners[name].scan(url)
                    except asyncio.CancelledError:
                        raise
                    except Exception:
                        _module_failed(name)
                        found = []
                    result.findings.extend(found)
                    done += 1
                    if done % 3 == 0 or done == total_work:
                        short = url if len(url) <= 55 else url[:55] + "…"
                        _emit("scan", done, total_work, f"[{name}] {short}")

            if jobs:
                await asyncio.gather(*(_run_job(u, m) for (u, m) in jobs))

        result.status = ScanStatus.COMPLETED

    except asyncio.CancelledError:
        if scan_id not in _cancelled:
            # cancelled from outside (shutdown, Ctrl-C) — persist, then propagate
            result.status = ScanStatus.CANCELLED
            result.error  = "interrupted"
            _finalize(result, http, started_at)
            await db.upsert_scan(result)
            _forget(scan_id)
            raise
        if task is not None and hasattr(task, "uncancel"):
            task.uncancel()
        result.status = ScanStatus.CANCELLED

    except Exception as exc:
        result.status = ScanStatus.FAILED
        result.error  = f"{type(exc).__name__}: {exc}"

    _finalize(result, http, started_at)
    try:
        await db.apply_triage(result)
        await db.upsert_scan(result)
    finally:
        _forget(scan_id)

    if result.status == ScanStatus.COMPLETED:
        _emit("done", 1, 1, f"Scan complete — {len(result.findings)} findings")
    elif result.status == ScanStatus.CANCELLED:
        _emit("cancelled", 1, 1, "Scan cancelled — partial results kept")
    else:
        _emit("error", 1, 1, f"Scan failed: {result.error}")
    return result


def _finalize(result: ScanResult, http: HTTPClient | None, started_at: str) -> None:
    result.findings = sort_findings(aggregate_findings(result.findings))
    if http is not None:
        result.stats = http.stats.as_dict()
    result.finished_at = datetime.now(timezone.utc).isoformat()
    result.duration_s = round(
        (datetime.fromisoformat(result.finished_at)
         - datetime.fromisoformat(started_at)).total_seconds(), 2)


def _forget(scan_id: str) -> None:
    _active.pop(scan_id, None)
    _tasks.pop(scan_id, None)
    _cancelled.discard(scan_id)


# ── crawler ───────────────────────────────────────────────────────────────────

# links that would log us out / destroy state — never crawl these
_DANGEROUS_LINK = ("logout", "signout", "sign-out", "log-out", "disconnect",
                   "delete", "destroy", "remove", "/logoff")
_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
             ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
             ".mp3", ".pdf", ".zip", ".gz", ".tar", ".rar", ".dmg", ".exe")


def same_origin(url: str, host: str) -> bool:
    """
    True when `url` is http(s) on exactly `host` (netloc compare).
    A prefix check would let `https://site.com.evil.net` slip into scope.
    """
    p = urlparse(url)
    return p.scheme in ("http", "https") and p.netloc.lower() == host


def canonical_url(url: str) -> str:
    """Drop the fragment and a trailing slash on non-root paths."""
    p = urlparse(url.split("#", 1)[0])
    path = p.path
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/")
    if p.query and not path:
        path = "/"
    return p._replace(path=path).geturl()


class Crawler:
    """Same-origin BFS that skips assets, destructive links and excluded paths."""

    def __init__(self, http: HTTPClient, cfg: ScanConfig) -> None:
        self.http = http
        self.cfg  = cfg
        p = urlparse(cfg.target)
        self.origin = f"{p.scheme}://{p.netloc}"
        self.host   = p.netloc.lower()
        self.disallow: list[str] = []

    def excluded(self, link: str) -> bool:
        low  = link.lower()
        path = urlparse(link).path or "/"
        if any(d in low for d in _DANGEROUS_LINK):
            return True
        if path.lower().endswith(_SKIP_EXT):
            return True
        if any(fnmatch.fnmatch(path, pat) for pat in self.cfg.exclude_paths):
            return True
        if self.cfg.respect_robots and any(path.startswith(d) for d in self.disallow):
            return True
        return False

    async def _robots(self) -> list[str]:
        r = await self.http.request(self.origin + "/robots.txt")
        if r.status != 200:
            return []
        out = []
        for line in r.body.splitlines():
            line = line.split("#", 1)[0].strip()
            if line.lower().startswith("disallow:"):
                path = line.split(":", 1)[1].strip()
                if path and path != "/":
                    out.append(path)
        return out

    async def links(self, url: str) -> list[str]:
        r = await self.http.request(url)
        if not r.ok or "html" not in r.headers.get("Content-Type", "").lower():
            return []
        try:
            soup = BeautifulSoup(r.body, "lxml")
        except Exception:
            return []
        base = r.url or url
        if soup.base and soup.base.get("href"):
            base = urljoin(base, soup.base["href"])
        found = []
        for tag in soup.find_all(["a", "form", "area", "iframe"]):
            href = tag.get("href") or tag.get("action") or tag.get("src") or ""
            if not href or href.startswith(("javascript:", "mailto:", "tel:", "data:")):
                continue
            full = canonical_url(urljoin(base, href))
            if same_origin(full, self.host) and not self.excluded(full):
                found.append(full)
        return list(dict.fromkeys(found))

    async def run(self, on_page: Callable[[int], None] | None = None) -> list[str]:
        cfg = self.cfg
        if cfg.respect_robots:
            self.disallow = await self._robots()

        start = [canonical_url(cfg.target)]
        start += [canonical_url(urljoin(cfg.target, s)) for s in cfg.seed_urls]
        start = [u for u in dict.fromkeys(start) if same_origin(u, self.host)]

        seen: set[str] = set(start)
        queue: deque[tuple[str, int]] = deque((u, 0) for u in start)
        out: list[str] = []

        while queue and len(out) < cfg.max_urls:
            # fetch one BFS "wave" of pages concurrently
            wave = []
            while queue and len(wave) + len(out) < cfg.max_urls and len(wave) < max(4, cfg.threads):
                wave.append(queue.popleft())
            out.extend(u for u, _ in wave)
            if on_page:
                on_page(len(out))
            if not cfg.crawl:
                break
            expandable = [(u, d) for u, d in wave if d < cfg.depth]
            results = await asyncio.gather(*(self.links(u) for u, _ in expandable))
            for (_, d), links in zip(expandable, results):
                for link in links:
                    if link not in seen and len(seen) < cfg.max_urls * 3:
                        seen.add(link)
                        queue.append((link, d + 1))
        return out[: cfg.max_urls]


# ── post-processing ───────────────────────────────────────────────────────────

_CONF_RANK = {Confidence.CERTAIN: 3, Confidence.FIRM: 2, Confidence.TENTATIVE: 1}


def aggregate_findings(findings: list[Finding]) -> list[Finding]:
    """
    Collapse findings that describe the same issue (same fingerprint) on
    different URLs into one finding with every affected URL listed. The kept
    representative is the most severe / most confident instance.
    """
    groups: dict[str, list[Finding]] = {}
    for f in findings:
        groups.setdefault(f.fingerprint, []).append(f)

    out: list[Finding] = []
    for group in groups.values():
        best = max(group, key=lambda f: (SEVERITY_ORDER[f.severity], _CONF_RANK[f.confidence]))
        urls: list[str] = []
        for f in group:
            urls.extend(f.affected_urls or [f.url])
        best.affected_urls = list(dict.fromkeys(urls))
        out.append(best)
    return out


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER[f.severity], -_CONF_RANK[f.confidence],
                       f.module, f.title),
    )


# kept for callers of the old helper name
_deduplicate = aggregate_findings
