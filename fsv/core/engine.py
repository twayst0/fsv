"""
FSV Scan Engine
───────────────
Orchestrates crawling + all modules for a given target.
"""

from __future__ import annotations
import asyncio
import uuid
from datetime import datetime, timezone
from typing import Callable, AsyncIterator
from urllib.parse import urljoin, urlparse, urlencode, parse_qs, urlunparse

import aiohttp
from bs4 import BeautifulSoup

from fsv.config import DEFAULT_TIMEOUT, DEFAULT_MAX_URLS, USER_AGENT, MODULES_ENABLED
from fsv.core.models import (
    Finding, ScanConfig, ScanResult, ScanStatus, ScanProgress, ScanProfile
)
from fsv.core import database as db
from fsv.core import registry
from fsv.core import knowledge
from fsv.core.http_client import HTTPClient


# Backwards-compatible alias (some callers import these from engine)
def _load_modules() -> dict[str, type]:
    return registry.load_registry()


SITE_WIDE = {n for n in registry.META if registry.is_site_wide(n)}


# ── active scans in memory ────────────────────────────────────────────────────

_active:    dict[str, ScanResult] = {}
_cancelled: set[str] = set()


def get_active_scan(scan_id: str) -> ScanResult | None:
    return _active.get(scan_id)


def cancel_scan(scan_id: str) -> bool:
    """Request cancellation of a running scan."""
    if scan_id in _active:
        _cancelled.add(scan_id)
        return True
    return False


# ── engine ────────────────────────────────────────────────────────────────────

async def run_scan(
    scan_config: ScanConfig,
    progress_cb: Callable[[ScanProgress], None] | None = None,
) -> ScanResult:
    """
    Entry point.  Runs a full scan and persists the result.
    progress_cb is called with progress updates throughout.
    """
    await db.init_db()
    scan_id    = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc).isoformat()

    result = ScanResult(
        scan_id    = scan_id,
        target     = scan_config.target,
        status     = ScanStatus.RUNNING,
        started_at = started_at,
    )
    _active[scan_id] = result
    await db.upsert_scan(result, scan_config.model_dump())

    def _emit(phase: str, current: int, total: int, message: str) -> None:
        p = ScanProgress(
            scan_id = scan_id,
            phase   = phase,
            current = current,
            total   = total,
            message = message,
        )
        if progress_cb:
            progress_cb(p)

    # ── apply profile presets (explicit config always wins) ──────────────
    profile = scan_config.profile
    result.profile = profile.value if hasattr(profile, "value") else str(profile)
    rate    = scan_config.rate_per_sec
    threads = scan_config.threads
    if profile == ScanProfile.AGGRESSIVE:
        rate    = max(rate, 40.0)
        threads = max(threads, 20)
    elif profile == ScanProfile.PASSIVE:
        rate    = min(rate, 15.0)

    try:
        connector = aiohttp.TCPConnector(ssl=False, limit=max(20, threads * 2))
        cookie_jar = aiohttp.CookieJar(unsafe=True)
        hdrs = {
            "User-Agent": scan_config.user_agent or USER_AGENT,
            **scan_config.headers,
        }
        async with aiohttp.ClientSession(
            connector  = connector,
            cookie_jar = cookie_jar,
            headers    = hdrs,
            cookies    = scan_config.cookies,
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
            urls = await _crawl(
                session, scan_config.target,
                max_urls = scan_config.max_urls,
                depth    = scan_config.depth,
                crawl    = scan_config.crawl,
                timeout  = scan_config.timeout,
                respect_robots = scan_config.respect_robots,
            )
            result.urls_scanned = len(urls)
            _emit("crawl", 1, 1, f"Found {len(urls)} URL(s)")

            # 2) SELECT MODULES (registry + profile)
            all_modules = registry.load_registry()
            available   = scan_config.modules or [
                k for k, v in MODULES_ENABLED.items() if v
            ]
            # keep only modules that actually exist in the registry
            available   = [m for m in available if m in all_modules]
            want_modules = registry.select_modules(profile, available)

            scanners = {
                name: all_modules[name](http, scan_config)
                for name in want_modules
            }

            site_modules    = [k for k in scanners if registry.is_site_wide(k)]
            per_url_modules = [k for k in scanners if not registry.is_site_wide(k)]

            sem = asyncio.Semaphore(max(2, threads))

            # 3) SITE-WIDE MODULES (once, on base target) — run concurrently
            total_site = len(site_modules)
            for i, mod_name in enumerate(site_modules):
                if scan_id in _cancelled:
                    raise asyncio.CancelledError("Scan cancelled by user")
                _emit("recon", i, total_site, f"[{mod_name}] analyzing target …")
                try:
                    findings = await scanners[mod_name].scan(scan_config.target)
                    result.findings.extend(findings)
                    if mod_name == "tech":
                        for f in findings:
                            if f.extra.get("technologies"):
                                result.tech_stack = f.extra["technologies"]
                except Exception:
                    pass

            # 4) PER-URL MODULES — bounded concurrency across URL×module pairs
            jobs = [(url, m) for url in urls for m in per_url_modules]
            total_work = len(jobs)
            done = 0

            async def _run_job(url: str, mod_name: str):
                nonlocal done
                async with sem:
                    if scan_id in _cancelled:
                        return []
                    try:
                        f = await scanners[mod_name].scan(url)
                    except Exception:
                        f = []
                    done += 1
                    if done % 3 == 0 or done == total_work:
                        short = url if len(url) <= 55 else url[:55] + "…"
                        _emit("scan", done, total_work, f"[{mod_name}] {short}")
                    return f

            if jobs:
                results_lists = await asyncio.gather(
                    *[_run_job(u, m) for (u, m) in jobs]
                )
                for lst in results_lists:
                    result.findings.extend(lst)

            if scan_id in _cancelled:
                raise asyncio.CancelledError("Scan cancelled by user")

        # Enrich every finding with knowledge-base context (impact, attack
        # scenario, OWASP category, remediation steps, references), then dedup.
        for f in result.findings:
            try:
                knowledge.enrich(f)
            except Exception:
                pass
        result.findings = _deduplicate(result.findings)

        # Sort by severity
        result.findings.sort(
            key=lambda f: (
                -{"critical":5,"high":4,"medium":3,"low":2,"info":1}.get(f.severity.value, 0),
            )
        )

        result.stats = http.stats.as_dict()
        finished_at = datetime.now(timezone.utc).isoformat()
        result.finished_at = finished_at
        started_dt  = datetime.fromisoformat(started_at)
        finished_dt = datetime.fromisoformat(finished_at)
        result.duration_s = (finished_dt - started_dt).total_seconds()
        result.status     = ScanStatus.COMPLETED
        _emit("done", 1, 1, f"Scan complete — {len(result.findings)} findings")

    except asyncio.CancelledError:
        result.status      = ScanStatus.CANCELLED
        result.finished_at = datetime.now(timezone.utc).isoformat()
        for f in result.findings:
            try:
                knowledge.enrich(f)
            except Exception:
                pass
        result.findings    = _deduplicate(result.findings)
        _emit("cancelled", 0, 0, "Scan cancelled")

    except Exception as exc:
        result.status     = ScanStatus.FAILED
        result.error      = str(exc)
        result.finished_at= datetime.now(timezone.utc).isoformat()
        _emit("error", 0, 0, f"Scan failed: {exc}")

    finally:
        await db.upsert_scan(result)
        _active.pop(scan_id, None)
        _cancelled.discard(scan_id)

    return result


# ── crawler ───────────────────────────────────────────────────────────────────

# links that would log us out / destroy state — never crawl these
_DANGEROUS_LINK = ("logout", "signout", "sign-out", "log-out", "disconnect",
                   "delete", "destroy", "remove", "/logoff")
_SKIP_EXT = (".jpg", ".jpeg", ".png", ".gif", ".svg", ".webp", ".ico",
             ".css", ".js", ".woff", ".woff2", ".ttf", ".eot", ".mp4",
             ".mp3", ".pdf", ".zip", ".gz", ".tar", ".rar", ".dmg", ".exe")


async def _robots_disallows(session, origin: str, timeout: int) -> list[str]:
    try:
        t = aiohttp.ClientTimeout(total=timeout)
        async with session.get(origin + "/robots.txt", timeout=t, ssl=False) as resp:
            if resp.status != 200:
                return []
            text = await resp.text(errors="replace")
    except Exception:
        return []
    dis = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith("disallow:"):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                dis.append(path)
    return dis


async def _crawl(
    session:  aiohttp.ClientSession,
    base_url: str,
    max_urls: int,
    depth:    int,
    crawl:    bool,
    timeout:  int,
    respect_robots: bool = False,
) -> list[str]:
    """BFS crawler — same-origin, skips assets, logout and (optionally) robots-disallowed paths."""
    parsed   = urlparse(base_url)
    origin   = f"{parsed.scheme}://{parsed.netloc}"
    visited: set[str] = set()
    queue:   list[tuple[str, int]] = [(base_url, 0)]
    to_scan: list[str] = []

    disallow = await _robots_disallows(session, origin, timeout) if respect_robots else []

    def _excluded(link: str) -> bool:
        low = link.lower()
        if any(d in low for d in _DANGEROUS_LINK):
            return True
        if low.split("?")[0].endswith(_SKIP_EXT):
            return True
        if respect_robots:
            path = urlparse(link).path
            if any(path.startswith(d) for d in disallow):
                return True
        return False

    async def _fetch_links(url: str) -> list[str]:
        try:
            t = aiohttp.ClientTimeout(total=timeout)
            async with session.get(url, timeout=t, ssl=False) as resp:
                if "text/html" not in resp.headers.get("Content-Type", ""):
                    return []
                html = await resp.text(errors="replace")
            soup = BeautifulSoup(html, "lxml")
            links = []
            for tag in soup.find_all(["a", "form"]):
                href = tag.get("href") or tag.get("action") or ""
                if not href:
                    continue
                full = urljoin(url, href).split("#")[0]
                if full.startswith(origin) and not _excluded(full):
                    links.append(full)
            return list(set(links))
        except Exception:
            return []

    while queue and len(to_scan) < max_urls:
        url, d = queue.pop(0)
        url = url.rstrip("/") or url
        if url in visited:
            continue
        visited.add(url)
        to_scan.append(url)

        if crawl and d < depth:
            links = await _fetch_links(url)
            for link in links:
                if link not in visited and len(to_scan) + len(queue) < max_urls * 2:
                    queue.append((link, d + 1))

    return to_scan[:max_urls]


# ── deduplication ─────────────────────────────────────────────────────────────

def _deduplicate(findings: list[Finding]) -> list[Finding]:
    seen: set[str] = set()
    out:  list[Finding] = []
    for f in findings:
        key = f"{f.module}:{f.title}:{f.url}:{f.parameter}"
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
