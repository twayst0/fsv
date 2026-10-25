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
import logging
import uuid
from collections import deque
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import urljoin, urlparse, urlencode

import aiohttp
from bs4 import BeautifulSoup

from fsv.config import USER_AGENT, MODULES_ENABLED, BLOCK_PRIVATE, REQUIRE_VERIFICATION
from fsv.core.models import (
    Finding, ScanConfig, ScanResult, ScanStatus, ScanProgress, ScanProfile,
    SEVERITY_ORDER, Confidence,
)
from fsv.core import database as db
from fsv.core import registry
from fsv.core.correlate import correlate
from fsv.core import ownership
from fsv.core import discovery
from fsv.core.http_client import HTTPClient
from fsv.core.netsafety import make_connector, make_trace_config, check_target


ProgressCallback = Callable[[ScanProgress], None]

log = logging.getLogger("fsv.engine")


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
    if not cfg.allow_external:
        # modules that contact hosts other than the target (cloud storage, subdomain probes…)
        wanted = [m for m in wanted if not all_modules[m].external]
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

    limit = scan_config.max_duration or None
    try:
        proxy = resolve_proxy(scan_config)
        await check_target(scan_config.target, allow_private=not BLOCK_PRIVATE)
        await _require_proof_of_control(scan_config)
        async with asyncio.timeout(limit):
            connector  = make_connector(max(20, threads * 2), allow_private=not BLOCK_PRIVATE)
            cookie_jar = aiohttp.CookieJar(unsafe=True)
            hdrs = {"User-Agent": scan_config.user_agent or USER_AGENT, **scan_config.headers}
            async with aiohttp.ClientSession(
                connector=connector, cookie_jar=cookie_jar,
                headers=hdrs, cookies=scan_config.cookies,
                trace_configs=[make_trace_config(not BLOCK_PRIVATE)],
            ) as session:
                http = HTTPClient(
                    session,
                    rate_per_sec = rate,
                    max_retries  = scan_config.max_retries,
                    timeout      = scan_config.timeout,
                    rotate_ua    = scan_config.rotate_ua,
                    default_ua   = scan_config.user_agent or USER_AGENT,
                    proxy        = proxy,
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
                if crawler.discovered:
                    result.stats["discovered"] = dict(crawler.discovered)
                _emit("crawl", 1, 1, f"Found {len(urls)} URL(s)")

                # 2) SELECT MODULES
                all_modules = registry.load_registry()
                want = _select_modules(scan_config)
                result.modules_run = want
                scanners = {name: all_modules[name](http, scan_config) for name in want}
                site_modules    = [k for k in scanners if registry.is_site_wide(k)]
                per_url_modules = [k for k in scanners if not registry.is_site_wide(k)]

                def _module_failed(name: str, exc: BaseException, where: str) -> None:
                    result.module_errors[name] = result.module_errors.get(name, 0) + 1
                    msg = f"{type(exc).__name__}: {exc}"[:300]
                    result.module_error_samples.setdefault(name, f"{msg}  (on {where})")
                    log.warning("module %s failed on %s: %s", name, where, msg,
                                exc_info=log.isEnabledFor(logging.DEBUG))

                # 3) SITE-WIDE MODULES — concurrently, once on the base target
                site_done = 0

                async def _run_site(name: str) -> None:
                    nonlocal site_done
                    try:
                        findings = await scanners[name].scan(scan_config.target)
                    except asyncio.CancelledError:
                        raise
                    except Exception as exc:
                        _module_failed(name, exc, scan_config.target)
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
                live = [u for u in urls if not http.known_dead(u)]
                if len(live) < len(urls):
                    result.stats["unresponsive_urls"] = [u for u in urls if u not in live][:20]
                jobs = [(u, m) for u in live for m in per_url_modules]
                total_work, done = len(jobs), 0
                sem = asyncio.Semaphore(max(2, threads))

                async def _run_job(url: str, name: str) -> None:
                    nonlocal done
                    async with sem:
                        try:
                            found = await scanners[name].scan(url)
                        except asyncio.CancelledError:
                            raise
                        except Exception as exc:
                            _module_failed(name, exc, url)
                            found = []
                        result.findings.extend(found)
                        done += 1
                        if done % 3 == 0 or done == total_work:
                            short = url if len(url) <= 55 else url[:55] + "…"
                            _emit("scan", done, total_work, f"[{name}] {short}")

                if jobs:
                    await asyncio.gather(*(_run_job(u, m) for (u, m) in jobs))

        result.status = ScanStatus.COMPLETED

    except TimeoutError:
        result.status = ScanStatus.CANCELLED
        result.error  = f"time limit reached ({scan_config.max_duration}s) — partial results"

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

    except ownership.OwnershipRequired as exc:
        result.status = ScanStatus.FAILED
        result.error  = str(exc)
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
        _emit("cancelled", 1, 1, result.error or "Scan cancelled — partial results kept")
    else:
        _emit("error", 1, 1, f"Scan failed: {result.error}")
    return result


async def _require_proof_of_control(cfg: ScanConfig) -> None:
    """Shared-service rule: payload-sending scans need proof the target belongs to the requester."""
    if not REQUIRE_VERIFICATION:
        return
    selected = _select_modules(cfg)
    if all(registry.is_passive(m) for m in selected):
        return                                           # read-only: allowed anywhere public
    if await ownership.is_local_target(cfg.target):
        return                                           # local development
    host = urlparse(cfg.target).hostname or ""
    if await db.is_host_verified(host):
        return
    info = ownership.instructions(host, await db.get_install_secret())
    raise ownership.OwnershipRequired(ownership.refusal_message(host, info))


def _finalize(result: ScanResult, http: HTTPClient | None, started_at: str) -> None:
    merged = aggregate_findings(result.findings)
    result.findings = sort_findings(merged + correlate(merged))
    if http is not None:
        keep = {k: result.stats[k] for k in ("discovered", "unresponsive_urls") if k in result.stats}
        result.stats = {**http.stats.as_dict(), **keep}
    if result.module_error_samples:
        result.stats["module_error_samples"] = dict(result.module_error_samples)
    if http is not None:
        if http.stats.requests and not http.stats.responses and not result.error:
            result.error = ("target unreachable — no HTTP response was received; "
                            "only non-HTTP checks (e.g. DNS) produced results")
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


def resolve_proxy(cfg: ScanConfig) -> str | None:
    """
    The proxy for this scan, or None. "env" reads HTTPS_PROXY / HTTP_PROXY (by the target's scheme)
    and honours NO_PROXY. Refused on shared deployments: the proxy resolves the target itself, so
    FSV's private-address guard could no longer see where requests really go.
    """
    raw = (cfg.proxy or "").strip()
    if not raw:
        return None
    if raw.lower() == "env":
        import os
        from urllib.request import proxy_bypass_environment
        scheme = urlparse(cfg.target).scheme
        raw = (os.environ.get(f"{scheme}_proxy") or os.environ.get(f"{scheme.upper()}_PROXY")
               or os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY")
               or os.environ.get("http_proxy") or os.environ.get("HTTP_PROXY") or "")
        if not raw or proxy_bypass_environment(urlparse(cfg.target).hostname or ""):
            return None
    if urlparse(raw).scheme not in ("http", "https") or not urlparse(raw).hostname:
        raise ValueError(f"proxy must be an http(s)://host:port URL, got {raw!r}")
    if BLOCK_PRIVATE:
        raise ValueError("a proxy cannot be used while FSV_BLOCK_PRIVATE is set (shared deployment): "
                         "the address guard could not see where requests go")
    return raw


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
        self.scripts_seen: set[str] = set()
        # where crawl seeds came from, beyond <a href> — reported in scan stats
        self.discovered: dict[str, int] = {}

    def _count(self, source: str, n: int) -> None:
        if n:
            self.discovered[source] = self.discovered.get(source, 0) + n

    def _in_scope(self, urls) -> list[str]:
        out = []
        for u in urls:
            full = canonical_url(urljoin(self.origin + "/", u))
            if same_origin(full, self.host) and not self.excluded(full):
                out.append(full)
        return list(dict.fromkeys(out))

    async def _discover(self) -> list[str]:
        """Seeds from robots.txt, sitemaps and a debug-mode 404 page (all plain GETs)."""
        seeds: list[str] = []
        r = await self.http.request(self.origin + "/robots.txt")
        paths, maps = discovery.robots_entries(r.body) if r.status == 200 else ([], [])
        found = self._in_scope(paths)
        self._count("robots.txt", len(found))
        seeds += found

        queue = list(dict.fromkeys(maps or [self.origin + "/sitemap.xml"]))
        pages: list[str] = []
        for sm in queue[:5]:                                  # an index may point to more maps
            if not same_origin(sm, self.host):
                continue
            r = await self.http.request(sm)
            if r.status != 200:
                continue
            got, nested = discovery.sitemap_locs(r.body)
            pages += got
            queue += [n for n in nested if n not in queue]
        found = self._in_scope(pages)
        self._count("sitemap", len(found))
        seeds += found

        r = await self.http.request(self.origin + "/fsv-discovery-" + uuid.uuid4().hex[:10])
        if r.status == 404:
            found = self._in_scope(discovery.django_debug_routes(r.body))
            self._count("debug 404 page", len(found))
            seeds += found
        return list(dict.fromkeys(seeds))[: self.cfg.max_urls * 2]

    async def _script_routes(self, soup, base: str) -> list[str]:
        """API paths quoted in same-origin scripts (external and inline)."""
        paths: list[str] = []
        for tag in soup.find_all("script"):
            src = tag.get("src")
            if not src:
                paths += discovery.js_routes(tag.string or "")
                continue
            full = urljoin(base, src).split("#", 1)[0]
            if not same_origin(full, self.host) or full in self.scripts_seen or len(self.scripts_seen) >= 40:
                continue
            self.scripts_seen.add(full)
            r = await self.http.request(full)
            if r.status == 200:
                paths += discovery.js_routes(r.body)
        found = self._in_scope(paths)
        self._count("javascript", len(found))
        return found

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
        found.extend(self._form_urls(soup, base))
        found.extend(await self._script_routes(soup, base))
        return list(dict.fromkeys(found))

    _FORM_SKIP = {"password", "file", "submit", "button", "image", "reset"}

    def _form_urls(self, soup, base: str) -> list[str]:
        """
        GET forms are entry points with parameters that plain links don't show
        (search boxes, filters). Turn each into one URL using the form's own
        defaults or a neutral placeholder, so per-URL modules see the parameters.
        POST forms are left alone — submitting them could change state.
        """
        out = []
        for form in soup.find_all("form"):
            if (form.get("method") or "get").lower() != "get":
                continue
            params: dict[str, str] = {}
            for field in form.find_all(["input", "select", "textarea"]):
                name = field.get("name")
                ftype = (field.get("type") or "text").lower()
                if not name or ftype in self._FORM_SKIP:
                    continue
                if field.name == "select":
                    opt = field.find("option")
                    params[name] = (opt.get("value") or opt.text.strip()) if opt else ""
                elif ftype in ("checkbox", "radio"):
                    params.setdefault(name, field.get("value") or "on")
                else:
                    params[name] = field.get("value") or "fsv"
            if not params:
                continue
            action = canonical_url(urljoin(base, form.get("action") or base))
            url = urlparse(action)._replace(query=urlencode(params)).geturl()
            if same_origin(url, self.host) and not self.excluded(url):
                out.append(url)
        return out

    async def run(self, on_page: Callable[[int], None] | None = None) -> list[str]:
        cfg = self.cfg
        if cfg.respect_robots:
            self.disallow = await self._robots()

        start = [canonical_url(cfg.target)]
        start += [canonical_url(urljoin(cfg.target, s)) for s in cfg.seed_urls]
        start = [u for u in dict.fromkeys(start) if same_origin(u, self.host)]
        extra = [u for u in await self._discover() if u not in start] if cfg.crawl else []

        seen: set[str] = set(start) | set(extra)
        queue: deque[tuple[str, int]] = deque([(u, 0) for u in start] + [(u, 1) for u in extra])
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
