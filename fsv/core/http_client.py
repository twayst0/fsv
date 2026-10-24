"""
FSV — Shared HTTP Client
────────────────────────
A single request pipeline used by every module. Centralising HTTP gives the
whole scan:

  • Response caching    — identical plain GETs are fetched once, not once per module
  • Rate limiting       — token-bucket politeness so we never hammer a target
  • Automatic retries   — transient network errors retried with backoff
  • Statistics          — requests sent, cache hits, retries, errors, bytes
  • Redirect helpers     — manual redirect-chain following

Modules never touch aiohttp directly; they call BaseScanner.fetch(), which
delegates here.
"""

from __future__ import annotations
import asyncio
import time
import random
from dataclasses import dataclass, field

import aiohttp


# ── rate limiter ───────────────────────────────────────────────────────────────

class TokenBucket:
    """Simple async token-bucket rate limiter."""
    def __init__(self, rate_per_sec: float, burst: int | None = None) -> None:
        self.rate   = max(0.1, rate_per_sec)
        self.capacity = burst if burst is not None else max(1, int(rate_per_sec))
        self.tokens = self.capacity
        self.updated = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.updated
            self.updated = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)
            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


# ── stats ──────────────────────────────────────────────────────────────────────

@dataclass
class HTTPStats:
    requests:   int = 0
    cache_hits: int = 0
    retries:    int = 0
    errors:     int = 0
    bytes_in:   int = 0

    def as_dict(self) -> dict:
        return {
            "requests":   self.requests,
            "cache_hits": self.cache_hits,
            "retries":    self.retries,
            "errors":     self.errors,
            "bytes_in":   self.bytes_in,
        }


# ── a lightweight response object ───────────────────────────────────────────────

@dataclass
class Response:
    status:  int
    headers: dict
    body:    str
    url:     str = ""
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status != -1


# a few realistic desktop UA strings for optional rotation
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
]


class HTTPClient:
    """Shared per-scan HTTP client."""

    def __init__(
        self,
        session:    aiohttp.ClientSession,
        rate_per_sec: float = 20.0,
        max_retries:  int = 2,
        timeout:      int = 10,
        rotate_ua:    bool = False,
        default_ua:   str = "",
    ) -> None:
        self.session   = session
        self.bucket    = TokenBucket(rate_per_sec)
        self.max_retries = max_retries
        self.timeout   = timeout
        self.rotate_ua = rotate_ua
        self.default_ua = default_ua
        self.stats     = HTTPStats()
        self._cache: dict[str, Response] = {}
        self._cache_lock = asyncio.Lock()

    # ── public API ──────────────────────────────────────────────────────

    async def request(
        self,
        url:     str,
        method:  str = "GET",
        params:  dict | None = None,
        data:    dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
        cache:   bool = True,
    ) -> Response:
        method = method.upper()

        # Cache only safe, header-free, redirect-following GETs
        cacheable = (cache and method == "GET" and not headers
                     and not params and not data and allow_redirects)
        if cacheable:
            async with self._cache_lock:
                hit = self._cache.get(url)
            if hit is not None:
                self.stats.cache_hits += 1
                return hit

        resp = await self._do_request(
            url, method, params, data, headers, allow_redirects
        )

        if cacheable and resp.ok:
            async with self._cache_lock:
                self._cache[url] = resp
        return resp

    async def redirect_chain(self, url: str) -> list[tuple[int, str]]:
        """Follow redirects manually, returning (status, location) pairs."""
        chain: list[tuple[int, str]] = []
        current = url
        for _ in range(10):
            r = await self._do_request(current, "GET", None, None, None, False)
            if not r.ok:
                break
            location = r.headers.get("Location", "")
            chain.append((r.status, location))
            if r.status not in (301, 302, 303, 307, 308) or not location:
                break
            current = location
        return chain

    # ── internals ───────────────────────────────────────────────────────

    async def _do_request(
        self, url, method, params, data, headers, allow_redirects
    ) -> Response:
        attempt = 0
        last_exc: Exception | None = None
        while attempt <= self.max_retries:
            await self.bucket.acquire()
            h = dict(headers or {})
            if self.rotate_ua:
                h.setdefault("User-Agent", random.choice(USER_AGENTS))
            elif self.default_ua:
                h.setdefault("User-Agent", self.default_ua)
            t0 = time.monotonic()
            try:
                to = aiohttp.ClientTimeout(total=self.timeout)
                async with self.session.request(
                    method, url, params=params, data=data, headers=h,
                    timeout=to, allow_redirects=allow_redirects, ssl=False,
                ) as resp:
                    body = await resp.text(errors="replace")
                    self.stats.requests += 1
                    self.stats.bytes_in += len(body)
                    return Response(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=time.monotonic() - t0,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                attempt += 1
                if attempt <= self.max_retries:
                    self.stats.retries += 1
                    await asyncio.sleep(0.4 * (2 ** (attempt - 1)) + random.random() * 0.2)
                continue
            except Exception as exc:
                last_exc = exc
                break

        self.stats.errors += 1
        return Response(status=-1, headers={}, body="", url=url)
