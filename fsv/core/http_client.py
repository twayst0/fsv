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
  • Request coalescing   — concurrent identical GETs share one in-flight request
  • Body size cap        — huge responses are truncated, not buffered whole

Modules never touch aiohttp directly; they call BaseScanner.fetch(), which
delegates here.
"""

from __future__ import annotations
import asyncio
import time
import random
from dataclasses import dataclass, field

import aiohttp
from urllib.parse import urljoin

from fsv.core.netsafety import BlockedTarget


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
    requests:   int = 0      # every attempt sent on the wire (incl. failed/retried)
    responses:  int = 0      # attempts that got an HTTP response back
    cache_hits: int = 0
    coalesced:  int = 0
    retries:    int = 0
    errors:     int = 0
    blocked:    int = 0      # refused by the outbound-address policy
    bytes_in:   int = 0
    status_codes: dict[int, int] = field(default_factory=dict)
    total_time: float = 0.0

    def as_dict(self) -> dict:
        avg = (self.total_time / self.responses) if self.responses else 0.0
        return {
            "requests":     self.requests,
            "responses":    self.responses,
            "cache_hits":   self.cache_hits,
            "coalesced":    self.coalesced,
            "retries":      self.retries,
            "errors":       self.errors,
            "blocked":      self.blocked,
            "bytes_in":     self.bytes_in,
            "avg_latency_ms": round(avg * 1000, 1),
            "status_codes": {str(k): v for k, v in sorted(self.status_codes.items())},
        }


# ── a lightweight response object ───────────────────────────────────────────────

@dataclass
class Response:
    status:  int
    headers: dict
    body:    str
    url:     str = ""
    elapsed: float = 0.0
    # every Set-Cookie header — a plain dict keeps only one of them
    set_cookies: list[str] = field(default_factory=list)
    truncated: bool = False
    error:   str = ""

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
        max_body:     int = 2_000_000,
    ) -> None:
        self.session   = session
        self.bucket    = TokenBucket(rate_per_sec)
        self.max_retries = max_retries
        self.timeout   = timeout
        self.rotate_ua = rotate_ua
        self.default_ua = default_ua
        self.stats     = HTTPStats()
        self.max_body  = max_body
        self._cache: dict[str, Response] = {}
        self._inflight: dict[str, asyncio.Future] = {}

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
        if not cacheable:
            return await self._do_request(
                url, method, params, data, headers, allow_redirects
            )

        hit = self._cache.get(url)
        if hit is not None:
            self.stats.cache_hits += 1
            return hit
        pending = self._inflight.get(url)
        if pending is not None:
            # another module is already fetching this URL — share its result
            self.stats.coalesced += 1
            return await asyncio.shield(pending)

        fut: asyncio.Future = asyncio.get_running_loop().create_future()
        self._inflight[url] = fut
        try:
            resp = await self._do_request(url, "GET", None, None, None, True)
            # A URL that timed out will time out again for the next module: remember the failure
            # too, so one hanging endpoint costs one timeout per scan instead of one per module.
            if resp.ok or "Timeout" in resp.error:
                self._cache[url] = resp
            fut.set_result(resp)
            return resp
        except BaseException as exc:
            fut.set_exception(exc)
            fut.exception()   # mark retrieved so waiters-less futures don't warn
            raise
        finally:
            self._inflight.pop(url, None)

    def known_dead(self, url: str) -> bool:
        """This scan already saw `url` time out (plain GET) — per-URL checks on it would only wait again."""
        hit = self._cache.get(url)
        return hit is not None and not hit.ok

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
            current = urljoin(current, location)
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
            self.stats.requests += 1
            try:
                to = aiohttp.ClientTimeout(total=self.timeout)
                async with self.session.request(
                    method, url, params=params, data=data, headers=h,
                    timeout=to, allow_redirects=allow_redirects, ssl=False,
                ) as resp:
                    raw = await resp.content.read(self.max_body + 1)
                    truncated = len(raw) > self.max_body
                    raw = raw[: self.max_body]
                    body = _decode(raw, resp.charset)
                    elapsed = time.monotonic() - t0
                    self.stats.responses += 1
                    self.stats.bytes_in += len(raw)
                    self.stats.total_time += elapsed
                    self.stats.status_codes[resp.status] = (
                        self.stats.status_codes.get(resp.status, 0) + 1
                    )
                    return Response(
                        status=resp.status,
                        headers=dict(resp.headers),
                        body=body,
                        url=str(resp.url),
                        elapsed=elapsed,
                        set_cookies=resp.headers.getall("Set-Cookie", []),
                        truncated=truncated,
                    )
            except BlockedTarget as exc:
                last_exc = exc
                self.stats.blocked += 1
                break                      # policy decision — never retry
            except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                last_exc = exc
                if isinstance(getattr(exc, "os_error", None), BlockedTarget):
                    self.stats.blocked += 1
                    break
                attempt += 1
                if attempt <= self.max_retries:
                    self.stats.retries += 1
                    await asyncio.sleep(0.4 * (2 ** (attempt - 1)) + random.random() * 0.2)
                continue
            except (asyncio.CancelledError, KeyboardInterrupt):
                raise
            except Exception as exc:
                last_exc = exc
                break

        self.stats.errors += 1
        return Response(status=-1, headers={}, body="", url=url,
                        error=type(last_exc).__name__ if last_exc else "error")


def _decode(raw: bytes, charset: str | None) -> str:
    try:
        return raw.decode(charset or "utf-8", errors="replace")
    except LookupError:   # bogus charset in Content-Type
        return raw.decode("utf-8", errors="replace")
