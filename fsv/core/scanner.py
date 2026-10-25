"""FSV — Base scanner class every module extends."""

from __future__ import annotations
import re
from abc import ABC, abstractmethod

from fsv.core.models import Finding, ScanConfig
from fsv.core.http_client import HTTPClient, Response


class BaseScanner(ABC):
    """
    Abstract base for all FSV scan modules.

    Subclasses set these class attributes — they are the single source of truth
    (the registry derives its catalogue from them):
        name        — unique module id (str)
        category    — "passive" (no payloads) or "active" (sends test payloads)
        scope       — "site" (run once on base target) or "url" (run per crawled URL)
        description — one-line summary of what the module checks
        external    — True if it sends requests to hosts other than the target

    and implement async scan(url) -> list[Finding].
    """

    name:        str  = "base"
    category:    str  = "passive"   # "passive" (no crafted payloads) | "active"
    scope:       str  = "url"       # "site" (once per scan) | "url" (per crawled URL)
    description: str  = ""          # one line, shown in CLI / dashboard / MCP
    external:    bool = False       # contacts hosts other than the target (e.g. cloud storage)

    def __init__(self, http: HTTPClient, scan_config: ScanConfig) -> None:
        self.http = http
        self.scan_config = scan_config

    @abstractmethod
    async def scan(self, url: str) -> list[Finding]:
        ...

    # ── helpers (unchanged interface for modules) ─────────────────────────

    async def fetch(
        self,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> tuple[int, dict, str]:
        """Fetch a URL. Returns (status_code, headers_dict, body_text)."""
        r = await self.fetch_response(url, method, params, data, headers, allow_redirects)
        return r.status, r.headers, r.body

    async def fetch_response(
        self,
        url: str,
        method: str = "GET",
        params: dict | None = None,
        data: dict | None = None,
        headers: dict | None = None,
        allow_redirects: bool = True,
    ) -> Response:
        """Like fetch() but returns the full Response (all Set-Cookie headers, timing…)."""
        # The session already carries scan_config.headers; only per-call
        # overrides are passed so plain GETs stay cacheable.
        return await self.http.request(
            url, method=method, params=params, data=data,
            headers=headers or None, allow_redirects=allow_redirects,
        )

    async def fetch_with_redirect_chain(self, url: str) -> list[tuple[int, str]]:
        return await self.http.redirect_chain(url)

    def _header(self, headers: dict, name: str) -> str | None:
        """Case-insensitive header lookup."""
        nl = name.lower()
        for k, v in headers.items():
            if k.lower() == nl:
                return v
        return None


def mask_secret(value: str, keep_start: int = 4, keep_end: int = 2) -> str:
    """
    'AKIAIOSFODNN7EXAMPLE'   → 'AKIA…************LE'
    "password = 'hunter22'"  → "password = 'hu******'"   (key kept, value masked)
    Enough to locate the leak, not to reuse it.
    """
    value = value.strip()
    kv = re.match(r"^([\w\-]+\s*[=:]\s*['\"]?)(.+?)(['\"]?)$", value)
    if kv and len(kv.group(2)) >= 4:
        return kv.group(1) + mask_secret(kv.group(2), 2, 0) + kv.group(3)
    if len(value) <= keep_start + keep_end + 2:
        return value[:2] + "*" * max(0, len(value) - 2)
    hidden = len(value) - keep_start - keep_end
    tail = value[-keep_end:] if keep_end else ""
    return f"{value[:keep_start]}…{'*' * min(hidden, 12)}{tail}"
