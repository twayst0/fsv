"""FSV — Base scanner class every module extends."""

from __future__ import annotations
from abc import ABC, abstractmethod

from fsv.core.models import Finding, ScanConfig
from fsv.core.http_client import HTTPClient, Response


class BaseScanner(ABC):
    """
    Abstract base for all FSV scan modules.

    Subclasses set these class attributes:
        name     — unique module id (str)
        category — "passive" (no payloads) or "active" (sends test payloads)
        scope    — "site" (run once on base target) or "url" (run per crawled URL)

    and implement async scan(url) -> list[Finding].
    """

    name:     str = "base"
    category: str = "passive"
    scope:    str = "url"

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
