"""FSV — Base scanner class every module extends."""

from __future__ import annotations
from abc import ABC, abstractmethod

from fsv.core.models import Finding, ScanConfig
from fsv.core.http_client import HTTPClient


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
        h = {**self.scan_config.headers}
        if headers:
            h.update(headers)
        r = await self.http.request(
            url, method=method, params=params, data=data,
            headers=h or None, allow_redirects=allow_redirects,
        )
        return r.status, r.headers, r.body

    async def fetch_with_redirect_chain(self, url: str) -> list[tuple[int, str]]:
        return await self.http.redirect_chain(url)

    def _header(self, headers: dict, name: str) -> str | None:
        """Case-insensitive header lookup."""
        nl = name.lower()
        for k, v in headers.items():
            if k.lower() == nl:
                return v
        return None
