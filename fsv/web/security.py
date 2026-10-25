"""
FSV — Web server request guard
──────────────────────────────
The dashboard binds to loopback, but a loopback service is still reachable from
any web page the user has open. Without a guard, a malicious site could:

  • CSRF   — POST /api/scan from the victim's browser (a body with no
             Content-Type is a "simple" request: no CORS preflight), making the
             user's machine scan a third party under their name
  • DNS rebinding — point its own hostname at 127.0.0.1 and then read the API
             as "same origin"

This ASGI middleware covers HTTP and WebSocket and enforces:

  1. Host allowlist     — Host must be loopback, the bind address, or listed in
                          FSV_ALLOWED_HOSTS (defeats DNS rebinding)
  2. Origin check       — if a browser sends Origin / Sec-Fetch-Site, it must be
                          same-origin for anything that changes state, and for
                          every WebSocket handshake
  3. JSON-only writes   — POST/PUT/PATCH with a body must be application/json
                          (no simple-request CSRF)

Non-browser clients (CLI, curl, scripts) send no Origin and pass untouched.
"""

from __future__ import annotations
import json
from urllib.parse import urlparse

_LOOPBACK = {"127.0.0.1", "localhost", "::1", "[::1]"}
_WILDCARD = {"0.0.0.0", "::", "[::]", ""}
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def _split_host(value: str) -> str:
    """'example.com:7474' → 'example.com'; '[::1]:7474' → '::1'."""
    value = value.strip().lower()
    if value.startswith("["):
        return value[1:value.index("]")] if "]" in value else value
    return value.rsplit(":", 1)[0] if value.count(":") == 1 else value


def allowed_hosts(bind_host: str, extra: str) -> set[str] | None:
    """
    The set of acceptable Host names, or None for "accept any" — only when
    bound to a wildcard address with no explicit allowlist (start-up warns).
    """
    hosts = set(_LOOPBACK)
    extra_hosts = {h.strip().lower() for h in extra.split(",") if h.strip()}
    if "*" in extra_hosts:
        return None
    hosts |= extra_hosts
    if bind_host.lower() in _WILDCARD:
        return hosts if extra_hosts else None
    hosts.add(bind_host.lower())
    return hosts


class RequestGuard:
    def __init__(self, app, hosts: set[str] | None) -> None:
        self.app = app
        self.hosts = hosts

    async def __call__(self, scope, receive, send):
        if scope["type"] not in ("http", "websocket"):
            return await self.app(scope, receive, send)

        headers = {k.decode("latin-1").lower(): v.decode("latin-1")
                   for k, v in scope.get("headers", [])}
        host_hdr = headers.get("host", "")
        method = scope.get("method", "GET").upper()
        is_ws = scope["type"] == "websocket"

        problem = None
        if self.hosts is not None and _split_host(host_hdr) not in self.hosts:
            problem = (f"Host '{host_hdr}' is not allowed (DNS-rebinding protection). "
                       "Add it to FSV_ALLOWED_HOSTS if this is intended.")
        elif is_ws or method in _UNSAFE:
            origin = headers.get("origin")
            fetch_site = headers.get("sec-fetch-site", "")
            if origin and origin != "null":
                if urlparse(origin).netloc.lower() != host_hdr.lower():
                    problem = "Cross-origin request blocked."
            elif origin == "null":
                problem = "Cross-origin request blocked."
            if not problem and fetch_site in ("cross-site", "same-site"):
                problem = "Cross-site request blocked."
            has_body = (headers.get("content-length", "0") not in ("", "0")
                        or "transfer-encoding" in headers)
            if (not problem and not is_ws and method in ("POST", "PUT", "PATCH")
                    and has_body):
                ctype = headers.get("content-type", "").split(";")[0].strip().lower()
                if ctype != "application/json":
                    problem = "Request body must be application/json."

        if problem is None:
            return await self.app(scope, receive, send)

        if is_ws:
            # reject the handshake before accept (→ HTTP 403 to the client)
            await receive()            # websocket.connect
            await send({"type": "websocket.close", "code": 4403})
            return
        body = json.dumps({"detail": problem}).encode()
        await send({"type": "http.response.start", "status": 403,
                    "headers": [(b"content-type", b"application/json"),
                                (b"content-length", str(len(body)).encode())]})
        await send({"type": "http.response.body", "body": body})
