"""
FSV — domain helpers and outbound-connection safety
───────────────────────────────────────────────────
  • registrable_domain()  — correct "example.co.uk" from "shop.example.co.uk"
                            (public-suffix list bundled with tldextract; no
                            network access at runtime)
  • is_blocked_address()  — loopback / private / link-local / metadata ranges
  • GuardedResolver       — aiohttp resolver that refuses blocked addresses on
                            *every* lookup, so it also covers redirects to
                            internal hosts and DNS-rebinding between the
                            pre-check and the connection

Why the resolver matters: when FSV is deployed as a shared service, "scan this
URL" is a request-forgery primitive — a target can 302 to
http://169.254.169.254/ (cloud metadata) or resolve to 10.x. Checking only the
user-supplied hostname is not enough.
"""

from __future__ import annotations
import ipaddress
import socket
from functools import lru_cache
from urllib.parse import urlparse

import aiohttp
from aiohttp.abc import AbstractResolver
from aiohttp.resolver import DefaultResolver
from yarl import URL


# ── registrable domain ────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _extractor():
    import tldextract
    # suffix_list_urls=() → use the snapshot shipped in the package, never fetch
    return tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None,
                                 include_psl_private_domains=True)


def is_ip_or_local(host: str) -> bool:
    """True for IP literals, localhost and mDNS/internal-only names."""
    if not host:
        return True
    host = host.strip("[]").lower()
    if host in ("localhost",) or host.endswith((".local", ".localhost", ".internal", ".lan")):
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def registrable_domain(host: str) -> str | None:
    """
    'shop.example.co.uk' → 'example.co.uk'. None for IPs / unknown suffixes.
    The old `".".join(host.split(".")[-2:])` returned 'co.uk' here and then
    checked SPF/DMARC on a public suffix.
    """
    host = (host or "").strip().strip(".").lower()
    if is_ip_or_local(host):
        return None
    try:
        r = _extractor()(host)
        dom = getattr(r, "top_domain_under_public_suffix", None) or r.registered_domain
    except Exception:
        dom = ""
    if dom:
        return dom
    parts = host.split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else None


# ── address policy ────────────────────────────────────────────────────────────

_ALWAYS_BLOCKED = [ipaddress.ip_network(n) for n in (
    "169.254.0.0/16",     # link-local incl. cloud metadata 169.254.169.254
    "fe80::/10",
    "fd00:ec2::/32",      # AWS IPv6 metadata
    "100.100.100.200/32", # Alibaba metadata
    "0.0.0.0/8",
)]


def is_blocked_address(addr: str, *, allow_private: bool) -> bool:
    """
    Cloud-metadata and link-local ranges are blocked unconditionally.
    Loopback / RFC1918 / ULA are blocked unless `allow_private`.
    """
    try:
        ip = ipaddress.ip_address(addr.split("%")[0])
    except ValueError:
        return True   # not an address we can reason about → refuse
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if any(ip in net for net in _ALWAYS_BLOCKED):
        return True
    if allow_private:
        return False
    return (ip.is_private or ip.is_loopback or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


class BlockedTarget(OSError):
    """Raised when a connection would go to a forbidden address."""


class GuardedResolver(AbstractResolver):
    """Resolve normally, then refuse if any answer is a forbidden address."""

    def __init__(self, allow_private: bool) -> None:
        self._inner = DefaultResolver()
        self.allow_private = allow_private

    async def resolve(self, host, port=0, family=socket.AF_INET):
        infos = await self._inner.resolve(host, port, family)
        for info in infos:
            if is_blocked_address(info["host"], allow_private=self.allow_private):
                raise BlockedTarget(
                    f"{host} resolves to {info['host']}, which FSV is configured "
                    "not to connect to (FSV_BLOCK_PRIVATE / metadata ranges)")
        return infos

    async def close(self) -> None:
        await self._inner.close()


def make_trace_config(allow_private: bool) -> aiohttp.TraceConfig:
    """
    aiohttp skips the resolver for IP *literals*, so `Location: http://169.254.169.254/`
    would sail through GuardedResolver. This hook checks the URL of the initial
    request and of every redirect hop.
    """
    def _check(url) -> None:
        host = (url.host or "").strip("[]")
        try:
            ipaddress.ip_address(host)
        except ValueError:
            return                       # a name: GuardedResolver handles it
        if is_blocked_address(host, allow_private=allow_private):
            raise BlockedTarget(f"connection to {host} is not allowed")

    async def on_start(session, ctx, params):
        _check(params.url)

    async def on_redirect(session, ctx, params):
        loc = params.response.headers.get("Location", "")
        _check(params.response.url.join(URL(loc)) if loc else params.url)

    tc = aiohttp.TraceConfig()
    tc.on_request_start.append(on_start)
    tc.on_request_redirect.append(on_redirect)
    return tc


def make_connector(limit: int, *, allow_private: bool) -> aiohttp.TCPConnector:
    """
    Always installs the guard: metadata/link-local are never reachable, and
    private ranges only when `allow_private` (the default for local use).
    """
    return aiohttp.TCPConnector(
        ssl=False, limit=limit, resolver=GuardedResolver(allow_private),
        use_dns_cache=False,   # a cached answer would bypass the per-lookup check
    )


def host_of_url(url: str) -> str:
    return (urlparse(url).hostname or "").lower()


async def check_target(url: str, *, allow_private: bool) -> None:
    """
    Pre-flight for the scan target (covers modules that open raw sockets, like
    the TLS analyzer, which bypass the aiohttp resolver). Raises BlockedTarget.
    """
    import asyncio
    host = host_of_url(url)
    if not host:
        raise BlockedTarget("target has no host")
    try:
        ipaddress.ip_address(host.strip("[]"))
        addrs = [host.strip("[]")]
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(
                host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return          # unresolvable → the scan itself will report that
        addrs = sorted({i[4][0] for i in infos})
    for a in addrs:
        if is_blocked_address(a, allow_private=allow_private):
            raise BlockedTarget(
                f"{host} → {a} is in a range FSV will not scan "
                "(cloud-metadata/link-local, or private while FSV_BLOCK_PRIVATE is set)")
