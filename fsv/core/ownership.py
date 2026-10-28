"""
FSV — proof of control for active scanning
──────────────────────────────────────────
A scanner that sends test payloads at any URL it is given is a tool for hurting
people as much as for protecting them. When FSV runs as a SHARED service (set
FSV_REQUIRE_VERIFICATION=1) it therefore applies the same rule bug-bounty
platforms and commercial scanners do:

    passive scans (read-only, public information)      → allowed against any public host
    scans that send payloads (balanced / aggressive)   → only against hosts whose
                                                         owner has proven control
    loopback / private-network targets                 → exempt (local development)

Proof is one of
    DNS   a TXT record   _fsv-challenge.<domain>  =  "fsv-verify=<token>"   (covers subdomains)
    HTTP  a file         http(s)://<host>/.well-known/fsv-verification.txt   containing the token

The token is an HMAC of the domain under a per-installation secret, so it cannot
be computed for a domain by anyone but this installation — you can't copy
someone else's token to "verify" a domain you don't control.
"""

from __future__ import annotations
import asyncio
import hashlib
import hmac
import ipaddress
import secrets
import socket
from datetime import datetime, timedelta, timezone

import aiohttp

from fsv.core import dnsutil
from fsv.core.netsafety import (
    host_of_url, is_blocked_address, make_connector, make_trace_config,
    registrable_domain,
)

VALID_DAYS = 90
WELL_KNOWN = "/.well-known/fsv-verification.txt"
DNS_LABEL = "_fsv-challenge"


class OwnershipRequired(Exception):
    pass


def new_secret() -> str:
    return secrets.token_hex(32)


def token_for(domain: str, secret: str) -> str:
    return hmac.new(secret.encode(), domain.lower().encode(), hashlib.sha256).hexdigest()[:32]


def verification_domain(host: str) -> str:
    """The name a challenge is issued for: the registrable domain (DNS covers subdomains)."""
    return registrable_domain(host) or host.lower()


def instructions(host: str, secret: str) -> dict:
    dom = verification_domain(host)
    tok = token_for(dom, secret)
    return {
        "host": host, "domain": dom, "token": f"fsv-verify={tok}",
        "dns":  {"name": f"{DNS_LABEL}.{dom}", "type": "TXT", "value": f"fsv-verify={tok}",
                 "covers": f"{dom} and all of its subdomains"},
        "http": {"url": f"https://{host}{WELL_KNOWN}", "body": f"fsv-verify={tok}",
                 "covers": host},
    }


async def check_proof(host: str, secret: str, timeout: float = 8.0,
                      netloc: str | None = None) -> str | None:
    """'dns' / 'http' if control is proven right now, else None. `netloc` = host[:port] for the HTTP probe."""
    dom = verification_domain(host)
    want = f"fsv-verify={token_for(dom, secret)}"

    ans = await dnsutil.aresolve(f"{DNS_LABEL}.{dom}", "TXT", 4.0)
    if any(want == t.strip() for t in ans.records):
        return "dns"

    for scheme in ("https", "http"):
        try:
            async with aiohttp.ClientSession(
                connector=make_connector(2, allow_private=True),
                trace_configs=[make_trace_config(True)],
                timeout=aiohttp.ClientTimeout(total=timeout),
            ) as s:
                # no redirects: a proof must be served by the host itself, not bounced elsewhere
                async with s.get(f"{scheme}://{netloc or host}{WELL_KNOWN}", allow_redirects=False) as r:
                    if r.status == 200 and want == (await r.content.read(512)).decode("utf-8", "replace").strip():
                        return "http"
        except Exception:
            continue
    return None


async def is_local_target(url: str) -> bool:
    """True when every address the host resolves to is loopback / private (local development)."""
    host = host_of_url(url).strip("[]")
    try:
        addrs = [host] if ipaddress.ip_address(host) else []
    except ValueError:
        try:
            infos = await asyncio.get_running_loop().getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return False
        addrs = sorted({i[4][0] for i in infos})
    return bool(addrs) and all(is_blocked_address(a, allow_private=False) for a in addrs)


def expired(verified_at: str) -> bool:
    try:
        return datetime.fromisoformat(verified_at) < datetime.now(timezone.utc) - timedelta(days=VALID_DAYS)
    except ValueError:
        return True


def covers(record_domain: str, method: str, host: str) -> bool:
    """Does a stored verification for `record_domain` cover `host`?"""
    host, record_domain = host.lower(), record_domain.lower()
    if method == "dns":
        return host == record_domain or host.endswith("." + record_domain)
    return host == record_domain          # an HTTP proof only proves the exact host


def refusal_message(host: str, info: dict) -> str:
    return (f"Ownership of '{host}' is not verified. This FSV instance only sends test payloads to "
            "hosts whose owner has proven control (passive scans need no proof).\n"
            f"  DNS : add TXT  {info['dns']['name']}  =  \"{info['dns']['value']}\"   (covers {info['dns']['covers']})\n"
            f"  HTTP: serve    {info['http']['url']}  containing  {info['http']['body']}\n"
            f"Then run `fsv verify {host} --check` (or POST /api/verify/check).")
