"""
FSV — DNS access layer
──────────────────────
One narrow function, `resolve(name, rtype) -> Answer`, that distinguishes the
cases the old code collapsed into "no record":

    ok        — records returned
    nodata    — the name exists but has no record of this type
    nxdomain  — the name does not exist  (this is what exposes dangling records)
    error     — timeout / SERVFAIL / resolver trouble (do NOT conclude anything)

Keeping NXDOMAIN separate from "no data" and from "error" is the foundation for
detecting dangling CNAMEs, dead SPF includes and broken delegations without
false alarms when the network is merely flaky.

The backend is swappable (`set_backend`) so modules are unit-tested with a
deterministic fake instead of the live DNS.
"""

from __future__ import annotations
import asyncio
from dataclasses import dataclass, field
from typing import Callable

try:
    import dns.exception
    import dns.resolver
    import dns.rdatatype
    HAVE_DNS = True
except Exception:                                   # pragma: no cover
    HAVE_DNS = False


@dataclass(frozen=True)
class Answer:
    status:  str                                    # ok | nodata | nxdomain | error
    records: tuple[str, ...] = field(default_factory=tuple)

    @property
    def ok(self) -> bool:
        return self.status == "ok"

    @property
    def nxdomain(self) -> bool:
        return self.status == "nxdomain"


Backend = Callable[[str, str, float], Answer]


def _norm(name: str) -> str:
    return name.strip().rstrip(".").lower()


def _dnspython_backend(name: str, rtype: str, timeout: float) -> Answer:
    if not HAVE_DNS:
        return Answer("error")
    r = dns.resolver.Resolver()
    r.lifetime = r.timeout = timeout
    try:
        ans = r.resolve(name, rtype)
    except dns.resolver.NXDOMAIN:
        return Answer("nxdomain")
    except dns.resolver.NoAnswer:
        return Answer("nodata")
    except dns.resolver.NoNameservers:
        return Answer("error")
    except (dns.exception.Timeout, dns.exception.DNSException, OSError):
        return Answer("error")

    out: list[str] = []
    for rd in ans:
        if rtype == "TXT":
            out.append("".join(s.decode("utf-8", "replace") if isinstance(s, bytes) else s
                               for s in rd.strings))
        elif rtype in ("CNAME", "NS", "PTR"):
            out.append(_norm(rd.target.to_text()))
        elif rtype == "MX":
            out.append(f"{rd.preference} {_norm(rd.exchange.to_text())}")
        else:
            out.append(rd.to_text())
    return Answer("ok", tuple(out))


_backend: Backend = _dnspython_backend


def set_backend(fn: Backend | None) -> None:
    """Install a fake backend (tests) or restore the real one with None."""
    global _backend
    _backend = fn or _dnspython_backend


def resolve(name: str, rtype: str, timeout: float = 3.0) -> Answer:
    """Blocking lookup. Call via `aresolve` from async code."""
    return _backend(_norm(name), rtype.upper(), timeout)


async def aresolve(name: str, rtype: str, timeout: float = 3.0) -> Answer:
    return await asyncio.to_thread(resolve, name, rtype, timeout)


def exists(name: str, timeout: float = 3.0) -> Answer:
    """
    Does the name resolve? NXDOMAIN is a property of the *name*, so the first
    definitive answer wins:  ok → resolves,  nxdomain → gone,  nodata → the name
    exists but carries no A record (e.g. only TXT/MX). Only transient errors
    fall through to the next record type; all-errors stays "error".

    Note: an A lookup follows CNAMEs, so a name whose CNAME *target* is gone
    reports nxdomain here even though the CNAME itself exists — which is exactly
    the dangling-record signal. Query CNAME explicitly to see the alias itself.
    """
    for rt in ("A", "AAAA", "CNAME"):
        a = resolve(name, rt, timeout)
        if a.status in ("ok", "nxdomain"):
            return a
        if a.status == "nodata" and rt == "A":
            # no A: could still be IPv6-only; AAAA decides
            continue
        if a.status == "nodata":
            return Answer("nodata")
    return Answer("error")
