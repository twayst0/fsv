"""Deterministic fakes: DNS zone + HTTP routes, so detection logic is tested without a network."""
from __future__ import annotations

from fsv.core import dnsutil
from fsv.core.dnsutil import Answer
from fsv.core.http_client import Response


class FakeDNS:
    """
    zone = {"example.com": {"TXT": ["v=spf1 -all"], "MX": ["10 mx.example.com"]},
            "blog.example.com": {"CNAME": ["old.github.io"]}}

    Unknown names are NXDOMAIN. A known name without the requested type is NODATA.
    Non-CNAME queries follow a CNAME exactly like a real resolver — so a name whose
    CNAME target is missing answers NXDOMAIN, which is what makes dangling aliases visible.
    """
    def __init__(self, zone: dict[str, dict[str, list[str]]], *, internet: bool = True):
        self.zone = {k.lower(): v for k, v in zone.items()}
        if internet:   # a working resolver knows the control names (see dnsutil.nxdomain_is_meaningful)
            self.zone.setdefault("iana.org", {"NS": ["a.iana-servers.net"]})
        self.queries: list[tuple[str, str]] = []

    def __call__(self, name: str, rtype: str, timeout: float) -> Answer:
        self.queries.append((name, rtype))
        return self._lookup(name, rtype, 0)

    def _lookup(self, name: str, rtype: str, depth: int) -> Answer:
        rec = self.zone.get(name)
        if rec is None:
            return Answer("nxdomain")
        if rtype in rec:
            return Answer("ok", tuple(rec[rtype]))
        if rtype != "CNAME" and "CNAME" in rec and depth < 8:
            return self._lookup(rec["CNAME"][0], rtype, depth + 1)
        return Answer("nodata")

    def install(self):
        dnsutil.set_backend(self)
        return self


class FakeHTTP:
    """routes: {url: (status, body[, headers])}. Unknown URLs → 404 empty body."""
    def __init__(self, routes: dict[str, tuple] | None = None):
        self.routes = routes or {}
        self.requested: list[str] = []

    async def request(self, url, method="GET", **kw) -> Response:
        self.requested.append(url)
        hit = self.routes.get(url)
        if hit is None:
            return Response(status=404, headers={}, body="", url=url)
        status, body, *rest = hit
        return Response(status=status, headers=(rest[0] if rest else {}), body=body, url=url)


def rsa_public_key_b64(bits: int) -> str:
    """
    Base64 SubjectPublicKeyInfo of an RSA *public* key with a `bits`-bit modulus.
    The modulus is an arbitrary odd number, not a real key pair (and `cryptography`
    refuses to generate sub-1024-bit keys) — we only need the size to be readable.
    """
    import base64
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    n = (1 << (bits - 1)) | 0xDEADBEEF | 1
    der = rsa.RSAPublicNumbers(65537, n).public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


class DynamicHTTP:
    """handler(url) -> (status, body[, headers]) — a tiny app whose answer depends on the query string."""
    def __init__(self, handler):
        self.handler = handler
        self.requested: list[str] = []

    async def request(self, url, method="GET", **kw) -> Response:
        self.requested.append(url)
        status, body, *rest = self.handler(url)
        return Response(status=status, headers=(rest[0] if rest else {}), body=body, url=url)


HTML = {"Content-Type": "text/html; charset=utf-8"}


def query(url: str) -> dict[str, str]:
    from urllib.parse import parse_qs, urlparse
    return {k: v[0] for k, v in parse_qs(urlparse(url).query, keep_blank_values=True).items()}
