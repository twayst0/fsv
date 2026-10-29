"""
FSV — shared helpers for modules that test URL parameters.

`reflected_candidates` is the "hidden parameter" search used by the deep profile: pages often read parameters
no link ever mentions (`?q=`, `?lang=`, `?redirect=`). One request carries a unique canary for each of ~15 common names;
the names whose canary comes back are parameters the page really reads, and those are worth testing.
Canaries are deterministic, so xss / ssti (and any later module) share the same cached requests.
"""

from __future__ import annotations
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from fsv.core.content import is_html
from fsv.core.reflect import CHUNK, candidate_names, canary_for, reflected_names


def with_param(url: str, name: str, value: str) -> str:
    """`url` with query parameter `name` set to `value` (other parameters kept, order kept)."""
    p = urlparse(url)
    q = {k: v[0] for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    q[name] = value
    return urlunparse(p._replace(query=urlencode(q)))


async def reflected_candidates(scanner, url: str, memo: dict) -> list[str]:
    """Common parameter names this page reads and echoes (deep profile). Memoised per path."""
    p = urlparse(url)
    key = (p.netloc, p.path)
    if key in memo:
        return memo[key]
    existing = {k: v[0] for k, v in parse_qs(p.query, keep_blank_values=True).items()}
    found: list[str] = []
    names = candidate_names(list(existing), full=getattr(scanner, "full", False))
    step = 30 if getattr(scanner, "full", False) else CHUNK          # ~3.5 KB of query string at most: servers accept ≥ 8 KB
    for i in range(0, len(names), step):
        chunk = names[i:i + step]
        query = {**existing, **{n: canary_for(n) for n in chunk}}
        r = await scanner.fetch_response(urlunparse(p._replace(query=urlencode(query))))
        if r.ok and r.status == 200 and r.body and is_html(r.headers, r.body):
            found += reflected_names(r.body, chunk)
    memo[key] = found
    return found
