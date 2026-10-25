"""
FSV — shared page/script collection for content-analysis modules
────────────────────────────────────────────────────────────────
js_analysis, js_libs and cloud_storage all need "the page and its scripts".
They fetch through the shared HTTPClient (response cache + request coalescing),
so a script referenced from 50 pages is downloaded once no matter how many
modules or pages look at it.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from fsv.core.netsafety import registrable_domain

MAX_SCRIPTS_PER_PAGE = 25


@dataclass
class Script:
    url:     str
    body:    str
    same_site: bool
    truncated: bool = False


def is_html(headers: dict, body: str) -> bool:
    ctype = next((v for k, v in headers.items() if k.lower() == "content-type"), "").lower()
    return "html" in ctype or (not ctype and body.lstrip()[:15].lower().startswith(("<!doctype", "<html")))


def script_refs(html: str, base_url: str) -> tuple[list[str], list[str]]:
    """(external script URLs in document order, inline script bodies)."""
    try:
        soup = BeautifulSoup(html, "lxml")
    except Exception:
        return [], []
    urls: list[str] = []
    inline: list[str] = []
    for tag in soup.find_all("script"):
        src = tag.get("src")
        if src:
            full = urljoin(base_url, src.strip())
            if urlparse(full).scheme in ("http", "https"):
                urls.append(full.split("#")[0])
        elif tag.string and len(tag.string) > 20:
            inline.append(tag.string)
    return list(dict.fromkeys(urls)), inline


def same_site(url: str, page_url: str) -> bool:
    """Same registrable domain as the page (first-party code, incl. subdomains/CDN subdomains)."""
    a = registrable_domain(urlparse(url).hostname or "")
    b = registrable_domain(urlparse(page_url).hostname or "")
    if a and b:
        return a == b
    return (urlparse(url).netloc.lower() == urlparse(page_url).netloc.lower())


async def load_scripts(http, page_url: str, html: str, *, first_party_only: bool,
                       skip: set[str] | None = None) -> tuple[list[Script], list[str]]:
    """
    Fetch the page's external scripts (bounded). `skip` lets a module avoid
    re-analysing a script it already handled on another page. Returns
    (scripts, inline_script_bodies).
    """
    urls, inline = script_refs(html, page_url)
    out: list[Script] = []
    for u in urls[:MAX_SCRIPTS_PER_PAGE]:
        fp = same_site(u, page_url)
        if first_party_only and not fp:
            continue
        if skip is not None:
            if u in skip:
                continue
            skip.add(u)
        r = await http.request(u)
        if r.ok and r.status == 200 and r.body:
            out.append(Script(u, r.body, fp, getattr(r, "truncated", False)))
    return out, inline


_BUCKET_PATTERNS = [
    # (provider, regex with named groups)
    ("s3",    re.compile(r"(?i)\b(?P<name>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\.s3(?:[.\-](?P<region>[a-z0-9\-]+))?\.amazonaws\.com\b")),
    ("s3",    re.compile(r"(?i)\bs3(?:[.\-](?P<region>[a-z0-9\-]+))?\.amazonaws\.com/(?P<name>[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9])\b")),
    ("gcs",   re.compile(r"(?i)\b(?P<name>[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\.storage\.googleapis\.com\b")),
    ("gcs",   re.compile(r"(?i)\bstorage\.googleapis\.com/(?P<name>[a-z0-9][a-z0-9._\-]{1,61}[a-z0-9])\b")),
    ("azure", re.compile(r"(?i)\b(?P<name>[a-z0-9]{3,24})\.blob\.core\.windows\.net(?:/(?P<container>[a-z0-9\-]{3,63}))?")),
]
_NOT_BUCKETS = {"s3", "www", "storage", "console", "aws", "docs", "status"}


def find_bucket_refs(text: str) -> set[tuple[str, str, str | None]]:
    """(provider, bucket/account name, container-or-None) mentioned in `text`."""
    found: set[tuple[str, str, str | None]] = set()
    for provider, rx in _BUCKET_PATTERNS:
        for m in rx.finditer(text):
            name = m.group("name").lower()
            if name in _NOT_BUCKETS or name.startswith(("s3-", "s3.")):
                continue
            found.add((provider, name, (m.groupdict().get("container") or None)))
    return found
