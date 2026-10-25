"""
FSV — Endpoint discovery beyond <a href>.

Modern sites hide most of their surface from a link-following crawler: single-page apps call
APIs from JavaScript, and the pages that matter most are often only in a sitemap or robots.txt.
These helpers turn those sources into crawl seeds. They are pure functions (text in, paths out) so
the engine stays the only place that makes requests.

Safety: a link a page *shows* is something a user clicks; a path pulled out of a script may be an
action the app only ever calls with POST (`/labs/start/…`, `/cart/clear`). Following it with GET
could still trigger it on a sloppy backend, so discovered paths that read like actions are dropped.
"""

from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

MAX_PER_SOURCE = 200

# path tokens that suggest a state change — never request these speculatively
_ACTION_WORDS = frozenset("""
    add approve cancel checkout clear create delete deploy destroy disable drop edit enable exec execute
    flush import install kill launch logoff logout pay purge reboot remove reset restart run save send
    set shutdown signout start stop submit sync toggle transfer truncate unsubscribe update upgrade upload
    vote wipe
""".split())

_STATIC_EXT = (".js", ".mjs", ".css", ".map", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
               ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".webm", ".pdf", ".zip", ".gz", ".wasm")

# a quoted absolute path: "/api/users", '/challenge/list-labs/', `/v1/items?x=1`
# (no whitespace, quotes, template placeholders or protocol-relative "//host")
_JS_PATH = re.compile(r"""["'`](/(?!/)[A-Za-z0-9_\-.~%/]*[A-Za-z0-9_\-~%/](?:\?[A-Za-z0-9_\-.~%&=]*)?)["'`]""")
_REGEXY = re.compile(r"[\^$()\[\]<>*+\\|{}]")


def is_action_path(path: str) -> bool:
    """True when any path segment (or its -/_ parts) is a state-changing verb."""
    tokens = re.split(r"[/_\-.]+", urlparse(path).path.lower())
    return any(t in _ACTION_WORDS for t in tokens)


def _keep(path: str) -> bool:
    p = urlparse(path).path.lower()
    return bool(p) and not p.endswith(_STATIC_EXT) and not is_action_path(path)


def _dedupe(paths) -> list[str]:
    return list(dict.fromkeys(paths))[:MAX_PER_SOURCE]


def js_routes(js: str) -> list[str]:
    """Absolute same-origin paths quoted in a script, minus assets and action-looking routes."""
    out = []
    for m in _JS_PATH.finditer(js or ""):
        path = m.group(1)
        if len(path) < 2 or len(path) > 200 or path.count("/") > 12:
            continue
        if _keep(path):
            out.append(path)
    return _dedupe(out)


def robots_entries(text: str) -> tuple[list[str], list[str]]:
    """(literal Allow/Disallow paths, Sitemap URLs) from robots.txt. Wildcard rules are skipped."""
    paths, maps = [], []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        key, _, val = line.partition(":")
        key, val = key.strip().lower(), val.strip()
        if key == "sitemap" and val.startswith(("http://", "https://")):
            maps.append(val)
        elif key in ("allow", "disallow") and val.startswith("/") and val != "/" \
                and "*" not in val and "$" not in val and _keep(val):
            paths.append(val)
    return _dedupe(paths), _dedupe(maps)


def sitemap_locs(xml: str) -> tuple[list[str], list[str]]:
    """(page URLs, nested sitemap URLs) from a sitemap or sitemap index."""
    try:
        soup = BeautifulSoup(xml or "", "xml")
    except Exception:
        return [], []
    nested = [loc.get_text(strip=True) for sm in soup.find_all("sitemap") for loc in sm.find_all("loc")]
    pages = [loc.get_text(strip=True) for u in soup.find_all("url") for loc in u.find_all("loc")]
    return _dedupe(pages), _dedupe(nested)


def django_debug_routes(html: str) -> list[str]:
    """
    A Django 404 page with DEBUG=True lists every URL pattern. Keep the literal ones
    (no converters or regex) as paths: the app has just told us where its pages are.
    """
    if "Django tried these URL patterns" not in (html or ""):
        return []
    soup = BeautifulSoup(html, "lxml")
    out = []
    for li in soup.select("ol li"):
        text = re.sub(r"\[name='[^']*'\]", " ", li.get_text(" "))
        pattern = "".join(text.split())
        if _REGEXY.search(pattern):
            continue
        path = "/" + pattern
        if _keep(path) or path == "/":
            out.append(path)
    return _dedupe(out)


def resolve(base: str, paths: list[str]) -> list[str]:
    return [urljoin(base, p) for p in paths]
