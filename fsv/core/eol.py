"""
FSV — end-of-life software lookup
─────────────────────────────────
Dated, offline table of when popular server-side products stopped receiving
security fixes. A static "PHP < 8 is EOL" rule rots the day PHP 8.0 and 8.1 go
out of support; a dated table with an injectable `today` does not.

Data is a curated snapshot of the vendors' published schedules (cross-check
https://endoflife.date/ for anything critical). Only *security-support end*
dates are used. Extend or override with FSV_EOL_FILE:

    {"php": {"8.2": "2026-12-31"}, "myproduct": {"1.0": "2024-01-01"}}
"""

from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass
from datetime import date

# product → {release cycle → end of security support}; None = still supported
EOL_DATES: dict[str, dict[str, str | None]] = {
    "php": {
        "5.6": "2018-12-31", "7.0": "2018-12-03", "7.1": "2019-12-01", "7.2": "2020-11-30",
        "7.3": "2021-12-06", "7.4": "2022-11-28", "8.0": "2023-11-26", "8.1": "2025-12-31",
        "8.2": "2026-12-31", "8.3": "2027-12-31", "8.4": "2028-12-31",
    },
    "apache": {"2.0": "2013-07-10", "2.2": "2017-12-31", "2.4": None},
    "iis": {"6.0": "2015-07-14", "7.0": "2020-01-14", "7.5": "2020-01-14",
            "8.0": "2023-10-10", "8.5": "2023-10-10", "10.0": None},
    "openssl": {"0.9.8": "2015-12-31", "1.0.0": "2015-12-31", "1.0.1": "2016-12-31",
                "1.0.2": "2019-12-31", "1.1.0": "2019-09-11", "1.1.1": "2023-09-11",
                "3.0": "2026-09-07"},
    "python": {"2.7": "2020-01-01", "3.5": "2020-09-30", "3.6": "2021-12-23", "3.7": "2023-06-27",
               "3.8": "2024-10-07", "3.9": "2025-10-31"},
    "drupal": {"6": "2016-02-24", "7": "2025-01-05", "8": "2021-11-02", "9": "2023-11-01"},
    "joomla": {"2": "2014-12-31", "3": "2023-08-17"},
}
DISPLAY = {"php": "PHP", "apache": "Apache httpd", "iis": "Microsoft IIS", "openssl": "OpenSSL",
           "python": "Python", "drupal": "Drupal", "joomla": "Joomla"}

def _load_user_file() -> None:
    path = os.getenv("FSV_EOL_FILE")
    if not path:
        return
    try:
        for prod, cycles in json.load(open(path, encoding="utf-8")).items():
            EOL_DATES.setdefault(prod.lower(), {}).update(cycles)
            DISPLAY.setdefault(prod.lower(), prod)
    except Exception:
        pass


_load_user_file()


@dataclass(frozen=True)
class EOLInfo:
    product: str
    version: str
    cycle:   str
    eol:     date
    years_past: float
    approx:  bool = False       # True: older than any release in the table; `eol` is an upper bound

    @property
    def label(self) -> str:
        return f"{DISPLAY.get(self.product, self.product)} {self.version}"


def _vt(v: str) -> tuple[int, ...]:
    """'1.0.2k' → (1, 0, 2): leading digits of each dotted component, stop at the first non-numeric one."""
    out = []
    for p in re.split(r"[.\-_]", v):
        m = re.match(r"\d+", p)
        if not m:
            break
        out.append(int(m.group()))
        if m.group() != p:          # a letter suffix ends the numeric part ("2k")
            break
    return tuple(out)


def check(product: str, version: str, today: date | None = None) -> EOLInfo | None:
    """EOLInfo if `product version` is past end of security support, else None."""
    today = today or date.today()
    cycles = EOL_DATES.get(product.lower())
    vt = _vt(version)
    if not cycles or not vt:
        return None
    # the release cycle is the LONGEST table key that prefixes the version
    # ("1.0.2k" → "1.0.2", "8.0.30" → "8.0", "7.98" → "7")
    matches = [k for k in cycles if _vt(k) and vt[:len(_vt(k))] == _vt(k)]
    approx = False
    if matches:
        cycle = max(matches, key=lambda k: len(_vt(k)))
        end = cycles[cycle]
        if end is None:
            return None
    else:
        oldest = min(cycles, key=_vt)
        if vt >= _vt(oldest):
            return None                                  # newer than anything listed: assume supported
        # older than every listed release: certainly EOL, exact date unknown → bound it
        cycle = ".".join(map(str, vt[:2]))
        end = min(d for d in cycles.values() if d)
        approx = True
    eol = date.fromisoformat(end)
    if eol > today:
        return None
    return EOLInfo(product.lower(), version, cycle, eol, round((today - eol).days / 365.25, 1), approx)


# header/meta extraction ------------------------------------------------------

_TOKEN = re.compile(r"(?i)\b(apache|php|openssl|python|microsoft-iis)/(\d+(?:\.\d+){1,3})")
_GENERATOR = re.compile(r"(?i)\b(drupal|joomla)!?\s+(\d+(?:\.\d+)*)")


def products_from(headers: dict[str, str], html: str = "") -> dict[str, tuple[str, str]]:
    """{product: (version, where)} disclosed by response headers / generator meta tag."""
    found: dict[str, tuple[str, str]] = {}
    for hname in ("Server", "X-Powered-By", "X-Generator", "Via"):
        val = next((v for k, v in headers.items() if k.lower() == hname.lower()), "")
        for m in _TOKEN.finditer(val):
            prod = {"microsoft-iis": "iis"}.get(m.group(1).lower(), m.group(1).lower())
            found.setdefault(prod, (m.group(2), f"{hname} header"))
        g = _GENERATOR.search(val)
        if g:
            found.setdefault(g.group(1).lower(), (g.group(2), f"{hname} header"))
    m = re.search(r'(?i)<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', html[:20000])
    if m:
        g = _GENERATOR.search(m.group(1))
        if g:
            found.setdefault(g.group(1).lower(), (g.group(2), "generator meta tag"))
    return found
