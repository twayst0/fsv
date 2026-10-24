"""
FSV Module — Vulnerable & End-of-Life JavaScript Libraries
──────────────────────────────────────────────────────────
Retire.js-style: find library versions in the scripts a page loads (filename,
CDN path, or the banner comment in the file) and compare them with known
advisories. Third-party CDN scripts are included — a vulnerable jQuery is just as
exploitable when it is loaded from cdnjs.

The advisory table below is a small curated, offline starter set — it is not a
substitute for a full SCA tool. Extend it without touching code:

    FSV_ADVISORY_FILE=/path/advisories.json
    [{"lib": "jquery", "ids": ["CVE-…"], "severity": "high", "summary": "…",
      "ranges": [["1.0.0", "3.5.0"]], "fix": "3.7.1", "eol": false}]

A match means "this version is inside an affected range" — not that the
vulnerable code path is reachable on this site. Findings say so.
"""

from __future__ import annotations
import json
import os
import re
from dataclasses import dataclass
from urllib.parse import urlparse

from fsv.core.content import MAX_SCRIPTS_PER_PAGE, is_html, script_refs
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner


Version = tuple[int, ...]


def parse_version(s: str) -> Version:
    parts = []
    for p in re.split(r"[.\-+]", s.strip().lstrip("vV")):
        if not p.isdigit():
            break
        parts.append(int(p))
    return tuple(parts) or (0,)


def _cmp(a: Version, b: Version) -> int:
    n = max(len(a), len(b), 3)
    a2, b2 = a + (0,) * (n - len(a)), b + (0,) * (n - len(b))
    return (a2 > b2) - (a2 < b2)


@dataclass(frozen=True)
class Advisory:
    ids:      tuple[str, ...]
    severity: Severity
    summary:  str
    ranges:   tuple[tuple[Version, Version], ...]    # [lo, hi) — lo inclusive, hi exclusive
    fix:      str = ""
    eol:      bool = False

    def affects(self, v: Version) -> bool:
        return any(_cmp(v, lo) >= 0 and _cmp(v, hi) < 0 for lo, hi in self.ranges)


def _adv(ids, sev, summary, ranges, fix="", eol=False) -> Advisory:
    return Advisory(tuple(ids), Severity(sev), summary,
                    tuple((parse_version(a), parse_version(b)) for a, b in ranges), fix, eol)


DISPLAY = {"jquery": "jQuery", "jqueryui": "jQuery UI", "bootstrap": "Bootstrap",
           "angularjs": "AngularJS", "lodash": "Lodash", "moment": "Moment.js",
           "underscore": "Underscore.js", "vue": "Vue.js", "dompurify": "DOMPurify",
           "axios": "axios"}

ADVISORIES: dict[str, list[Advisory]] = {
    "jquery": [
        _adv(["CVE-2020-11022", "CVE-2020-11023"], "medium",
             "XSS: HTML containing <option>/<style> elements passed to .html(), .append() etc. "
             "can bypass sanitisation", [("1.2.0", "3.5.0")], "3.7.1"),
        _adv(["CVE-2019-11358"], "medium",
             "Prototype pollution via jQuery.extend(true, …)", [("0", "3.4.0")], "3.7.1"),
        _adv(["CVE-2015-9251"], "medium",
             "XSS: cross-domain Ajax responses served as text/javascript are executed",
             [("0", "3.0.0")], "3.7.1"),
        _adv(["CVE-2012-6708"], "medium",
             "XSS: jQuery(strInput) can interpret attacker-controlled strings (e.g. location.hash) as HTML",
             [("0", "1.9.0")], "3.7.1"),
    ],
    "jqueryui": [
        _adv(["CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184"], "medium",
             "XSS via the altField, *Text and `of` options", [("0", "1.13.0")], "1.13.2"),
        _adv(["CVE-2016-7103"], "medium", "XSS via the dialog closeText option",
             [("0", "1.12.0")], "1.13.2"),
    ],
    "bootstrap": [
        _adv(["CVE-2019-8331"], "medium", "XSS in tooltip/popover data-template",
             [("0", "3.4.1"), ("4.0.0", "4.3.1")], "5.3.x"),
        _adv(["CVE-2018-14040", "CVE-2018-14041", "CVE-2018-14042"], "medium",
             "XSS in collapse data-parent, scrollspy data-target and tooltip data-container",
             [("0", "3.4.0"), ("4.0.0", "4.1.2")], "5.3.x"),
        _adv([], "low", "Bootstrap 3 and 4 are end-of-life and no longer receive security fixes",
             [("0", "5.0.0")], "5.3.x", eol=True),
    ],
    "angularjs": [
        _adv([], "medium",
             "AngularJS 1.x reached end-of-life on 2022-01-01: no further security fixes, and its "
             "template-expression model has a long history of XSS/sandbox escapes",
             [("1.0.0", "2.0.0")], "migrate to a maintained framework", eol=True),
        _adv(["CVE-2020-7676"], "medium",
             "XSS: regex-based HTML sanitisation can turn sanitised markup back into active markup",
             [("0", "1.8.0")], "1.8.3 (EOL — migrate)"),
        _adv(["CVE-2019-10768"], "medium", "Prototype pollution via angular.merge()",
             [("0", "1.7.9")], "1.8.3 (EOL — migrate)"),
    ],
    "lodash": [
        _adv(["CVE-2021-23337"], "high", "Command injection via _.template() with attacker-influenced options",
             [("0", "4.17.21")], "4.17.21"),
        _adv(["CVE-2020-8203"], "high", "Prototype pollution in _.zipObjectDeep",
             [("0", "4.17.19")], "4.17.21"),
        _adv(["CVE-2019-10744"], "high", "Prototype pollution in _.defaultsDeep",
             [("0", "4.17.12")], "4.17.21"),
    ],
    "moment": [
        _adv(["CVE-2022-31129"], "high",
             "ReDoS: parsing a crafted long date string can block the thread for a very long time",
             [("2.18.0", "2.29.4")], "2.30.1 (or migrate to Luxon/date-fns)"),
    ],
    "underscore": [
        _adv(["CVE-2021-23358"], "high", "Code injection via the _.template variable option",
             [("1.3.2", "1.12.1")], "1.13.x"),
    ],
    "vue": [
        _adv([], "low", "Vue 2 reached end-of-life on 2023-12-31 and no longer receives security fixes",
             [("2.0.0", "3.0.0")], "Vue 3", eol=True),
    ],
    "dompurify": [
        _adv(["CVE-2024-45801"], "medium",
             "Sanitiser bypass: nesting-depth check can be circumvented, leading to XSS",
             [("0", "2.5.4"), ("3.0.0", "3.1.3")], "latest 3.x"),
    ],
    "axios": [
        _adv(["CVE-2021-3749"], "high", "ReDoS in the trim function", [("0", "0.21.2")], "1.x latest"),
        _adv(["CVE-2023-45857"], "medium",
             "XSRF-TOKEN cookie value leaked to third-party hosts in a request header",
             [("0.8.1", "0.28.0"), ("1.0.0", "1.6.0")], "1.6+ latest"),
    ],
}


def _load_extra_advisories() -> None:
    path = os.getenv("FSV_ADVISORY_FILE")
    if not path:
        return
    try:
        for row in json.load(open(path, encoding="utf-8")):
            ADVISORIES.setdefault(row["lib"].lower(), []).append(
                _adv(row.get("ids", []), row.get("severity", "medium"), row["summary"],
                     row["ranges"], row.get("fix", ""), bool(row.get("eol"))))
            DISPLAY.setdefault(row["lib"].lower(), row["lib"])
    except Exception:
        pass     # a bad user file must never break scanning


_load_extra_advisories()


# ── detection ─────────────────────────────────────────────────────────────────

_VER = r"(\d+\.\d+(?:\.\d+)?)"
_NAMES = {   # library → names it appears under in file/CDN paths
    "jquery": ["jquery"], "jqueryui": ["jquery-ui", "jqueryui"],
    "bootstrap": ["bootstrap"], "angularjs": ["angular", "angularjs", "angular\\.js"],
    "lodash": ["lodash", "lodash\\.js"], "moment": ["moment", "moment\\.js"],
    "underscore": ["underscore", "underscore\\.js"], "vue": ["vue", "vue\\.js"],
    "dompurify": ["dompurify", "purify"], "axios": ["axios"],
}
_URL_RX: dict[str, list[re.Pattern]] = {}
for _lib, _names in _NAMES.items():
    _URL_RX[_lib] = []
    for _n in _names:
        _URL_RX[_lib] += [re.compile(rf"(?i)/{_n}@{_VER}(?:/|$|\b)"),
                          re.compile(rf"(?i)/{_n}/{_VER}/"),
                          re.compile(rf"(?i)/{_n}[-.]{_VER}(?:\.min|\.slim|\.bundle|\.esm|\.js)")]

_BANNER_RX: dict[str, re.Pattern] = {
    "jquery":     re.compile(r"jQuery(?: JavaScript Library)? v(\d+\.\d+\.\d+)"),
    "jqueryui":   re.compile(r"jQuery UI(?: -)? v?(\d+\.\d+\.\d+)"),
    "bootstrap":  re.compile(r"Bootstrap(?: v| )(\d+\.\d+\.\d+)"),
    "angularjs":  re.compile(r"AngularJS v(\d+\.\d+\.\d+)"),
    "lodash":     re.compile(r"(?i)lodash(?:\.js)?\s+(?:v|version\s*)?(\d+\.\d+\.\d+)"),
    "moment":     re.compile(r"moment\.js[\s\S]{0,60}?version\s*:\s*(\d+\.\d+\.\d+)", re.I),
    "underscore": re.compile(r"Underscore\.js (\d+\.\d+\.\d+)"),
    "vue":        re.compile(r"Vue\.js v(\d+\.\d+\.\d+)"),
    "dompurify":  re.compile(r"DOMPurify (\d+\.\d+\.\d+)"),
    "axios":      re.compile(r"axios v(\d+\.\d+\.\d+)"),
}


def detect_libraries(script_url: str, body: str) -> dict[str, tuple[str, str]]:
    """{lib: (version, how)} found from the URL and the file's leading comment banner."""
    found: dict[str, tuple[str, str]] = {}
    path = urlparse(script_url).path
    for lib, rxs in _URL_RX.items():
        for rx in rxs:
            m = rx.search(path)
            if m:
                found[lib] = (m.group(1), "file/CDN path")
                break
    head = body[:6000]
    for lib, rx in _BANNER_RX.items():
        m = rx.search(head)
        if m and lib not in found:
            found[lib] = (m.group(1), "banner comment")
    # a jquery-ui file also carries a jQuery mention; don't let URL pattern for
    # "jquery" claim "jquery-ui-1.12.1.js" — the regexes above already require a digit
    return found


def assess(lib: str, version: str) -> list[Advisory]:
    v = parse_version(version)
    return [a for a in ADVISORIES.get(lib, []) if a.affects(v)]


# ── module ────────────────────────────────────────────────────────────────────

_RANK = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}


class JSLibsScanner(BaseScanner):
    name        = "js_libs"
    category    = "passive"
    scope       = "url"
    description = "Known-vulnerable and end-of-life JavaScript libraries (jQuery, Bootstrap, AngularJS, Lodash, …) from script URLs/banners"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._seen_scripts: set[str] = set()
        self._reported: set[tuple[str, str]] = set()

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not is_html(r.headers, r.body):
            return []
        urls, _ = script_refs(r.body, url)
        out: list[Finding] = []
        for sc_url in urls[:MAX_SCRIPTS_PER_PAGE]:
            if sc_url in self._seen_scripts:
                continue
            self._seen_scripts.add(sc_url)
            # 1) the version is often in the URL itself (…/jquery/3.3.1/jquery.min.js,
            #    …/bootstrap@3.3.7/…): no download needed — which also means no request
            #    to a third-party CDN just to read a file name
            found = detect_libraries(sc_url, "")
            # 2) otherwise read the banner comment at the top of the file
            if not found:
                f = await self.http.request(sc_url)
                if f.ok and f.status == 200 and f.body:
                    found = detect_libraries(sc_url, f.body)
            for lib, (version, how) in found.items():
                if (lib, version) in self._reported:
                    continue
                advs = assess(lib, version)
                if not advs:
                    continue
                self._reported.add((lib, version))
                out.append(self._finding(sc_url, lib, version, how, advs))
        return out

    def _finding(self, script_url: str, lib: str, version: str, how: str, advs: list[Advisory]) -> Finding:
        name = DISPLAY.get(lib, lib)
        top = max(advs, key=lambda a: _RANK[a.severity])
        only_eol = all(a.eol for a in advs)
        title = (f"End-of-Life JavaScript Framework: {name} {version}" if only_eol
                 else f"Vulnerable JavaScript Library: {name} {version}")
        lines = []
        for a in advs:
            tag = ", ".join(a.ids) if a.ids else ("end-of-life" if a.eol else "advisory")
            lines.append(f"• {tag} — {a.summary}")
        fixes = sorted({a.fix for a in advs if a.fix})
        cves = [i for a in advs for i in a.ids]
        return Finding(
            title=title, severity=top.severity, confidence=Confidence.FIRM, url=script_url,
            module=self.name,
            description=(
                f"{name} {version} (detected from the {how}) falls inside the affected range of "
                f"{len(advs)} known advisor{'y' if len(advs) == 1 else 'ies'}. That tells you the "
                "version is exposed, not that the vulnerable code path is reachable here — but "
                "attackers scan for exactly these versions."),
            evidence=f"{script_url}\n" + "\n".join(lines),
            recommendation=(f"Upgrade {name} to a fixed release ({', '.join(fixes) or 'latest'}), "
                            "or remove it if unused. Pin versions and add dependency scanning "
                            "(e.g. `npm audit`, OSV-Scanner, Dependabot) to CI."),
            references=[f"https://nvd.nist.gov/vuln/detail/{c}" for c in cves[:4]] + ["https://osv.dev/"],
            cwe="CWE-1104" if only_eol else "CWE-1395",
            extra={"library": lib, "version": version, "cves": cves})
