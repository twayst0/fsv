"""
FSV Module — Reflected XSS (context-aware)

Not "does the payload appear?" but "where does the input land, and does it survive the characters that
matter *there*?" — HTML text needs `<`, a double-quoted attribute needs `"`, a JS string needs its quote.
A context-matched payload then confirms it, so a report means "this exact input ran as markup/script
in this exact spot". JSON echoes, comments and correctly escaped output are not reported.

Deep profile: also looks for hidden parameters (names the page reads that no link mentions) and tries
every payload shape for the context instead of the first.
"""

from __future__ import annotations
from urllib.parse import parse_qs, urlparse

from fsv.core import reflect as R
from fsv.core.content import is_html
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.probing import reflected_candidates, with_param
from fsv.core.scanner import BaseScanner

_CONTEXT_TEXT = {
    "html": "in HTML text, where `<` is not escaped",
    "attr-dq": "inside a double-quoted attribute, where `\"` is not escaped",
    "attr-sq": "inside a single-quoted attribute, where `'` is not escaped",
    "attr-unquoted": "inside an unquoted attribute value",
    "attr-new": "inside a tag, where it can start a new attribute",
    "url": "at the start of a link/URL attribute, so a `javascript:` URL can be supplied",
    "js-attr": "inside an inline event handler (it is already script)",
    "js-code": "in JavaScript code outside a string",
    "js-string-dq": "inside a double-quoted JavaScript string, where `\"` is not escaped",
    "js-string-sq": "inside a single-quoted JavaScript string, where `'` is not escaped",
    "js-string-bt": "inside a JavaScript template literal",
    "script-close": "inside a script block, where `<` is not escaped (`</script>` ends the block)",
}
_REFS = [
    "https://owasp.org/www-community/attacks/xss/",
    "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
    "https://cwe.mitre.org/data/definitions/79.html",
]


class XSSScanner(BaseScanner):
    name = "xss"
    category    = "active"
    scope       = "url"
    description = "Reflected XSS: context-aware (HTML, attribute, JS string), hidden parameters when deep"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._discovery: dict = {}

    async def scan(self, url: str) -> list[Finding]:
        names = list(parse_qs(urlparse(url).query, keep_blank_values=True))
        discovered: list[str] = []
        if self.deep:
            discovered = await reflected_candidates(self, url, self._discovery)
            names += [n for n in discovered if n not in names]
        findings: list[Finding] = []
        for param in names:
            f = await self._test_param(url, param, hidden=param in discovered)
            if f:
                findings.append(f)
        return findings

    async def _test_param(self, url: str, param: str, hidden: bool) -> Finding | None:
        probe_url = with_param(url, param, R.probe_for(param))
        r = await self.fetch_response(probe_url)
        if not r.ok or not r.body or not is_html(r.headers, r.body):
            return None                                   # a JSON/plain-text echo is not rendered as markup
        kinds = [k for k in (R.exploit_kind(x) for x in R.find_reflections(r.body, param)) if k]
        if not kinds:
            return None

        for kind in dict.fromkeys(kinds):                 # first context that can be confirmed
            for payload in R.payloads_for(kind, self.deep):
                test_url = with_param(url, param, payload)
                tr = await self.fetch_response(test_url)
                if tr.ok and tr.body and R.raw_in_context(tr.body, payload):
                    return self._finding(url, param, kind, payload, test_url, Confidence.FIRM, hidden)
        # the characters pass through, but every concrete payload was altered or blocked → worth a look, not a verdict
        kind = kinds[0]
        return self._finding(url, param, kind, R.payloads_for(kind, False)[0], probe_url, Confidence.TENTATIVE, hidden)

    def _finding(self, url, param, kind, payload, test_url, conf, hidden) -> Finding:
        where = _CONTEXT_TEXT[kind]
        link_only = kind == "url"
        confirmed = conf == Confidence.FIRM
        title = ("Reflected Input Controls a Link Target (javascript: URL)" if link_only
                 else "Reflected Cross-Site Scripting (XSS)")
        return Finding(
            title       = title,
            severity    = Severity.MEDIUM if (link_only or not confirmed) else Severity.HIGH,
            confidence  = conf,
            url         = url,
            module      = self.name,
            parameter   = param,
            description = (
                f"The `{param}` parameter is reflected {where}. "
                + ("A context-matched payload came back unmodified, so attacker-controlled input is interpreted as markup or script "
                   "in the victim's browser."
                   if confirmed else
                   "The characters needed to break out pass through unescaped, but the concrete payload we tried was altered or blocked "
                   "(a filter or WAF?). Filters are bypassable; the missing output encoding is the real bug.")
                + (" The parameter appears in no link — it was found by probing common names (deep scan)." if hidden else "")
            ),
            evidence    = (
                f"Parameter: {param}\n"
                f"Reflected: {where}\n"
                f"Payload: {payload}\n"
                f"Payload came back unmodified: {'YES' if confirmed else 'NO (characters unescaped, payload filtered)'}\n"
                f"Test URL: {test_url[:200]}"
            ),
            recommendation = (
                "1. Encode output for the context it lands in (HTML-encode text; quote and attribute-encode attribute values; "
                "JSON-encode into scripts) — a templating engine that auto-escapes does this.\n"
                "2. Add a strict Content-Security-Policy (no 'unsafe-inline') as a second layer.\n"
                "3. Validate input shape where you can (an id is digits).\n"
                "4. Never put user input in a `javascript:` capable URL attribute without an allow-list of schemes."
            ),
            references  = _REFS,
            cwe         = "CWE-79",
            cvss_score  = 6.1,
            extra       = {"payload": payload, "context": kind, "hidden_parameter": hidden},
        )
