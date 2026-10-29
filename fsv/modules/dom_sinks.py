"""
FSV Module — DOM-based XSS & client-side message handling (static analysis)

A server-side scanner cannot run JavaScript, but it can read it. This looks, in the page's own inline scripts and
first-party bundles, for dangerous flows that never touch the server and so are invisible to every other check:

  • a URL-controlled source (location.hash / search / href, document.referrer, window.name, document.cookie) that
    reaches an HTML/script sink (innerHTML, document.write, eval, jQuery .html(), setTimeout("…")) → DOM XSS
  • a URL source assigned to location / window.open → DOM-based open redirect
  • message handlers (`addEventListener("message", …)`) that never look at `event.origin`
  • postMessage(…, "*") and `document.domain =`

Heuristic by nature: direct source→sink in one expression is FIRM; flows through a variable are TENTATIVE; code that
passes through a known sanitizer (DOMPurify, textContent, encodeURIComponent…) is skipped. Third-party libraries are not read.
"""

from __future__ import annotations
import re

from fsv.core.content import MAX_SCRIPTS_PER_PAGE, is_html, load_scripts
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

# what an attacker can set from outside the page. (Plain `location` / `location.pathname` are deliberately not sources:
# `location.href = "/login?next=" + location.pathname` is everywhere and harmless.)
SOURCE = (r"(?:location\.(?:hash|search|href)|document\.(?:URL|documentURI|referrer|cookie)|window\.name|URLSearchParams\s*\()")
REDIRECT_SOURCE = r"(?:location\.(?:hash|search)|document\.referrer|window\.name|URLSearchParams\s*\()"   # href is the page itself
_SOURCE_RX = re.compile(SOURCE)
_REDIRECT_SOURCE_RX = re.compile(REDIRECT_SOURCE)
_SANITIZER = re.compile(r"(?i)DOMPurify|sanitiz|escapeHtml|escape_html|encodeURIComponent|textContent|innerText|createTextNode|\.escape\(|xss\(|he\.encode")
_LIBRARY = re.compile(r"(?i)(?:^|[/._-])(?:jquery|jquery-?ui|bootstrap|angular|react|vue|lodash|underscore|moment|modernizr|polyfills?|popper|"
                      r"core-js|backbone|ember|d3|three|chart|highcharts|swiper|slick|select2|tinymce|ckeditor|vendor)[.\-0-9a-z]*\.js")
_ASSIGN = re.compile(r"(?:var|let|const)?\s*([A-Za-z_$][\w$]*)\s*=\s*([^;\n]{0,120})")

# (kind, title, severity, regex that finds the sink; the text after the match is what gets inspected)
_SINKS = [
    ("html", "innerHTML / outerHTML", re.compile(r"\.(?:innerHTML|outerHTML)\s*\+?=")),
    ("html", "insertAdjacentHTML", re.compile(r"\.insertAdjacentHTML\s*\(")),
    ("html", "document.write", re.compile(r"\bdocument\.write(?:ln)?\s*\(")),
    ("html", "jQuery .html()/.append()", re.compile(r"\.(?:html|append|prepend|after|before|replaceWith|wrap)\s*\(")),
    ("html", "jQuery selector from the URL", re.compile(r"\$\s*\(\s*(?=" + SOURCE + r")")),
    ("code", "eval / Function", re.compile(r"\b(?:eval\s*\(|new\s+Function\s*\()")),
    ("code", "setTimeout/setInterval with a string", re.compile(r"\bset(?:Timeout|Interval)\s*\(\s*(?=[\"'`]|[A-Za-z_$])")),
    ("redirect", "location / window.open", re.compile(r"(?:\blocation(?:\.href)?\s*=(?!=)|\blocation\.(?:replace|assign)\s*\(|\bwindow\.open\s*\()")),
]
_WINDOW = 220


def _slice(code: str, m: re.Match) -> str:
    seg = code[m.end(): m.end() + _WINDOW]
    cut = min([i for i in (seg.find(";"), seg.find("\n\n")) if i != -1] or [len(seg)])
    return code[m.start(): m.end() + cut]


def analyze_script(code: str, label: str) -> list[tuple[str, str, Confidence, str]]:
    """[(kind, sink label, confidence, snippet)] — at most one per (kind, sink)."""
    def taint(rx):
        return {m.group(1) for m in _ASSIGN.finditer(code) if rx.search(m.group(2)) and m.group(1) not in ("location", "href")}
    tainted = {"redirect": taint(_REDIRECT_SOURCE_RX)}
    tainted["html"] = tainted["code"] = taint(_SOURCE_RX)
    found: dict[tuple[str, str], tuple[str, str, Confidence, str]] = {}
    for kind, name, rx in _SINKS:
        src = _REDIRECT_SOURCE_RX if kind == "redirect" else _SOURCE_RX
        for m in rx.finditer(code):
            seg = _slice(code, m)
            if _SANITIZER.search(seg):
                continue
            after = seg[m.end() - m.start():]
            direct = bool(src.search(after))
            via_var = any(re.search(rf"(?<![\w$.]){re.escape(v)}(?![\w$])", after) for v in tainted[kind])
            if not (direct or via_var):
                continue
            key = (kind, name)
            if key not in found or (direct and found[key][2] != Confidence.FIRM):
                found[key] = (kind, name, Confidence.FIRM if direct else Confidence.TENTATIVE, re.sub(r"\s+", " ", seg)[:200])
    return list(found.values())


def analyze_messages(code: str) -> list[tuple[str, str]]:
    """[(kind, snippet)] for message handlers without an origin check, '*' targets, document.domain."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(r"""addEventListener\(\s*["']message["']\s*,|\bonmessage\s*=""", code):
        body = code[m.start(): m.start() + 700]
        if not re.search(r"\.origin\b|\borigin\s*[=!]==?", body):
            sink = any(rx.search(body) for _, _, rx in _SINKS[:6]) and re.search(r"\b(?:e|ev|event|msg|message)\.data\b", body)
            out.append(("message-sink" if sink else "message", re.sub(r"\s+", " ", body)[:160]))
            break
    m = re.search(r"""\.postMessage\([^)]{0,200},\s*["']\*["']\s*\)""", code)
    if m:
        out.append(("star", re.sub(r"\s+", " ", m.group(0))[:120]))
    m = re.search(r"\bdocument\.domain\s*=[^=]", code)
    if m:
        out.append(("domain", code[m.start(): m.start() + 60].replace("\n", " ")))
    return out


_COPY = {
    "html": ("DOM-Based XSS: URL Data Reaches an HTML Sink", Severity.HIGH,
             "Data the attacker controls through the URL (or referrer / window.name) is written into the page as HTML or script by `{sink}`. "
             "The server never sees this payload, so a WAF and every server-side scan miss it; one crafted link runs script in the victim's session.",
             "Write with `textContent` / `createTextNode`, or sanitise with DOMPurify before any HTML sink; never feed location.* into innerHTML, "
             "document.write, eval or jQuery's `$()`/`.html()`. Add a strict CSP with Trusted Types where supported."),
    "code": ("DOM-Based Code Injection: URL Data Reaches eval / setTimeout", Severity.HIGH,
             "Data from the URL reaches `{sink}`, which executes it as code.",
             "Remove eval/Function/string-timeouts; parse data with JSON.parse and pass functions, not strings, to setTimeout."),
    "redirect": ("DOM-Based Open Redirect", Severity.MEDIUM,
                 "A URL parameter decides where `{sink}` sends the browser, so a link on your domain can bounce victims to a phishing page.",
                 "Allow-list redirect targets (same-origin paths only) and reject anything with a scheme or `//`."),
}


class DOMSinksScanner(BaseScanner):
    name        = "dom_sinks"
    category    = "passive"
    scope       = "url"
    description = "DOM XSS & message handling: URL sources reaching innerHTML/eval/redirects, postMessage without origin check (static)"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._seen_scripts: set[str] = set()
        self._seen_inline: set[int] = set()

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not is_html(r.headers, r.body):
            return []
        scripts, inline = await load_scripts(self.http, url, r.body, first_party_only=True, skip=self._seen_scripts,
                                             limit=100 if self.full else MAX_SCRIPTS_PER_PAGE)
        units: list[tuple[str, str]] = []
        for body in inline:
            if hash(body) not in self._seen_inline:
                self._seen_inline.add(hash(body))
                units.append((f"inline script on {url}", body))
        units += [(s.url, s.body) for s in scripts if not _LIBRARY.search(s.url.split("?")[0].rsplit("/", 1)[-1] or s.url)]

        findings: list[Finding] = []
        for label, code in units:
            code = code[:400_000]
            for kind, sink, conf, snippet in analyze_script(code, label):
                title, sev, desc, rec = _COPY[kind]
                findings.append(Finding(
                    title=title, severity=sev, confidence=conf, url=url, module=self.name,
                    description=desc.format(sink=sink) + ("" if conf == Confidence.FIRM else
                                                          " (The value passes through a variable first — FSV cannot see whether it is sanitised in between; verify in the code.)"),
                    evidence=f"{label}\n{snippet}", recommendation=rec,
                    references=["https://owasp.org/www-community/attacks/DOM_Based_XSS",
                                "https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html"],
                    cwe="CWE-79" if kind != "redirect" else "CWE-601", cvss_score=6.1))
            for kind, snippet in analyze_messages(code):
                if kind in ("message", "message-sink"):
                    findings.append(Finding(
                        title="postMessage Handler Does Not Check the Sender's Origin",
                        severity=Severity.HIGH if kind == "message-sink" else Severity.MEDIUM, confidence=Confidence.TENTATIVE, url=url,
                        module=self.name,
                        description=("A `message` event handler never reads `event.origin`, so any page that can frame or open this one can send it commands or data"
                                     + (" — and the message data reaches an HTML/script sink." if kind == "message-sink" else ".")),
                        evidence=f"{label}\n{snippet}",
                        recommendation="Compare `event.origin` to an exact allow-list (`=== 'https://app.example'`) before touching `event.data`.",
                        references=["https://developer.mozilla.org/en-US/docs/Web/API/Window/postMessage#security_concerns"], cwe="CWE-346"))
                elif kind == "star":
                    findings.append(Finding(
                        title="postMessage Sent to Any Origin ('*')", severity=Severity.LOW, confidence=Confidence.TENTATIVE, url=url, module=self.name,
                        description="`postMessage(data, '*')` delivers the message to whatever page currently occupies the target window — data in it can leak.",
                        evidence=f"{label}\n{snippet}", recommendation="Pass the exact target origin instead of '*'.", cwe="CWE-345"))
                elif kind == "domain":
                    findings.append(Finding(
                        title="document.domain Is Being Relaxed", severity=Severity.LOW, confidence=Confidence.FIRM, url=url, module=self.name,
                        description="Setting `document.domain` weakens the same-origin policy between subdomains (and is deprecated): an XSS on any sibling "
                                    "subdomain becomes an XSS here.",
                        evidence=f"{label}\n{snippet}", recommendation="Use postMessage or CORS between subdomains instead.", cwe="CWE-346"))
        # one finding per (title, evidence-label) is enough; the engine merges identical fingerprints across pages
        return findings
