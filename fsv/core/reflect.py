"""
FSV — reflection analysis: where does an input come back, and can it break out of that spot?
─────────────────────────────────────────────────────────────────────────────────────────────
"The payload appears in the response" is not XSS. It is harmless inside a JSON body, inside an
HTML comment, or inside a quoted attribute whose quote was escaped; it is dangerous in HTML text
when `<` survives, in a double-quoted attribute when `"` survives, in a JS string when the quote
survives. Telling these apart is what separates a finding from noise — and it finds what a fixed
payload list misses (an attribute that only needs `"`, a script block that only needs `;`).

Method (benign, one request per parameter):
  1. send  <t1>"'<><t2>   — two unique alphanumeric tokens around the four characters that matter
  2. find every place <t1> comes back; classify the surrounding syntax (text / attribute value and
     its quote / script and its string state / comment / style / textarea-title)
  3. look at which of  " ' < >  came back *unescaped* at that spot
  4. a module then verifies with one context-matched payload before it reports

Pure functions: no network, fully unit-tested.
"""

from __future__ import annotations
import hashlib
import re
from dataclasses import dataclass, field

PROBE_CHARS = "\"'<>"
_URL_ATTRS = {"href", "src", "action", "formaction", "data", "poster", "xlink:href", "background", "ping"}
_RAW_ELEMENTS = ("script", "style", "textarea", "title")


@dataclass
class Reflection:
    context: str                    # text | attr | tag | script | script-string | style | rcdata | comment
    index: int
    raw: set[str] = field(default_factory=set)      # of  " ' < >  — which came back unescaped
    quote: str | None = None        # attr / script-string: the quote that encloses the value
    attr: str | None = None         # attr: attribute name (lower-case)
    at_value_start: bool = False    # attr: the input is the very beginning of the value (javascript: scheme possible)


# ── tokens ────────────────────────────────────────────────────────────────────

def tokens_for(name: str) -> tuple[str, str]:
    """Deterministic per parameter name, so identical probes are served from the HTTP cache."""
    h = hashlib.sha1(name.encode("utf-8", "replace")).hexdigest()[:8]
    return f"fsv{h}a", f"fsv{h}b"


def probe_for(name: str) -> str:
    t1, t2 = tokens_for(name)
    return f"{t1}{PROBE_CHARS}{t2}"


# ── syntax state at a position ────────────────────────────────────────────────

def _last_open_raw(head: str, tag: str) -> int:
    """Index of the last `<tag …>` that is still open at the end of `head`, else -1."""
    opens = [m.start() for m in re.finditer(rf"(?i)<{tag}(?=[\s/>])", head)]
    if not opens:
        return -1
    last = opens[-1]
    closes = [m.start() for m in re.finditer(rf"(?i)</{tag}\s*>", head)]
    return last if not closes or closes[-1] < last else -1


def _lex_tag(body: str, start: int, pos: int) -> dict | None:
    """
    Lex the start tag beginning at `start` up to `pos`. None when the tag closed before `pos`
    (so `pos` is plain text); otherwise where in the tag `pos` falls.
    """
    i, n = start + 1, pos
    while i < n and body[i] not in " \t\r\n/>":
        i += 1
    while i < n:
        ch = body[i]
        if ch in " \t\r\n/":
            i += 1
            continue
        if ch == ">":
            return None
        j = i
        while j < n and body[j] not in " \t\r\n/=>":
            j += 1
        name = body[i:j].lower()
        i = j
        if i >= n:
            return {"kind": "tag"}                       # inside an attribute *name*
        k = i
        while k < n and body[k] in " \t\r\n":
            k += 1
        if k >= n or body[k] != "=":
            i = k
            continue                                      # boolean attribute
        k += 1
        while k < n and body[k] in " \t\r\n":
            k += 1
        if k >= n:
            return {"kind": "attr", "attr": name, "quote": None, "start": True}
        q = body[k]
        if q in "\"'":
            end = body.find(q, k + 1)
            if end == -1 or end >= n:
                return {"kind": "attr", "attr": name, "quote": q, "start": k + 1 == n}
            i = end + 1
        else:
            j = k
            while j < n and body[j] not in " \t\r\n>":
                j += 1
            if j >= n:
                return {"kind": "attr", "attr": name, "quote": None, "start": k == n}
            i = j
    return {"kind": "tag"}


def _js_state(src: str) -> str | None:
    """Quote that encloses the end of `src` ('"', "'", '`'), 'comment', or None for plain code."""
    q: str | None = None
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        if q:
            if c == "\\":
                i += 2
                continue
            if c == q:
                q = None
        elif c in "\"'`":
            q = c
        elif c == "/" and src[i + 1:i + 2] == "/":
            j = src.find("\n", i)
            if j == -1:
                return "comment"
            i = j
            continue
        elif c == "/" and src[i + 1:i + 2] == "*":
            j = src.find("*/", i + 2)
            if j == -1:
                return "comment"
            i = j + 2
            continue
        i += 1
    return q


def context_at(body: str, pos: int) -> Reflection:
    head = body[:pos]
    c_open = head.rfind("<!--")
    if c_open != -1 and head.find("-->", c_open + 4) == -1:
        return Reflection("comment", pos)
    for tag in _RAW_ELEMENTS:
        o = _last_open_raw(head, tag)
        if o == -1:
            continue
        gt = _tag_end(body, o, pos)
        if gt is None:                                    # still inside the opening tag itself
            break
        if tag == "script":
            state = _js_state(body[gt + 1:pos])
            if state == "comment":
                return Reflection("comment", pos)
            if state:
                return Reflection("script-string", pos, quote=state)
            return Reflection("script", pos)
        return Reflection("style" if tag == "style" else "rcdata", pos)
    tags = list(re.finditer(r"<[a-zA-Z][^\s/>]*", head))
    if tags:
        info = _lex_tag(body, tags[-1].start(), pos)
        if info is not None:
            if info["kind"] == "attr":
                return Reflection("attr", pos, quote=info["quote"], attr=info["attr"], at_value_start=info["start"])
            return Reflection("tag", pos)
    return Reflection("text", pos)


def _tag_end(body: str, start: int, limit: int) -> int | None:
    """Index of the `>` that ends the tag starting at `start`, if it ends before `limit`."""
    i, quote = start + 1, None
    while i < limit:
        c = body[i]
        if quote:
            if c == quote:
                quote = None
        elif c in "\"'":
            quote = c
        elif c == ">":
            return i
        i += 1
    return None


# ── reflections of a probe ────────────────────────────────────────────────────

def find_reflections(body: str, name: str, limit: int = 12) -> list[Reflection]:
    t1, t2 = tokens_for(name)
    out: list[Reflection] = []
    for m in re.finditer(re.escape(t1), body):
        if len(out) >= limit:
            break
        ref = context_at(body, m.start())
        end = body.find(t2, m.end(), m.end() + 80)
        seg = body[m.end(): end if end != -1 else m.end() + len(PROBE_CHARS) + 20]
        for ch in PROBE_CHARS:
            idx = seg.find(ch)
            while idx != -1:
                escaped = ref.context == "script-string" and idx > 0 and seg[idx - 1] == "\\"
                if not escaped:
                    ref.raw.add(ch)
                    break
                idx = seg.find(ch, idx + 1)
        out.append(ref)
    return out


# ── what a reflection allows ──────────────────────────────────────────────────

# kind → (title of the exploit path, context-matched benign payloads in order of preference)
def exploit_kind(ref: Reflection) -> str | None:
    """
    The way this reflection can be turned into script execution, or None when the characters that
    would be needed were escaped (or the spot is inert, e.g. a comment).
    """
    c, raw = ref.context, ref.raw
    if c == "text":
        return "html" if "<" in raw else None
    if c == "rcdata":
        return "html" if "<" in raw else None             # </textarea> / </title> breaks out
    if c == "style":
        return "html" if "<" in raw else None             # </style> breaks out
    if c == "tag":
        return "attr-new" if ">" in raw or '"' in raw or "'" in raw else None
    if c == "attr":
        if ref.quote == '"':
            if '"' in raw:
                return "attr-dq"
        elif ref.quote == "'":
            if "'" in raw:
                return "attr-sq"
        else:
            return "attr-unquoted"                          # a space ends an unquoted value; spaces are never escaped
        if ref.attr in _URL_ATTRS and ref.at_value_start:
            return "url"
        if ref.attr and ref.attr.startswith("on"):
            return "js-attr"                                # inside an event handler: already script
        return None
    if c == "script":
        return "js-code"
    if c == "script-string":
        if ref.quote in raw:
            return "js-string-" + {'"': "dq", "'": "sq", "`": "bt"}[ref.quote]
        if "<" in raw:
            return "script-close"                           # </script> ends the block even inside a string
        return None
    return None


_PAYLOADS: dict[str, list[str]] = {
    "html":           ["<svg onload=alert(1)>", "<img src=x onerror=alert(1)>", '<script>alert("fsv")</script>'],
    "attr-dq":        ['"><svg onload=alert(1)>', '" autofocus onfocus=alert(1) x="'],
    "attr-sq":        ["'><svg onload=alert(1)>", "' autofocus onfocus=alert(1) x='"],
    "attr-unquoted":  ["x onmouseover=alert(1) y", "><svg onload=alert(1)>"],
    "attr-new":       ["><svg onload=alert(1)>", " autofocus onfocus=alert(1) "],
    "url":            ["javascript:alert(1)"],
    "js-attr":        ["alert(1)"],
    "js-code":        [";alert(1);//", "alert(1)"],
    "js-string-dq":   ['";alert(1);//', '"-alert(1)-"'],
    "js-string-sq":   ["';alert(1);//", "'-alert(1)-'"],
    "js-string-bt":   ["${alert(1)}"],
    "script-close":   ["</script><svg onload=alert(1)>"],
}


def payloads_for(kind: str, deep: bool) -> list[str]:
    """One payload normally; every shape when scanning deep."""
    lst = _PAYLOADS.get(kind, [])
    return lst if deep else lst[:1]


def raw_in_context(body: str, payload: str) -> bool:
    """The payload came back byte-for-byte (so it was neither escaped nor stripped)."""
    return payload in body


# ── hidden-parameter discovery ────────────────────────────────────────────────

COMMON_PARAMS = (
    "q", "s", "search", "query", "keyword", "term", "id", "page", "p", "name", "title", "url", "redirect", "next",
    "return", "returnUrl", "callback", "lang", "file", "path", "ref", "error", "msg", "message", "email", "user",
    "view", "action", "type", "category", "sort", "filter", "debug", "data", "text", "value", "input", "param",
)
# full profile: a much longer list (search/redirect/template/debug/format/API-style names)
EXTRA_PARAMS = (
    "keywords", "s_query", "searchterm", "search_query", "qs", "term", "text", "content", "body", "comment", "description", "subject",
    "uri", "link", "target", "dest", "destination", "continue", "redirect_uri", "redirect_url", "return_url", "returnTo", "goto", "forward", "out",
    "image", "img", "src", "source", "resource", "document", "doc", "folder", "dir", "template", "tpl", "layout", "theme", "style", "include",
    "page_id", "pid", "post", "post_id", "article", "item", "item_id", "product", "product_id", "cat", "cat_id", "category_id", "tag", "slug",
    "uid", "user_id", "userid", "username", "login", "account", "member", "profile", "customer", "order", "order_id", "invoice", "ref_id",
    "format", "output", "fmt", "mode", "step", "tab", "section", "module", "controller", "func", "method", "cmd", "command", "exec", "query_string",
    "sortby", "order_by", "orderby", "dir", "limit", "offset", "start", "end", "from", "to", "date", "year", "month", "day", "country", "region",
    "locale", "language", "currency", "host", "domain", "site", "server", "ip", "port", "proxy", "callback_url", "jsonp", "cb", "fn",
    "error_message", "err", "success", "status", "code", "reason", "notice", "alert", "info", "warning", "flash", "msg_text", "feedback",
)
CHUNK = 14


def candidate_names(existing: list[str], full: bool = False) -> list[str]:
    have = {e.lower() for e in existing}
    pool = list(dict.fromkeys(COMMON_PARAMS + EXTRA_PARAMS)) if full else COMMON_PARAMS
    return [n for n in pool if n.lower() not in have]


def canary_for(name: str) -> str:
    return tokens_for(name)[0]


def reflected_names(body: str, names: list[str]) -> list[str]:
    """Which of `names` had their canary echoed in `body` (one request, many names)."""
    return [n for n in names if canary_for(n) in body]
