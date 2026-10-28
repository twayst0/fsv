"""
FSV Module — HTML source leaks

What developers leave in the page that never shows in the browser:
  • secrets and credentials in HTML comments (provider formats + `password: …` style notes) — reported masked
  • internal hostnames, private IPs and server paths in comments
  • a password field that arrives pre-filled (the server is echoing a stored password)
  • hidden form fields carrying data the server must not trust (role, price, is_admin, user_id…)
  • developer notes ("TODO remove before prod", "bypass auth") — informational

Reads HTML only, through the shared cached client. Credentials are never tested.
"""

from __future__ import annotations
import re

from bs4 import BeautifulSoup, Comment

from fsv.core.content import is_html
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner, mask_secret
from fsv.core.secrets import _PLACEHOLDER, find_secrets

MAX_HTML = 800_000
_CRED_NOTE = re.compile(r"(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|credentials?)\b\s*(?:is|=|:)\s*[\"']?([^\s\"'<>]{6,60})")
_INTERNAL = re.compile(
    r"(?i)(?:\b(?:10|127)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b192\.168\.\d{1,3}\.\d{1,3}\b|\b172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}\b"
    r"|\b[a-z0-9][a-z0-9.\-]{1,60}\.(?:internal|corp|local|lan|intranet)\b|\b[A-Za-z]:\\[\w\\.\-]{3,}|(?<![\w:/.])/(?:home|var/www|usr/local|opt|srv|etc)/[\w./\-]{3,})")
_NOTE = re.compile(r"(?i)\b(?:todo|fixme|hack|xxx|temporary|remove (?:before|me)|disable[d]? (?:auth|check|security)|bypass|backdoor|debug mode)\b")
_IGNORED = re.compile(r"(?i)^\s*(?:\[if |<!\[endif|/?ko\b|ko |\s*/?(?:ko|ngIf)|\[endif|noindex|googleoff|googleon|\s*end\b|\s*/?ssi)")
_TRUST_HIDDEN = re.compile(r"(?i)^(?:is[_-]?admin|admin|role|roles|user[_-]?role|privilege[ds]?|access[_-]?level|price|amount|total|discount|coupon|"
                           r"debug|test[_-]?mode|user[_-]?id|uid|account[_-]?id|owner|owner[_-]?id)$")


_MASK_ONLY = re.compile(r"[•●·*xX._\-\u2022\u25cf\u00b7]+")      # "••••••••" is a placeholder for a stored password, not the password


def _human_secret(value: str) -> bool:
    """A value that plausibly is a password/token, not a sentence fragment or a placeholder."""
    if _PLACEHOLDER.search(value) or len(value) < 6:
        return False
    return bool(re.search(r"\d", value) or re.search(r"[^\w]", value))


def comment_texts(html: str) -> list[str]:
    try:
        soup = BeautifulSoup(html[:MAX_HTML], "lxml")
    except Exception:
        return []
    out = []
    for c in soup.find_all(string=lambda t: isinstance(t, Comment)):
        text = str(c).strip()
        if len(text) >= 8 and not _IGNORED.match(text):
            out.append(text)
    return out


class HTMLLeaksScanner(BaseScanner):
    name        = "html_leaks"
    category    = "passive"
    scope       = "url"
    description = "HTML source: secrets and internal details in comments, pre-filled password fields, trust-bearing hidden fields"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._seen_comments: set[int] = set()          # a footer comment on 50 pages is one finding

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not r.body or not is_html(r.headers, r.body):
            return []
        findings = self.review_comments(url, comment_texts(r.body))
        findings += self.review_forms(url, r.body)
        return findings

    # ── comments ──
    def review_comments(self, url: str, comments: list[str]) -> list[Finding]:
        secrets: list[tuple[str, Severity, Confidence, str]] = []   # (label, severity, confidence, masked evidence)
        internal: list[str] = []
        notes: list[str] = []
        for text in comments:
            h = hash(text)
            if h in self._seen_comments:
                continue
            self._seen_comments.add(h)
            hits = find_secrets(text, max_hits=3)
            for hit in hits:
                secrets.append((hit.rule.label, hit.rule.severity, hit.rule.confidence, hit.masked))
            if not hits:
                m = _CRED_NOTE.search(text)
                if m and _human_secret(m.group(1)):
                    secrets.append(("credential mentioned in a comment", Severity.MEDIUM, Confidence.TENTATIVE,
                                    mask_secret(m.group(0)[:100])))
            for m in _INTERNAL.finditer(text):
                if len(internal) < 6:
                    internal.append(m.group(0)[:80])
            if _NOTE.search(text):
                notes.append(text.replace("\n", " ")[:140])

        out: list[Finding] = []
        if secrets:
            worst = max(secrets, key=lambda s: ["info", "low", "medium", "high", "critical"].index(s[1].value))
            out.append(Finding(
                title="Credentials or Secrets in HTML Comments", severity=worst[1], confidence=worst[2], url=url, module=self.name,
                description=("An HTML comment contains what looks like a credential. Comments are delivered to every visitor and kept by caches, "
                             "archives and scrapers even after the page is fixed."),
                evidence="\n".join(f"{lbl}: {ev}" for lbl, _, _, ev in secrets[:5]),
                recommendation="Remove the comment, treat the credential as compromised and rotate it, and strip comments in the production build.",
                references=["https://cwe.mitre.org/data/definitions/615.html"], cwe="CWE-615"))
        if internal:
            out.append(Finding(
                title="Internal Hostnames, IP Addresses or Paths in HTML Comments", severity=Severity.LOW, confidence=Confidence.FIRM,
                url=url, module=self.name,
                description="Comments reveal internal network details or server file paths — a free map for an attacker.",
                evidence="\n".join(dict.fromkeys(internal)),
                recommendation="Strip comments from production HTML (most build tools and template engines can), and keep internal names out of markup.",
                references=["https://cwe.mitre.org/data/definitions/615.html"], cwe="CWE-615"))
        if notes:
            out.append(Finding(
                title="Developer Notes Left in HTML Comments", severity=Severity.INFO, confidence=Confidence.TENTATIVE, url=url, module=self.name,
                description="Comments such as TODO / FIXME / 'bypass' / 'debug mode' hint at unfinished or disabled security controls.",
                evidence="\n".join(notes[:4]),
                recommendation="Review what these notes refer to, and strip comments from production output.", cwe="CWE-615"))
        return out

    # ── forms ──
    def review_forms(self, url: str, html: str) -> list[Finding]:
        try:
            soup = BeautifulSoup(html[:MAX_HTML], "lxml")
        except Exception:
            return []
        out: list[Finding] = []
        for pw in soup.find_all("input", attrs={"type": lambda t: t and t.lower() == "password"}):
            value = (pw.get("value") or "").strip()
            if value and not _PLACEHOLDER.search(value) and not _MASK_ONLY.fullmatch(value):
                out.append(Finding(
                    title="Password Field Is Pre-Filled", severity=Severity.HIGH, confidence=Confidence.FIRM, url=url, module=self.name,
                    description=("A password input arrives with a value already in it, so the server puts a stored password into the page — "
                                 "visible in the source, caches, browser history and to any script on the page."),
                    evidence=f"<input type=\"password\" name=\"{pw.get('name', '')}\" value=\"{mask_secret(value)}\">",
                    recommendation="Never send a stored password back to the browser. For 'keep my password' show a placeholder and only act when the field is changed.",
                    references=["https://cwe.mitre.org/data/definitions/256.html"], cwe="CWE-256"))
                break
        hidden = [(i.get("name") or "", (i.get("value") or "")[:40]) for i in soup.find_all("input", attrs={"type": lambda t: t and t.lower() == "hidden"})
                  if _TRUST_HIDDEN.match(i.get("name") or "")]
        if hidden:
            out.append(Finding(
                title="Hidden Form Field Carries Data the Server Should Not Trust", severity=Severity.LOW, confidence=Confidence.TENTATIVE,
                url=url, module=self.name,
                description=("Fields like role, price, is_admin or user_id sit in the page where the user can edit them. If the server believes the "
                             "submitted value instead of looking it up itself, this is privilege escalation or price tampering. FSV cannot tell "
                             "which — test it: change the value and see whether the server accepts it."),
                evidence="\n".join(f"{n} = {v!r}" for n, v in hidden[:6]),
                recommendation="Derive roles, prices and ownership on the server from the session; never read them from form fields.",
                references=["https://cwe.mitre.org/data/definitions/472.html"], cwe="CWE-472"))
        return out
