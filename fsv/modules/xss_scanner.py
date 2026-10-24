"""
FSV Module — Reflected XSS Detection (context-aware)

For every URL parameter FSV injects a unique, benign marker in several syntactic
breakouts (HTML body, attribute, JS string, title/textarea). It then determines
*where* the marker landed and whether the special characters that would be needed
to break out of that context survive unencoded. Reporting the reflection context
makes the finding actionable (it tells the developer which encoder is missing)
while keeping payloads non-weaponised — the marker is a comment/inert tag, not a
live script.
"""

from __future__ import annotations
import html
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.config import XSS_PAYLOADS, XSS_MARKER, XSS_SPECIAL_CHARS


class XSSScanner(BaseScanner):
    name = "xss"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        findings: list[Finding] = []

        for param in params:
            hit = await self._test_param(parsed, params, param)
            if hit:
                findings.append(hit)

        return findings

    async def _test_param(self, parsed, params, param) -> Finding | None:
        for payload in XSS_PAYLOADS:
            test_params = {k: v[0] for k, v in params.items()}
            test_params[param] = payload
            test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
            status, headers, body = await self.fetch(test_url)
            if status == -1 or not body:
                continue

            ctype = (self._header(headers, "Content-Type") or "").lower()
            # Only HTML responses can execute reflected markup.
            if ctype and "html" not in ctype and "xml" not in ctype:
                continue

            if payload in body:
                # Full payload reflected verbatim → unencoded breakout survived.
                context = self._classify_context(body, payload)
                return self._finding(parsed, param, payload, context,
                                     encoded=False, confidence=Confidence.FIRM)

            # Marker reflected but payload was (partially) encoded — check which
            # special chars survived to judge exploitability.
            if XSS_MARKER in body:
                survived = [c for c in XSS_SPECIAL_CHARS if c in body and
                            self._char_near_marker(body, c)]
                if survived:
                    context = self._classify_context(body, XSS_MARKER)
                    return self._finding(parsed, param, payload, context,
                                        encoded=True, survived=survived,
                                        confidence=Confidence.TENTATIVE)
        return None

    # ── helpers ───────────────────────────────────────────────────────────

    def _char_near_marker(self, body: str, ch: str) -> bool:
        """Is the raw (unencoded) char present adjacent to a marker reflection?"""
        idx = body.find(XSS_MARKER)
        while idx != -1:
            window = body[max(0, idx - 40): idx + len(XSS_MARKER) + 40]
            if ch in window and html.escape(ch) not in window.replace(ch, "", 1):
                return True
            idx = body.find(XSS_MARKER, idx + 1)
        return False

    def _classify_context(self, body: str, needle: str) -> str:
        idx = body.find(needle)
        if idx == -1:
            return "unknown"
        before = body[max(0, idx - 120): idx].lower()
        last_script = before.rfind("<script")
        last_script_end = before.rfind("</script")
        if last_script > last_script_end:
            return "JavaScript"
        if before.rfind("<") > before.rfind(">"):
            # inside a tag → attribute context
            return "HTML attribute"
        if "href=" in before[-40:] or "src=" in before[-40:]:
            return "URL/href"
        return "HTML body"

    def _finding(self, parsed, param, payload, context, encoded,
                 survived=None, confidence=Confidence.FIRM) -> Finding:
        url = urlunparse(parsed._replace(query=parsed.query))
        test_url = urlunparse(parsed._replace(
            query=urlencode({**{k: v[0] for k, v in
                                parse_qs(parsed.query, keep_blank_values=True).items()},
                             param: payload})))
        if encoded:
            title = "Potential Reflected XSS (partial encoding)"
            sev = Severity.MEDIUM
            enc_line = (f"Marker reflected; unencoded special chars near it: "
                        f"{' '.join(survived or [])}")
        else:
            title = "Reflected Cross-Site Scripting (XSS)"
            sev = Severity.HIGH
            enc_line = "Full payload reflected unencoded (breakout survived)."

        return Finding(
            title       = title,
            severity    = sev,
            confidence  = confidence,
            url         = url,
            module      = self.name,
            parameter   = param,
            description = (
                f"Input in the `{param}` parameter is reflected into the response in a "
                f"**{context}** context without adequate output encoding. An attacker who "
                "controls this value can inject markup/script that executes in a victim's browser."
            ),
            evidence    = (
                f"Parameter: {param}\n"
                f"Reflection context: {context}\n"
                f"Payload injected: {payload}\n"
                f"{enc_line}\n"
                f"Test URL: {test_url[:220]}"
            ),
            recommendation = (
                f"Apply context-aware output encoding for the {context} context "
                "(HTML-encode in body, attribute-encode in attributes, JS-encode in scripts, "
                "URL-encode in URLs). Prefer an auto-escaping framework and add a strict CSP."
            ),
            cwe         = "CWE-79",
            cvss_score  = 6.1 if encoded else 7.2,
            extra       = {"payload": payload, "context": context, "encoded": encoded},
        )
