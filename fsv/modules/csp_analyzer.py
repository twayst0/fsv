"""FSV Module — Content-Security-Policy deep review"""

from __future__ import annotations

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


_REFS = [
    "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
    "https://csp-evaluator.withgoogle.com/",
]


def parse_csp(value: str) -> dict[str, list[str]]:
    """'default-src 'self'; img-src *' → {'default-src': ["'self'"], 'img-src': ['*']}"""
    out: dict[str, list[str]] = {}
    for part in value.split(";"):
        tokens = part.strip().split()
        if tokens:
            out.setdefault(tokens[0].lower(), [t for t in tokens[1:]])
    return out


class CSPAnalyzerScanner(BaseScanner):
    """
    The `headers` module only flags a missing CSP and the obvious unsafe-* tokens.
    This one reads the policy the way a reviewer would.
    """
    name     = "csp_analyzer"
    category = "passive"
    scope    = "url"
    description = "Deep Content-Security-Policy review (directives, sources, reporting)"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, _ = await self.fetch(url)
        if status == -1:
            return []
        csp = self._header(headers, "Content-Security-Policy")
        ro  = self._header(headers, "Content-Security-Policy-Report-Only")
        if not csp:
            if ro:
                return [self._f(url, "CSP Deployed in Report-Only Mode", Severity.LOW,
                    "A policy is sent only as Content-Security-Policy-Report-Only, so browsers "
                    "report violations but block nothing.",
                    "Once the reports are clean, send the same policy as Content-Security-Policy.",
                    f"Content-Security-Policy-Report-Only: {ro[:300]}")]
            return []   # missing CSP is reported by the headers module

        d = parse_csp(csp)
        findings: list[Finding] = []
        ev = f"Content-Security-Policy: {csp[:400]}"
        script = d.get("script-src", d.get("default-src"))

        if script is None:
            findings.append(self._f(url, "CSP Has No script-src or default-src", Severity.MEDIUM,
                "Without script-src or default-src the policy places no restriction on scripts, "
                "so it gives no XSS protection.",
                "Add `default-src 'self'` and a specific `script-src`.", ev))
        else:
            wild = [s for s in script if s in ("*", "http:", "https:", "data:")]
            if wild:
                findings.append(self._f(url, "CSP script-src Allows Any Host", Severity.MEDIUM,
                    f"script-src contains {', '.join(wild)}, which lets scripts load from anywhere "
                    "(or from data: URLs) and largely defeats the policy.",
                    "List exact origins, or move to a nonce/hash-based policy with 'strict-dynamic'.", ev))

        if "object-src" not in d and "'none'" not in d.get("default-src", []):
            findings.append(self._f(url, "CSP Missing object-src 'none'", Severity.LOW,
                "Plugins (<object>/<embed>) are not restricted. They are a known way around "
                "script-src.", "Add `object-src 'none'`.", ev))
        if "base-uri" not in d:
            findings.append(self._f(url, "CSP Missing base-uri", Severity.LOW,
                "Without base-uri, an injected <base> tag can change where relative script "
                "URLs point.", "Add `base-uri 'self'` (or 'none').", ev))
        if "frame-ancestors" not in d:
            findings.append(self._f(url, "CSP Missing frame-ancestors", Severity.INFO,
                "frame-ancestors is the modern replacement for X-Frame-Options.",
                "Add `frame-ancestors 'self'` (or 'none').", ev, Confidence.FIRM))
        if "report-uri" not in d and "report-to" not in d:
            findings.append(self._f(url, "CSP Has No Violation Reporting", Severity.INFO,
                "Nothing reports violations, so blocked attacks and broken pages go unnoticed.",
                "Add a `report-to` (or legacy `report-uri`) endpoint.", ev, Confidence.FIRM))
        return findings

    def _f(self, url, title, sev, desc, rec, ev, conf=Confidence.CERTAIN) -> Finding:
        return Finding(title=title, severity=sev, url=url, module=self.name,
                       description=desc, recommendation=rec, evidence=ev,
                       cwe="CWE-693", confidence=conf, references=_REFS)
