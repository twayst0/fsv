"""
FSV Module — Known-Vulnerability (CVE) Version Matcher

Site-wide, passive. Fingerprints product *versions* from response headers and
page markup (Server, X-Powered-By, <meta name=generator>, library filenames and
inline version strings), then matches them against an offline heuristic table
(config.VERSION_VULN_DB). A hit means "this version line has serious published
CVEs — verify and update". It is a prioritisation hint, not a definitive
per-CVE confirmation, so findings are reported at FIRM/TENTATIVE confidence.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.config import VERSION_VULN_DB


def _parse_version(v: str) -> tuple[int, ...]:
    nums = re.findall(r"\d+", v or "")
    return tuple(int(n) for n in nums[:4]) or (0,)


def _lt(a: str, b: str) -> bool:
    """Return True if version a < version b (numeric component compare)."""
    pa, pb = _parse_version(a), _parse_version(b)
    length = max(len(pa), len(pb))
    pa += (0,) * (length - len(pa))
    pb += (0,) * (length - len(pb))
    return pa < pb


class CVEMatcherScanner(BaseScanner):
    name = "cve_matcher"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1:
            return []

        detected = self._fingerprint_versions(headers, body or "")
        findings: list[Finding] = []

        for product, version in detected.items():
            rules = VERSION_VULN_DB.get(product, [])
            for rule in rules:
                fixed = rule["fixed"]
                is_eol = rule.get("cve") in ("EOL",) or fixed == "0"
                if is_eol or _lt(version, fixed):
                    sev = Severity(rule.get("severity", "medium"))
                    findings.append(Finding(
                        title       = f"Outdated Component: {product} {version}",
                        severity    = sev,
                        confidence  = Confidence.FIRM,
                        url         = url,
                        module      = self.name,
                        description = (
                            f"Detected **{product} {version}**. {rule['summary']} "
                            f"Versions below {fixed} are affected. Running a component with "
                            "publicly documented vulnerabilities means ready-made exploits exist."
                        ),
                        evidence    = (
                            f"Detected version: {product} {version}\n"
                            f"Known-affected: < {fixed}\n"
                            f"Reference: {rule.get('cve', 'n/a')}"
                        ),
                        recommendation = (
                            f"Upgrade {product} to {fixed} or later (ideally the latest supported "
                            "release), verify the CVE references below against your exact build, and "
                            "add Software Composition Analysis to CI so this is caught automatically."
                        ),
                        cwe         = "CWE-1035",
                        cvss_score  = {"critical": 9.1, "high": 7.5, "medium": 5.3,
                                       "low": 3.1, "info": 0.0}.get(rule.get("severity", "medium"), 5.3),
                        references  = [
                            f"https://nvd.nist.gov/vuln/search/results?query={product}+{version}",
                        ],
                        extra       = {"product": product, "version": version,
                                       "fixed": fixed, "cve": rule.get("cve")},
                    ))
                    break  # most-severe rule per product (rules are ordered)

        return findings

    def _fingerprint_versions(self, headers: dict, body: str) -> dict[str, str]:
        found: dict[str, str] = {}

        def add(name, ver):
            if ver and name not in found:
                found[name] = ver

        # ── Server / X-Powered-By headers ──
        server = self._header(headers, "Server") or ""
        for prod, pat in (("Apache", r"Apache/([\d.]+)"),
                          ("Nginx", r"nginx/([\d.]+)"),
                          ("OpenSSL", r"OpenSSL/([\d.a-z]+)")):
            m = re.search(pat, server)
            if m:
                add(prod, m.group(1))

        xpb = self._header(headers, "X-Powered-By") or ""
        m = re.search(r"PHP/([\d.]+)", xpb) or re.search(r"PHP/([\d.]+)", server)
        if m:
            add("PHP", m.group(1))

        # ── generator meta (WordPress, Drupal, etc.) ──
        m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']',
                      body, re.I)
        if m:
            gen = m.group(1)
            wm = re.search(r"WordPress\s+([\d.]+)", gen, re.I)
            if wm:
                add("WordPress", wm.group(1))

        # ── JS library versions from script filenames / inline strings ──
        patterns = {
            "jQuery":    [r"jquery[.-]([\d.]+)(?:\.min)?\.js", r"jQuery v?([\d.]+)"],
            "Bootstrap": [r"bootstrap[.-]([\d.]+)(?:\.min)?\.(?:js|css)", r"Bootstrap v?([\d.]+)"],
            "AngularJS": [r"angular[.-]([\d.]+)(?:\.min)?\.js", r"angular.*?version['\"]?\s*[:=]\s*['\"]([\d.]+)"],
            "Lodash":    [r"lodash[.-]([\d.]+)(?:\.min)?\.js"],
        }
        for prod, pats in patterns.items():
            for pat in pats:
                mm = re.search(pat, body, re.I)
                if mm:
                    add(prod, mm.group(1))
                    break

        return found
