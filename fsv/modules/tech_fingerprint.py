"""FSV Module — Technology Stack Fingerprinting"""

from __future__ import annotations
from fsv.core.scanner import BaseScanner
from datetime import date

from fsv.core import eol
from fsv.core.models import Confidence, Finding, Severity
from fsv.config import TECH_SIGNATURES


class TechScanner(BaseScanner):
    name = "tech"
    category    = "passive"
    scope       = "site"
    description = "Technology fingerprint + outdated-software hints"

    @staticmethod
    def _today() -> date:
        return date.today()            # indirection so tests can pin the date

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1:
            return []

        detected: list[str] = []
        all_text = body + " " + " ".join(f"{k}: {v}" for k, v in headers.items())

        for tech, signatures in TECH_SIGNATURES.items():
            for sig in signatures:
                if sig.lower() in all_text.lower():
                    if tech not in detected:
                        detected.append(tech)
                    break

        # end-of-life software the response itself discloses (dated table, see core/eol.py)
        eol_hits = []
        for prod, (ver, where) in eol.products_from(headers, body).items():
            info = eol.check(prod, ver, self._today())
            if info:
                eol_hits.append((info, where))

        if not detected and not eol_hits:
            return []

        findings: list[Finding] = [] if not detected else [
            Finding(
                title       = "Technology Stack Identified",
                severity    = Severity.INFO,
                url         = url,
                module      = self.name,
                description = (
                    f"The following technologies were identified: {', '.join(detected)}. "
                    "This information helps attackers target known CVEs and default configurations."
                ),
                evidence    = f"Detected: {', '.join(detected)}",
                recommendation = (
                    "Keep all software up to date. Remove version disclosures from HTTP headers "
                    "and HTML source. Disable default error pages."
                ),
                references  = [],
                extra       = {"technologies": detected},
            )
        ]

        for info, where in eol_hits:
            sev = Severity.HIGH if info.years_past >= 2 else Severity.MEDIUM
            findings.append(Finding(
                title       = f"End-of-Life Software: {info.label}",
                severity    = sev,
                confidence  = Confidence.FIRM,
                url         = url,
                module      = self.name,
                description = (
                    f"{info.label} (disclosed in the {where}) stopped receiving security fixes "
                    + (f"no later than {info.eol.isoformat()}" if info.approx else f"on {info.eol.isoformat()}")
                    + f" — at least {info.years_past:g} year(s) ago. Every vulnerability "
                    "found since then is permanent, and public exploit code for old versions is "
                    "readily available. (Some distributions back-port fixes into old version "
                    "numbers; verify with your vendor if you rely on that.)"),
                evidence    = (f"{where}: {info.label}\nEnd of security support: "
                               f"{'no later than ' if info.approx else ''}{info.eol.isoformat()}"),
                recommendation = (
                    f"Upgrade to a supported {eol.DISPLAY.get(info.product, info.product)} release. "
                    "Until then, hide the version banner and restrict exposure (WAF, network ACLs)."),
                references  = [f"https://endoflife.date/{info.product}"],
                cwe         = "CWE-1104",
                extra       = {"product": info.product, "version": info.version,
                               "eol": info.eol.isoformat()}))

        return findings
