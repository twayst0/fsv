"""FSV Module — Framework debug mode left on in production"""

from __future__ import annotations
import json
import uuid
from urllib.parse import urlparse

from fsv.core.discovery import django_debug_routes
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

# Debug pages only appear on errors, so a crawler that reads 200 pages never sees them.
# One request to a path that cannot exist shows what this site does with a 404.
# (framework, signatures that must ALL appear, severity, what the page gives away)
_ERROR_PAGES = [
    ("Django", ("seeing this error because you have", "debug = true"), Severity.HIGH,
     "Django's technical 404/500 pages list every URL pattern, and the 500 page shows settings, local "
     "variables and source code around the failing line."),
    ("Werkzeug / Flask", ("werkzeug debugger",), Severity.CRITICAL,
     "The Werkzeug debugger offers an in-browser Python console. Its PIN can be derived from data the "
     "same app often leaks, which turns the debugger into remote code execution."),
    ("Ruby on Rails", ("action controller: exception caught",), Severity.HIGH,
     "Rails development error pages print the full routing table, request parameters and source."),
    ("Laravel (Ignition)", ("ignition", "laravel"), Severity.HIGH,
     "Laravel's Ignition error page reveals the environment, stack traces and source; older versions "
     "allowed remote code execution (CVE-2021-3129)."),
    ("Symfony", ("symfony exception",), Severity.HIGH,
     "Symfony's debug error page shows stack traces and source, and implies the web profiler is on."),
    ("Express / Node.js", ("<br> &nbsp; &nbsp;at ",), Severity.MEDIUM,
     "Express prints the stack trace (file paths, dependency versions) because NODE_ENV is not "
     "'production'."),
    ("ASP.NET", ("stack trace:", "version information:"), Severity.MEDIUM,
     "ASP.NET detailed errors (customErrors off) print stack traces and framework versions."),
]


class DebugModeScanner(BaseScanner):
    name = "debug_mode"
    category    = "passive"
    scope       = "site"
    description = "Framework debug mode in production (Django, Werkzeug, Rails, Laravel, Symfony, Express, ASP.NET)"

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        findings: list[Finding] = []

        probe = f"{base}/fsv-debug-probe-{uuid.uuid4().hex[:10]}"
        r = await self.fetch_response(probe)
        if r.ok and r.status >= 400:
            low = r.body.lower()
            for framework, sigs, sev, impact in _ERROR_PAGES:
                if all(s in low for s in sigs):
                    findings.append(self._debug_finding(framework, sev, impact, probe, r.status, r.body))
                    break

        # Werkzeug's console is a page of its own, reachable without any error
        r = await self.fetch_response(base + "/console")
        if r.status == 200 and "interactive console" in r.body.lower() and "werkzeug" in r.body.lower():
            findings.append(Finding(
                title="Werkzeug Interactive Console Exposed", severity=Severity.CRITICAL, url=base + "/console",
                module=self.name, confidence=Confidence.CERTAIN, cwe="CWE-94",
                description=("Flask/Werkzeug runs with debug=True and serves its Python console at /console. "
                             "Anyone who gets past the PIN (often derivable) can execute code on the server."),
                evidence="GET /console → 200, Werkzeug interactive console page",
                recommendation="Never run with debug=True in production; serve the app with a WSGI server (gunicorn, uWSGI).",
                references=["https://werkzeug.palletsprojects.com/en/latest/debug/"]))

        # Laravel Ignition's health check says whether it will run commands (the CVE-2021-3129 precondition)
        r = await self.fetch_response(base + "/_ignition/health-check")
        if r.status == 200:
            try:
                data = json.loads(r.body)
            except ValueError:
                data = None
            if isinstance(data, dict) and data.get("can_execute_commands") is True:
                findings.append(Finding(
                    title="Laravel Ignition Can Execute Commands", severity=Severity.CRITICAL,
                    url=base + "/_ignition/health-check", module=self.name, confidence=Confidence.CERTAIN,
                    cwe="CWE-94",
                    description=("Laravel's Ignition debug endpoints are reachable and report "
                                 "can_execute_commands=true. Unpatched versions are remotely exploitable "
                                 "(CVE-2021-3129); patched ones still expose solution runners."),
                    evidence=f"GET /_ignition/health-check → {r.body[:120]}",
                    recommendation="Set APP_DEBUG=false in production and update facade/ignition.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2021-3129"]))
        return findings

    def _debug_finding(self, framework: str, sev: Severity, impact: str, url: str,
                       status: int, body: str) -> Finding:
        routes = django_debug_routes(body) if framework == "Django" else []
        extra_ev = f"\nThe page lists {len(routes)} URL pattern(s), e.g. {', '.join(routes[:6])}" if routes else ""
        return Finding(
            title=f"{framework} Debug Mode Enabled",
            severity=sev, url=url, module=self.name, confidence=Confidence.CERTAIN, cwe="CWE-489",
            description=(f"A request for a page that does not exist returned {framework}'s debug error page. "
                         f"{impact} The same switch usually makes every server error a source-code leak."),
            evidence=f"GET {urlparse(url).path} → {status}, {framework} debug page{extra_ev}",
            recommendation=("Turn debug mode off in production (Django DEBUG=False, Flask debug=False, "
                            "Rails/Express production env, Laravel APP_DEBUG=false, ASP.NET customErrors On) "
                            "and log errors server-side."),
            references=["https://cwe.mitre.org/data/definitions/489.html",
                        "https://docs.djangoproject.com/en/stable/ref/settings/#debug"],
            extra={"framework": framework, "routes": routes[:50]},
        )
