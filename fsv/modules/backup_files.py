"""
FSV Module — backup copies of crawled files (full profile only)

`config.php.bak`, `index.php~`, `settings.py.old`: an editor or a deploy script leaves a copy next to the original, and
the web server — which executes `.php` but serves `.php.bak` as plain text — hands out the source code (with its database
password) to anyone who asks.

For every crawled URL whose file name ends in a server-side/config extension, FSV asks for the usual backup spellings
and reports a hit only when the response *looks like source code or configuration* (`<?php`, `<%@`, a shebang, an
`[section]` ini, SQL…) and is not an HTML page. Contents are never copied into the report.

Does nothing unless the profile is `full`. Budgeted (≤ 120 probes per scan) and read-only.
"""

from __future__ import annotations
import re
from urllib.parse import urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner

_SCRIPT_EXT = {"php", "php3", "php4", "php5", "phtml", "inc", "asp", "aspx", "ashx", "asmx", "jsp", "jspx", "cfm", "pl", "py", "rb", "cgi"}
_CONFIG_EXT = {"ini", "conf", "config", "cfg", "yml", "yaml", "sql", "properties", "toml"}
_SUFFIXES = (".bak", ".old", "~", ".orig", ".save", ".copy", ".txt", ".1", "_bak", ".backup")
_SOURCE = re.compile(
    r"(<\?php|<\?=|<%@|<%=|<%\s|^#!\s*/\S+|^\s*(?:import|from)\s+\w+[\w.]*\s+(?:import\b|$)|^\s*require(?:_once)?\s*[(\"']|"
    r"^\s*use\s+strict|^\s*\[[A-Za-z_][\w .-]*\]\s*$|^\s*[\w.-]+\s*[=:]\s*\S|CREATE\s+TABLE|INSERT\s+INTO)",
    re.IGNORECASE | re.MULTILINE)
BUDGET = 120


def variants(path: str) -> list[str]:
    """Backup spellings for one file path ('/a/config.php' → '/a/config.php.bak', '/a/config.php~', …, '/a/.config.php.swp')."""
    name = path.rsplit("/", 1)[-1]
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    if ext not in _SCRIPT_EXT and ext not in _CONFIG_EXT:
        return []
    out = [path + s for s in _SUFFIXES]
    d = path.rsplit("/", 1)[0]
    out.append(f"{d}/.{name}.swp")
    out.append(path.rsplit(".", 1)[0] + ".bak")                  # config.bak
    return out


class BackupFilesScanner(BaseScanner):
    name        = "backup_files"
    category    = "passive"
    scope       = "url"
    description = "Full profile: .bak/.old/~/.swp copies of crawled scripts and config files that serve source code as text"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._tried: set[str] = set()
        self._spent = 0

    async def scan(self, url: str) -> list[Finding]:
        if not self.full:
            return []
        p = urlparse(url)
        if p.path in self._tried:
            return []
        self._tried.add(p.path)
        out: list[Finding] = []
        for v in variants(p.path):
            if self._spent >= BUDGET:
                break
            self._spent += 1
            target = f"{p.scheme}://{p.netloc}{v}"
            r = await self.http.request(target)
            if not (r.ok and r.status == 200 and r.body):
                continue
            ctype = next((val for k, val in r.headers.items() if k.lower() == "content-type"), "").lower()
            head = r.body.lstrip()[:200].lower()
            if "text/html" in ctype or head.startswith(("<!doctype", "<html")):
                continue
            ok = r.body.startswith("b0VIM") if v.endswith(".swp") else bool(_SOURCE.search(r.body[:4000]))
            if ok:
                out.append(Finding(
                    title=f"Backup Copy Exposes Source or Configuration: `{v}`", severity=Severity.HIGH, confidence=Confidence.CERTAIN, url=target,
                    module=self.name,
                    description=("A backup copy of a script or configuration file is downloadable as plain text. The web server runs the original but serves "
                                 "this copy as a file, so anyone can read the source code — usually with database credentials, keys and internal logic."),
                    evidence=f"HTTP 200 at {v} ({len(r.body)} bytes, {ctype or 'no content type'}) — contents withheld from the report",
                    recommendation=("Delete the backup from the web root and stop creating them there (deploy from a clean build; exclude *.bak *~ *.swp *.old). "
                                    "Treat any credentials in the file as compromised and rotate them."),
                    references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information"],
                    cwe="CWE-530"))
                break                                            # one proven copy per file is enough
        return out
