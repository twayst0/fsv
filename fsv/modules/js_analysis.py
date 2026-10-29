"""
FSV Module — Client-side JavaScript Analysis
────────────────────────────────────────────
Front-end bundles are public by definition, yet they routinely ship with things
that were never meant to be: build-time secrets baked in by a bundler, internal
hostnames, and — most often — source maps that hand over the original,
unminified source code.

  • hard-coded credentials (provider-specific formats + entropy-gated generic)
  • exposed source maps (and the secrets / comments inside `sourcesContent`)
  • references to internal / non-production hosts

Reads first-party scripts only, through the shared cached client. Credentials
are reported masked and are never tested.
"""

from __future__ import annotations
import ipaddress
import json
import re
from urllib.parse import urljoin, urlparse

from fsv.core.content import MAX_SCRIPTS_PER_PAGE, is_html, load_scripts, same_site
from fsv.core.models import Confidence, Finding, Severity
from fsv.core.netsafety import registrable_domain
from fsv.core.scanner import BaseScanner
from fsv.core.secrets import find_secrets

_SOURCEMAP = re.compile(r"[#@]\s*sourceMappingURL=([^\s'\"*]+)")
_URL_HOST = re.compile(r"(?i)\bhttps?://([a-z0-9][a-z0-9.\-]{1,100}[a-z0-9])(?::\d+)?")
_NONPROD_LABEL = re.compile(r"(?i)(^|[.\-])(staging|stage|stg|dev|uat|qa|preprod|pre-prod|sandbox|internal|test)([.\-]|$)")
_INTERNAL_TLD = (".internal", ".corp", ".local", ".lan", ".intranet", ".localhost")

REFS_SECRET = ["https://owasp.org/Top10/A02_2021-Cryptographic_Failures/",
               "https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html"]
MAX_MAP_SOURCES_SCANNED = 150


def _is_internal_host(host: str, page_domain: str | None) -> bool:
    host = host.lower().rstrip(".")
    if host == "localhost" or host.endswith(_INTERNAL_TLD):
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        pass
    # non-production names of THIS organisation (api-staging.example.com)
    return bool(page_domain and registrable_domain(host) == page_domain
                and host != page_domain and _NONPROD_LABEL.search(host.removesuffix("." + page_domain)))


class JSAnalysisScanner(BaseScanner):
    name        = "js_analysis"
    category    = "passive"
    scope       = "url"
    description = "Client-side JS: hard-coded credentials, exposed source maps, internal/non-prod hosts"

    def __init__(self, http, scan_config) -> None:
        super().__init__(http, scan_config)
        self._seen_scripts: set[str] = set()      # each script analysed once per scan
        self._seen_inline: set[int] = set()
        self._reported: set[tuple[str, str]] = set()

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not is_html(r.headers, r.body):
            return []
        scripts, inline = await load_scripts(self.http, url, r.body, first_party_only=True, limit=100 if self.full else MAX_SCRIPTS_PER_PAGE,
                                             skip=self._seen_scripts)
        page_domain = registrable_domain(urlparse(url).hostname or "")
        findings: list[Finding] = []

        for body in inline:
            h = hash(body)
            if h in self._seen_inline:
                continue
            self._seen_inline.add(h)
            findings += self._secrets(url, body, "inline <script>")

        internal: dict[str, str] = {}
        for sc in scripts:
            findings += self._secrets(sc.url, sc.body, sc.url)
            findings += await self._sourcemap(sc.url, sc.body, r.headers)
            for m in _URL_HOST.finditer(sc.body[:600_000]):
                host = m.group(1)
                if _is_internal_host(host, page_domain):
                    internal.setdefault(host.lower(), sc.url)

        if internal:
            findings.append(Finding(
                title="Internal or Non-Production Hosts Referenced in Client Code",
                severity=Severity.LOW, confidence=Confidence.FIRM, url=url, module=self.name,
                description=(
                    "Public JavaScript refers to hosts that look internal or non-production. They "
                    "reveal infrastructure naming, are an obvious next target, and often run with "
                    "weaker controls than production."),
                evidence="\n".join(f"{h}   (in {s})" for h, s in sorted(internal.items())[:15]),
                recommendation=("Build production bundles with production endpoints only; keep "
                                "environment-specific URLs out of shipped code (inject at runtime)."),
                cwe="CWE-200", extra={"hosts": sorted(internal)}))
        return findings

    # ── credentials ──────────────────────────────────────────────────────

    def _secrets(self, where_url: str, text: str, label: str) -> list[Finding]:
        out: list[Finding] = []
        for hit in find_secrets(text[:1_500_000]):
            key = (hit.rule.key, hit.masked)
            if key in self._reported:
                continue
            self._reported.add(key)
            out.append(Finding(
                title=f"Hard-Coded {hit.rule.label[0].upper()}{hit.rule.label[1:]} in Client-Side Code",
                severity=hit.rule.severity, confidence=hit.rule.confidence, url=where_url,
                module=self.name,
                description=(
                    f"A string matching the format of a {hit.rule.label} is embedded in {label}. "
                    "Everything shipped to the browser is public: anyone can read it, and it will "
                    "also persist in caches, archives and scrapers. " + hit.rule.note +
                    " FSV did not test whether the credential is valid."),
                evidence=f"{hit.masked}   (offset {hit.offset} in {label})",
                recommendation=(
                    "Treat it as compromised: rotate/revoke it now, then remove it from the "
                    "bundle. Keep secrets server-side; use short-lived, scoped tokens for "
                    "anything the browser must hold, and add secret scanning to CI."),
                references=REFS_SECRET, cwe="CWE-798",
                parameter=hit.rule.key, extra={"provider_rule": hit.rule.key}))
        return out

    # ── source maps ──────────────────────────────────────────────────────

    async def _sourcemap(self, script_url: str, body: str, _page_headers) -> list[Finding]:
        # the directive is conventionally the last line, but some tools put it first.
        # Join with a newline: a bare concatenation glued the end of the file onto the
        # start and corrupted the captured URL on short scripts.
        tail = body if len(body) <= 2300 else body[:300] + "\n" + body[-2000:]
        m = _SOURCEMAP.search(tail)
        if not m:
            return []
        ref = m.group(1)
        if ref.startswith("data:"):
            return [self._map_finding(script_url, "inline (data: URI)", None, inline=True)]
        map_url = urljoin(script_url, ref)
        if not same_site(map_url, script_url):
            return []
        r = await self.http.request(map_url)
        if not (r.ok and r.status == 200 and '"sources"' in r.body[:200_000] and '"version"' in r.body[:2000]):
            return []
        info = self._read_map(r.body)
        out = [self._map_finding(script_url, map_url, info)]
        # original sources often contain what the bundler stripped: comments, fixtures, config
        for name, content in info["contents"][:(600 if self.full else MAX_MAP_SOURCES_SCANNED)]:
            out += self._secrets(map_url, content, f"original source {name}")
        return out

    @staticmethod
    def _read_map(text: str) -> dict:
        info = {"sources": [], "has_content": '"sourcesContent"' in text, "contents": [], "truncated": False}
        try:
            data = json.loads(text)
        except ValueError:
            info["truncated"] = True
            info["sources"] = re.findall(r'"([^"]{1,200}\.(?:js|jsx|ts|tsx|vue|svelte))"', text[:200_000])[:200]
            return info
        srcs = data.get("sources") or []
        cont = data.get("sourcesContent") or []
        info["sources"] = [s for s in srcs if isinstance(s, str)]
        for i, s in enumerate(info["sources"]):
            if i < len(cont) and isinstance(cont[i], str) and "node_modules" not in s:
                info["contents"].append((s.split("/")[-1][:60], cont[i][:500_000]))
        return info

    def _map_finding(self, script_url: str, where: str, info: dict | None, inline: bool = False) -> Finding:
        own = [s for s in (info or {}).get("sources", []) if "node_modules" not in s]
        has_content = inline or bool(info and info["has_content"])
        sev = Severity.MEDIUM if has_content else Severity.LOW
        ev = (f"source map: {where}\n"
              + (f"{len(own)} application source files listed, e.g.:\n  " + "\n  ".join(own[:8]) if own else "")
              + ("\nsourcesContent present: original code is embedded" if has_content else ""))
        return Finding(
            title="Source Map Exposes Original Source Code",
            severity=sev, confidence=Confidence.CERTAIN, url=script_url, module=self.name,
            description=(
                "The bundle publishes its source map. Source maps turn minified code back into the "
                "original files — names, comments, structure, hidden routes and API endpoints — "
                "which makes finding real vulnerabilities in your front-end dramatically cheaper "
                "for anyone who looks." + (" This map embeds the full source (sourcesContent)." if has_content else "")),
            evidence=ev.strip(),
            recommendation=("Do not deploy .map files (or the sourceMappingURL comment) to "
                            "production; upload them privately to your error tracker instead. "
                            "Block `*.map` at the CDN/web server."),
            references=["https://owasp.org/www-project-web-security-testing-guide/"],
            cwe="CWE-540", extra={"map": where, "files": len(own)})
