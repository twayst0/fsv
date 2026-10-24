"""
FSV Module — API & Endpoint Discovery

Site-wide, passive. Probes well-known locations for machine-readable API specs
(OpenAPI/Swagger, GraphQL, WordPress REST, …). When one is reachable it parses
the document and enumerates every declared path — because an exposed spec hands
an attacker the full map of the API: endpoints, parameters, and auth schemes.
Only safe GET requests are made; no declared endpoint is called.
"""

from __future__ import annotations
import json
import asyncio
from urllib.parse import urlparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.config import API_SPEC_PATHS


class APIDiscoveryScanner(BaseScanner):
    name = "api_discovery"

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"

        findings: list[Finding] = []
        tasks = [self._probe(base, path) for path in API_SPEC_PATHS]
        for result in await asyncio.gather(*tasks):
            if result:
                findings.append(result)
        return findings

    async def _probe(self, base: str, path: str) -> Finding | None:
        target = base.rstrip("/") + path
        status, headers, body = await self.fetch(target)
        if status not in (200, 206) or not body:
            return None

        ctype = (self._header(headers, "Content-Type") or "").lower()
        low = body.lower()

        # ── OpenAPI / Swagger JSON ──
        spec = None
        if "json" in ctype or body.lstrip()[:1] in ("{", "["):
            try:
                spec = json.loads(body)
            except Exception:
                spec = None

        if isinstance(spec, dict) and ("swagger" in spec or "openapi" in spec or "paths" in spec):
            paths = list((spec.get("paths") or {}).keys())
            ver = spec.get("info", {}).get("version", "?") if isinstance(spec.get("info"), dict) else "?"
            title = spec.get("info", {}).get("title", "API") if isinstance(spec.get("info"), dict) else "API"
            sample = "\n".join(f"  {ep}" for ep in paths[:40])
            more = f"\n  … and {len(paths) - 40} more endpoints" if len(paths) > 40 else ""
            return Finding(
                title       = "Exposed API Specification (OpenAPI/Swagger)",
                severity    = Severity.MEDIUM,
                confidence  = Confidence.CERTAIN,
                url         = target,
                module      = self.name,
                description = (
                    f"A machine-readable API specification ('{title}', v{ver}) is publicly "
                    f"reachable and declares {len(paths)} endpoint(s). This gives an attacker a "
                    "complete map of the API — every route, parameter and (often) the auth model — "
                    "removing the guesswork from attacking it."
                ),
                evidence    = f"HTTP {status} at {target}\nDeclared endpoints:\n{sample}{more}",
                recommendation = (
                    "Only publish API docs that are meant to be public. For internal/private APIs, "
                    "require authentication to reach the spec, or do not serve it in production. "
                    "Ensure every declared endpoint enforces its own authentication and authorization."
                ),
                cwe         = "CWE-200",
                cvss_score  = 5.3,
                extra       = {"endpoints": paths[:200], "spec_url": target},
            )

        # ── GraphQL endpoint (reachable) ──
        if path.rstrip("/").endswith(("graphql", "graphiql")) and (
            "graphql" in low or "__schema" in low or status == 200 and "query" in low
        ):
            return Finding(
                title       = "GraphQL Endpoint Reachable",
                severity    = Severity.LOW,
                confidence  = Confidence.FIRM,
                url         = target,
                module      = self.name,
                description = (
                    "A GraphQL endpoint is reachable. If introspection is enabled it exposes the "
                    "full schema; GraphQL endpoints also widen the attack surface for injection, "
                    "authorization flaws and denial-of-service via deeply nested queries."
                ),
                evidence    = f"HTTP {status} at {target}",
                recommendation = (
                    "Disable introspection in production, enforce query depth/complexity limits, "
                    "require authentication, and apply per-field authorization."
                ),
                cwe         = "CWE-200",
                cvss_score  = 4.0,
            )

        # ── WordPress REST API ──
        if "wp-json" in path and ("routes" in low or "namespaces" in low):
            return Finding(
                title       = "WordPress REST API Exposed",
                severity    = Severity.LOW,
                confidence  = Confidence.FIRM,
                url         = target,
                module      = self.name,
                description = (
                    "The WordPress REST API is reachable. Some routes (e.g. /wp-json/wp/v2/users) "
                    "can enumerate usernames and content, aiding targeted attacks."
                ),
                evidence    = f"HTTP {status} at {target}",
                recommendation = (
                    "Restrict or authenticate sensitive REST routes, disable user enumeration, and "
                    "keep WordPress core/plugins updated."
                ),
                cwe         = "CWE-200",
                cvss_score  = 4.0,
            )

        return None
