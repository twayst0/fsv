"""
FSV Module — API documentation & GraphQL IDEs

A published OpenAPI/Swagger document is an inventory of the attack surface. The path scanner notes that such a file
exists; this module *reads it* and reports what makes it a finding:

  • endpoints the document itself marks as needing no authentication, and how many
  • sensitive-looking routes (/admin, /internal, /debug, /export, /token, /users/{id}…)
  • servers declared over plain HTTP
  • example credentials/keys embedded in the spec (masked, never tested)

and flags exposed interactive tools: Swagger UI / ReDoc / GraphiQL / GraphQL Playground / Altair.
JSON specs only (YAML would need a parser FSV does not ship). Read-only GETs, content-validated.
"""

from __future__ import annotations
import json
import re
from urllib.parse import urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.scanner import BaseScanner
from fsv.core.secrets import find_secrets

SPEC_PATHS = ("/openapi.json", "/swagger.json", "/api/openapi.json", "/api/swagger.json", "/api-docs", "/api/v1/openapi.json",
              "/api/v1/swagger.json", "/swagger/v1/swagger.json", "/v1/openapi.json", "/docs/openapi.json", "/openapi/v1.json")
UI_PATHS = ("/docs", "/redoc", "/swagger", "/swagger/", "/api/docs", "/api-docs/", "/swagger-ui/", "/documentation", "/api/swagger-ui/", "/help/api")
GRAPHQL_IDE = ("/graphiql", "/playground", "/altair", "/graphql", "/api/graphql", "/graphql/playground", "/explorer")
_UI_MARK = re.compile(r"(?i)swagger-ui|SwaggerUIBundle|<redoc|redoc\.standalone|rapidoc|stoplight-elements")
_IDE_MARK = re.compile(r"(?i)graphiql|graphql playground|altair-graphql|GraphQLPlayground|apollo sandbox|graphql-voyager")
_SENSITIVE = re.compile(r"(?i)/(?:admin|internal|debug|actuator|backup|export|import|dump|token|tokens|secret|secrets|keys?|impersonate|"
                        r"users?/\{[^}]+\}|accounts?/\{[^}]+\}|config|settings|private|sudo|root|shell|exec|upload)\b")
_METHODS = ("get", "post", "put", "patch", "delete")
_REFS = ["https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/"]


def _ops(spec: dict):
    for path, item in (spec.get("paths") or {}).items():
        if isinstance(item, dict):
            for m in _METHODS:
                if isinstance(item.get(m), dict):
                    yield path, m, item[m]


def analyze_openapi(spec: dict, url: str, module: str = "api_docs") -> list[Finding]:
    if not isinstance(spec, dict) or not (spec.get("openapi") or spec.get("swagger")) or not isinstance(spec.get("paths"), dict):
        return []
    ops = list(_ops(spec))
    if not ops:
        return []
    schemes = (spec.get("components") or {}).get("securitySchemes") or spec.get("securityDefinitions") or {}
    global_sec = spec.get("security")
    unauth: list[str] = []
    for path, m, op in ops:
        sec = op.get("security")
        protected = bool(sec) if sec is not None else bool(global_sec)
        if not protected or not schemes:
            unauth.append(f"{m.upper()} {path}")
    sensitive = sorted({f"{m.upper()} {p}" for p, m, _ in ops if _SENSITIVE.search(p)})
    sensitive_open = [s for s in sensitive if s in unauth]
    insecure_servers = [s.get("url", "") for s in (spec.get("servers") or []) if isinstance(s, dict)
                        and str(s.get("url", "")).lower().startswith("http://") and urlparse(s["url"]).hostname not in ("localhost", "127.0.0.1")]
    if spec.get("host") and spec.get("schemes") == ["http"]:
        insecure_servers.append("http://" + str(spec["host"]))
    secrets = find_secrets(json.dumps(spec)[:600_000], max_hits=3)

    out: list[Finding] = []
    n = len(ops)
    if unauth and (sensitive_open or not schemes):
        out.append(Finding(
            title=f"Public API Specification Lists {len(unauth)} Endpoint(s) Without Authentication", severity=Severity.MEDIUM if sensitive_open else Severity.LOW,
            confidence=Confidence.FIRM, url=url, module=module,
            description=(f"The API description is public and documents {n} operations; {len(unauth)} declare no authentication"
                         + (f", including sensitive-looking routes ({len(sensitive_open)})." if sensitive_open else
                            (" — the document defines no security schemes at all." if not schemes else "."))
                         + " The spec is a ready-made target list; whether the endpoints really enforce auth must be tested."),
            evidence="\n".join((sensitive_open or unauth)[:8]),
            recommendation="Restrict the specification to authenticated developers (or internal networks), and make sure every listed endpoint enforces authorisation server-side.",
            references=_REFS, cwe="CWE-200", extra={"operations": n, "unauthenticated": len(unauth), "sensitive": sensitive[:20]}))
    elif sensitive:
        out.append(Finding(
            title="Public API Specification Reveals Sensitive-Looking Routes", severity=Severity.LOW, confidence=Confidence.FIRM, url=url, module=module,
            description=f"The public API description documents {n} operations, including routes that suggest admin, internal or bulk-data functions.",
            evidence="\n".join(sensitive[:8]), recommendation="Hide the specification from the public, or at least strip internal routes from it.",
            references=_REFS, cwe="CWE-200", extra={"operations": n, "sensitive": sensitive[:20]}))
    if insecure_servers:
        out.append(Finding(
            title="API Specification Declares HTTP (Non-TLS) Servers", severity=Severity.MEDIUM, confidence=Confidence.FIRM, url=url, module=module,
            description="The specification tells clients (and generated SDKs) to call the API over plain HTTP.", evidence="\n".join(insecure_servers[:4]),
            recommendation="Declare https:// servers only, and redirect/disable the HTTP listener.", cwe="CWE-319"))
    if secrets:
        out.append(Finding(
            title="Credentials or Keys Embedded in the API Specification", severity=max((h.rule.severity for h in secrets), key=lambda s: ["info", "low", "medium", "high", "critical"].index(s.value)),
            confidence=Confidence.FIRM, url=url, module=module,
            description="Example values in the public specification look like real credentials.", evidence="\n".join(f"{h.rule.label}: {h.masked}" for h in secrets),
            recommendation="Replace with obvious placeholders, and rotate anything that was real.", cwe="CWE-798"))
    return out


class APIDocsScanner(BaseScanner):
    name        = "api_docs"
    category    = "passive"
    scope       = "site"
    description = "API docs: reads exposed OpenAPI/Swagger (unauthenticated & sensitive routes, HTTP servers, secrets); flags Swagger UI, GraphiQL, Playground"

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        out: list[Finding] = []
        seen_specs: set[str] = set()
        spec_candidates = list(SPEC_PATHS)

        for path in UI_PATHS:
            r = await self.http.request(base + path)
            if r.ok and r.status == 200 and r.body and _UI_MARK.search(r.body):
                out.append(Finding(
                    title="API Documentation UI Is Publicly Accessible", severity=Severity.LOW, confidence=Confidence.CERTAIN, url=base + path, module=self.name,
                    description="An interactive API explorer is open to anyone. It lists every operation and lets visitors send requests ('Try it out') straight from the browser.",
                    evidence=f"HTTP 200 at {path} — {_UI_MARK.search(r.body).group(0)}",
                    recommendation="Put API documentation behind authentication or on an internal network, and disable it in production builds.",
                    references=_REFS, cwe="CWE-200"))
                for m in re.finditer(r"""url\s*:\s*["']([^"']+\.(?:json))["']""", r.body):
                    ref = m.group(1)
                    if ref.startswith("/"):
                        spec_candidates.insert(0, ref)
                break

        for path in dict.fromkeys(spec_candidates):
            r = await self.http.request(base + path)
            if not (r.ok and r.status == 200 and r.body and r.body.lstrip().startswith("{")):
                continue
            try:
                spec = json.loads(r.body)
            except ValueError:
                continue
            key = json.dumps(sorted((spec.get("paths") or {}).keys()))[:500] if isinstance(spec, dict) else ""
            if key in seen_specs:
                continue
            seen_specs.add(key)
            out += analyze_openapi(spec, base + path, self.name)

        for path in GRAPHQL_IDE:
            r = await self.http.request(base + path, headers={"Accept": "text/html"})
            if r.ok and r.status == 200 and r.body and _IDE_MARK.search(r.body):
                out.append(Finding(
                    title="GraphQL IDE (GraphiQL / Playground) Is Publicly Accessible", severity=Severity.MEDIUM, confidence=Confidence.CERTAIN,
                    url=base + path, module=self.name,
                    description="An interactive GraphQL console is exposed. It makes schema discovery and crafting queries (including expensive or abusive ones) trivial.",
                    evidence=f"HTTP 200 at {path} — {_IDE_MARK.search(r.body).group(0)}",
                    recommendation="Disable GraphiQL/Playground (and introspection) in production, or require authentication.",
                    references=["https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html"], cwe="CWE-200"))
                break
        return out
