"""FSV Module — GraphQL Introspection Exposure"""

from __future__ import annotations
import json
from urllib.parse import urlparse
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


GRAPHQL_PATHS = ["/graphql", "/api/graphql", "/v1/graphql", "/graphql/v1",
                 "/query", "/api/graphql/v1", "/gql"]

# Minimal introspection query
INTROSPECTION = {"query": "{__schema{queryType{name} types{name}}}"}


class GraphQLScanner(BaseScanner):
    name     = "graphql_introspection"
    category = "passive"
    scope    = "site"
    description = "GraphQL introspection exposure"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        base   = f"{parsed.scheme}://{parsed.netloc}"
        findings: list[Finding] = []

        for path in GRAPHQL_PATHS:
            endpoint = base + path
            # Send the introspection query as JSON
            status, headers, body = await self.fetch(
                endpoint, method="POST",
                data=json.dumps(INTROSPECTION),
                headers={"Content-Type": "application/json"},
            )
            if status == -1 or not body:
                continue

            low = body.lower()
            if '"__schema"' in low or '"querytype"' in low or '"types"' in low and "name" in low:
                findings.append(Finding(
                    title       = "GraphQL Introspection Enabled",
                    severity    = Severity.MEDIUM,
                    url         = endpoint,
                    module      = self.name,
                    confidence  = Confidence.FIRM,
                    description = (
                        "The GraphQL endpoint responds to introspection queries, exposing the "
                        "entire API schema — every type, field, query and mutation. Attackers "
                        "use this to map the full attack surface."
                    ),
                    evidence    = f"POST {endpoint} returned a __schema response:\n{body[:300]}",
                    recommendation = (
                        "Disable introspection in production (e.g. in Apollo set "
                        "introspection:false). Enforce authentication, query depth/complexity "
                        "limits, and rate limiting on the GraphQL endpoint."
                    ),
                    references  = [
                        "https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html",
                    ],
                    cwe         = "CWE-200",
                ))
                break  # one endpoint is enough

        return findings
