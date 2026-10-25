"""FSV Module — JWT Weakness Analysis (passive)"""

from __future__ import annotations
import re
import json
import base64
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence


JWT_RE = re.compile(r'eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]*')


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


class JWTScanner(BaseScanner):
    name     = "jwt_analysis"
    category = "passive"
    scope    = "url"
    description = "JWT weaknesses (alg:none, weak HMAC, sensitive claims)"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1:
            return []

        # Collect JWTs from body + Set-Cookie + Authorization-like headers
        hay = (body or "")
        for k, v in headers.items():
            if k.lower() in ("set-cookie", "authorization", "x-auth-token"):
                hay += "\n" + v

        tokens = set(JWT_RE.findall(hay))
        if not tokens:
            return []

        findings: list[Finding] = []
        seen_issue: set[str] = set()

        for tok in list(tokens)[:5]:
            try:
                header_seg = tok.split(".")[0]
                hdr = json.loads(_b64url_decode(header_seg))
            except Exception:
                continue
            alg = str(hdr.get("alg", "")).lower()

            # alg: none
            if alg in ("none", ""):
                key = "alg_none"
                if key not in seen_issue:
                    seen_issue.add(key)
                    findings.append(Finding(
                        title       = "JWT Uses 'alg: none'",
                        severity    = Severity.HIGH,
                        url         = url,
                        module      = self.name,
                        confidence  = Confidence.FIRM,
                        description = (
                            "A JSON Web Token was found using the 'none' algorithm, meaning it is "
                            "unsigned. If the server accepts it, anyone can forge arbitrary tokens "
                            "and impersonate any user."
                        ),
                        evidence    = f"JWT header: {json.dumps(hdr)}",
                        recommendation = (
                            "Reject the 'none' algorithm server-side. Pin the expected algorithm "
                            "(e.g. RS256) and verify signatures with a trusted key."
                        ),
                        references  = [
                            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
                            "https://cwe.mitre.org/data/definitions/347.html",
                        ],
                        cwe         = "CWE-347",
                    ))

            # weak HMAC (HS256) exposed to client — brute-force risk
            elif alg.startswith("hs"):
                key = "hmac"
                if key not in seen_issue:
                    seen_issue.add(key)
                    findings.append(Finding(
                        title       = "JWT Signed with Symmetric HMAC (brute-force surface)",
                        severity    = Severity.LOW,
                        url         = url,
                        module      = self.name,
                        confidence  = Confidence.TENTATIVE,
                        description = (
                            f"A JWT uses a symmetric HMAC algorithm ({alg.upper()}). If the signing "
                            "secret is weak, it can be brute-forced offline, allowing token forgery."
                        ),
                        evidence    = f"JWT header: {json.dumps(hdr)}",
                        recommendation = (
                            "Use a long, high-entropy secret (≥256-bit) or switch to asymmetric "
                            "signing (RS256/ES256). Never expose the secret to clients."
                        ),
                        references  = ["https://cwe.mitre.org/data/definitions/326.html"],
                        cwe         = "CWE-326",
                    ))

            # sensitive data in payload
            try:
                payload = json.loads(_b64url_decode(tok.split(".")[1]))
                sensitive = [k for k in payload
                             if k.lower() in ("password", "pwd", "secret", "ssn", "credit_card", "card")]
                if sensitive and "payload_leak" not in seen_issue:
                    seen_issue.add("payload_leak")
                    findings.append(Finding(
                        title       = "Sensitive Data in JWT Payload",
                        severity    = Severity.MEDIUM,
                        url         = url,
                        module      = self.name,
                        confidence  = Confidence.FIRM,
                        description = (
                            "A JWT payload contains sensitive fields. JWT payloads are only "
                            "base64-encoded, not encrypted — anyone holding the token can read them."
                        ),
                        evidence    = f"Sensitive claim(s): {', '.join(sensitive)}",
                        recommendation = "Never store secrets/PII in JWT claims. Keep only non-sensitive identifiers.",
                        references  = ["https://cwe.mitre.org/data/definitions/312.html"],
                        cwe         = "CWE-312",
                    ))
            except Exception:
                pass

        return findings
