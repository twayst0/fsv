"""
FSV Module — /.well-known: OpenID Connect / OAuth discovery and JWKS

Identity providers publish their configuration at well-known URLs, and the file is a precise map of what the
server will accept. FSV reads it and judges the *configuration*:

  • discovery document: HTTP (non-TLS) endpoints, `none` accepted as a signing algorithm, implicit flow,
    password grant (ROPC), PKCE (S256) not advertised
  • JWKS: **a private or symmetric key published in the key set** (critical — anyone can mint tokens),
    and RSA keys under 2048 bits

Same-site documents only; nothing is fetched from third-party issuers. Read-only GETs.
"""

from __future__ import annotations
import base64
import json
from urllib.parse import urlparse

from fsv.core.models import Confidence, Finding, Severity
from fsv.core.netsafety import registrable_domain
from fsv.core.scanner import BaseScanner

DISCOVERY = ("/.well-known/openid-configuration", "/.well-known/oauth-authorization-server")
JWKS_DEFAULT = "/.well-known/jwks.json"
_PRIVATE_PARAMS = ("d", "p", "q", "dp", "dq", "qi")
_REFS = ["https://openid.net/specs/openid-connect-discovery-1_0.html", "https://datatracker.ietf.org/doc/html/rfc9700"]


def _b64len(value: str) -> int:
    try:
        return len(base64.urlsafe_b64decode(value + "=" * (-len(value) % 4)))
    except Exception:                                              # noqa: BLE001
        return 0


def analyze_discovery(doc: dict, url: str, module: str = "well_known") -> list[Finding]:
    out: list[Finding] = []

    def add(title, sev, desc, rec, cwe, evidence, conf=Confidence.CERTAIN):
        out.append(Finding(title=title, severity=sev, confidence=conf, url=url, module=module, description=desc,
                           evidence=evidence, recommendation=rec, references=_REFS, cwe=cwe))

    insecure = [f"{k}: {v}" for k, v in doc.items()
                if k.endswith(("_endpoint", "_uri", "issuer")) and isinstance(v, str)
                and v.lower().startswith("http://") and urlparse(v).hostname not in ("localhost", "127.0.0.1", "::1")]
    if insecure:
        add("OAuth/OIDC Endpoints Advertised Over HTTP", Severity.HIGH,
            "The discovery document points clients at plain-HTTP endpoints. Authorization codes, tokens and client credentials sent there can be read or altered on the network.",
            "Serve every endpoint over HTTPS only and fix the issuer / endpoint URLs the identity provider generates (often a missing X-Forwarded-Proto behind a proxy).",
            "CWE-319", "\n".join(insecure[:6]))
    algs = doc.get("id_token_signing_alg_values_supported") or []
    if any(str(a).lower() == "none" for a in algs):
        add("OIDC Provider Accepts Unsigned Tokens (alg=none)", Severity.HIGH,
            "`none` is listed as a supported ID-token signing algorithm: a client that trusts this list may accept tokens with no signature at all.",
            "Remove `none` from the supported algorithms; require RS256/ES256 (or stronger).", "CWE-347", f"id_token_signing_alg_values_supported: {algs}")
    rts = [str(r) for r in (doc.get("response_types_supported") or [])]
    implicit = [r for r in rts if "token" in r.split()]
    if implicit:
        add("OAuth Implicit Flow Is Enabled", Severity.LOW,
            "Implicit-flow response types return tokens in the URL fragment, where browser history, extensions and referrers can read them. It is deprecated by OAuth 2.0 Security BCP.",
            "Use the authorization-code flow with PKCE and disable the implicit response types.", "CWE-522",
            f"response_types_supported: {rts}", Confidence.FIRM)
    if "password" in [str(g) for g in (doc.get("grant_types_supported") or [])]:
        add("OAuth Password Grant (ROPC) Is Enabled", Severity.MEDIUM,
            "The resource-owner password grant makes every client handle raw passwords, defeats MFA and phishing protection, and is removed in OAuth 2.1.",
            "Disable the password grant; use the authorization-code flow with PKCE.", "CWE-522",
            f"grant_types_supported: {doc.get('grant_types_supported')}", Confidence.FIRM)
    pkce = [str(m) for m in (doc.get("code_challenge_methods_supported") or [])]
    if doc.get("authorization_endpoint") and "S256" not in pkce:
        add("PKCE (S256) Is Not Advertised", Severity.LOW,
            "The server does not advertise PKCE with S256. Without PKCE, a stolen authorization code can be redeemed by an attacker (public clients especially).",
            "Support and require `code_challenge_method=S256` for all clients.", "CWE-345",
            f"code_challenge_methods_supported: {pkce or 'absent'}", Confidence.FIRM)
    return out


def analyze_jwks(doc: dict, url: str, module: str = "well_known") -> list[Finding]:
    out: list[Finding] = []
    for key in doc.get("keys", []) if isinstance(doc, dict) else []:
        if not isinstance(key, dict):
            continue
        kid, kty = key.get("kid", "?"), str(key.get("kty", ""))
        if kty == "oct" and key.get("k"):
            out.append(Finding(
                title="Symmetric Key Published in JWKS", severity=Severity.CRITICAL, confidence=Confidence.CERTAIN, url=url, module=module,
                description="The public key set contains a symmetric (HMAC) secret. Anyone who reads it can sign tokens the server will accept — full authentication bypass.",
                evidence=f"kid={kid} kty=oct (secret material present — value withheld)",
                recommendation="Remove it from the JWKS immediately, rotate the secret, and invalidate every token signed with it. Publish public keys only.",
                references=_REFS, cwe="CWE-321", cvss_score=9.8))
        elif any(p in key for p in _PRIVATE_PARAMS) and kty in ("RSA", "EC", "OKP"):
            out.append(Finding(
                title="Private Key Material Published in JWKS", severity=Severity.CRITICAL, confidence=Confidence.CERTAIN, url=url, module=module,
                description="The JWKS contains private-key parameters (RSA d/p/q… or EC d). Anyone can sign tokens as this server.",
                evidence=f"kid={kid} kty={kty} private parameters: {', '.join(p for p in _PRIVATE_PARAMS if p in key)} (values withheld)",
                recommendation="Remove the private parameters, generate a new key pair, rotate, and treat every token issued with the old key as forgeable.",
                references=_REFS, cwe="CWE-321", cvss_score=9.8))
        elif kty == "RSA" and key.get("n") and _b64len(key["n"]) * 8 < 2048:
            bits = _b64len(key["n"]) * 8
            out.append(Finding(
                title=f"Weak RSA Signing Key in JWKS ({bits}-bit)", severity=Severity.HIGH, confidence=Confidence.CERTAIN, url=url, module=module,
                description=f"A {bits}-bit RSA key is below the 2048-bit minimum and can be factored with modest resources, letting an attacker forge tokens.",
                evidence=f"kid={kid} modulus ≈ {bits} bits", recommendation="Rotate to RSA 2048+ (or ES256).", references=_REFS, cwe="CWE-326"))
    return out


class WellKnownScanner(BaseScanner):
    name        = "well_known"
    category    = "passive"
    scope       = "site"
    description = "/.well-known OIDC/OAuth discovery & JWKS: http endpoints, alg=none, implicit/password grants, published private keys"

    async def _json(self, url: str):
        r = await self.http.request(url)
        if not r.ok or r.status != 200 or not r.body:
            return None
        try:
            doc = json.loads(r.body)
        except ValueError:
            return None
        return doc if isinstance(doc, dict) else None

    async def scan(self, url: str) -> list[Finding]:
        p = urlparse(url)
        base = f"{p.scheme}://{p.netloc}"
        out: list[Finding] = []
        jwks_urls = [base + JWKS_DEFAULT]
        for path in DISCOVERY:
            doc = await self._json(base + path)
            if doc and ("issuer" in doc or "authorization_endpoint" in doc or "token_endpoint" in doc):
                out += analyze_discovery(doc, base + path, self.name)
                uri = doc.get("jwks_uri")
                if isinstance(uri, str) and registrable_domain(urlparse(uri).hostname or "") == registrable_domain(p.hostname or ""):
                    jwks_urls.insert(0, uri)
                break
        for u in dict.fromkeys(jwks_urls):
            doc = await self._json(u)
            if doc and isinstance(doc.get("keys"), list):
                out += analyze_jwks(doc, u, self.name)
                break
        return out
