"""OIDC discovery, JWKS, OpenAPI and API-explorer exposure."""
import json

from fsv.core.models import ScanConfig, Severity
from fsv.modules import api_docs as A
from fsv.modules import well_known as W
from helpers import HTML, FakeHTTP

JSON = {"Content-Type": "application/json"}


def cfg():
    return ScanConfig(target="https://x.test")


def titles(fs):
    return [f.title for f in fs]


# ── discovery ──
def test_discovery_flags_http_endpoints_alg_none_implicit_password_and_missing_pkce():
    doc = {"issuer": "http://id.x.test", "authorization_endpoint": "http://id.x.test/auth", "token_endpoint": "https://id.x.test/token",
           "id_token_signing_alg_values_supported": ["RS256", "none"], "response_types_supported": ["code", "id_token token"],
           "grant_types_supported": ["authorization_code", "password"], "code_challenge_methods_supported": ["plain"]}
    out = W.analyze_discovery(doc, "https://x.test/.well-known/openid-configuration")
    assert set(titles(out)) == {"OAuth/OIDC Endpoints Advertised Over HTTP", "OIDC Provider Accepts Unsigned Tokens (alg=none)",
                                "OAuth Implicit Flow Is Enabled", "OAuth Password Grant (ROPC) Is Enabled", "PKCE (S256) Is Not Advertised"}
    assert next(f for f in out if "Over HTTP" in f.title).evidence.count("http://") == 2


def test_clean_discovery_document_is_silent():
    doc = {"issuer": "https://id.x.test", "authorization_endpoint": "https://id.x.test/a", "token_endpoint": "https://id.x.test/t",
           "id_token_signing_alg_values_supported": ["RS256"], "response_types_supported": ["code"],
           "grant_types_supported": ["authorization_code", "refresh_token"], "code_challenge_methods_supported": ["S256"]}
    assert W.analyze_discovery(doc, "u") == []


def test_localhost_http_endpoints_are_not_flagged():
    assert W.analyze_discovery({"issuer": "http://localhost:8080/realms/dev", "code_challenge_methods_supported": ["S256"]}, "u") == []


# ── JWKS ──
def test_private_and_symmetric_keys_in_jwks_are_critical_and_values_withheld():
    jwks = {"keys": [{"kty": "RSA", "kid": "a", "n": "AQAB", "e": "AQAB", "d": "SECRETPRIVATE", "p": "x", "q": "y"},
                     {"kty": "oct", "kid": "b", "k": "SUPERSECRETHMAC"}]}
    out = W.analyze_jwks(jwks, "u")
    assert [f.severity for f in out] == [Severity.CRITICAL, Severity.CRITICAL]
    blob = " ".join(f.evidence + f.description for f in out)
    assert "SECRETPRIVATE" not in blob and "SUPERSECRETHMAC" not in blob


def test_weak_rsa_modulus_in_jwks():
    import base64
    n = base64.urlsafe_b64encode(b"\xff" * 128).decode().rstrip("=")          # 1024-bit
    out = W.analyze_jwks({"keys": [{"kty": "RSA", "kid": "k", "n": n, "e": "AQAB"}]}, "u")
    assert titles(out) == ["Weak RSA Signing Key in JWKS (1024-bit)"]
    ok = base64.urlsafe_b64encode(b"\xff" * 256).decode().rstrip("=")
    assert W.analyze_jwks({"keys": [{"kty": "RSA", "n": ok, "e": "AQAB"}]}, "u") == []


async def test_well_known_module_fetches_same_site_jwks_from_discovery():
    disc = {"issuer": "https://x.test", "jwks_uri": "https://keys.x.test/jwks", "authorization_endpoint": "https://x.test/a",
            "code_challenge_methods_supported": ["S256"]}
    http = FakeHTTP({"https://x.test/.well-known/openid-configuration": (200, json.dumps(disc), JSON),
                     "https://keys.x.test/jwks": (200, json.dumps({"keys": [{"kty": "oct", "k": "zzzz", "kid": "1"}]}), JSON)})
    out = await W.WellKnownScanner(http, cfg()).scan("https://x.test/")
    assert titles(out) == ["Symmetric Key Published in JWKS"]


async def test_well_known_ignores_third_party_jwks_and_non_json():
    disc = {"issuer": "https://x.test", "jwks_uri": "https://evil.example/jwks", "authorization_endpoint": "https://x.test/a",
            "code_challenge_methods_supported": ["S256"]}
    http = FakeHTTP({"https://x.test/.well-known/openid-configuration": (200, json.dumps(disc), JSON),
                     "https://evil.example/jwks": (200, json.dumps({"keys": [{"kty": "oct", "k": "z"}]}), JSON)})
    assert await W.WellKnownScanner(http, cfg()).scan("https://x.test/") == []
    spa = FakeHTTP({"https://x.test/.well-known/openid-configuration": (200, "<html>app</html>", HTML)})
    assert await W.WellKnownScanner(spa, cfg()).scan("https://x.test/") == []


# ── OpenAPI ──
SPEC = {"openapi": "3.0.0", "info": {"title": "t"}, "servers": [{"url": "http://api.x.test"}],
        "paths": {"/users/{id}": {"get": {}}, "/admin/export": {"post": {}}, "/health": {"get": {}}}}


def test_openapi_without_security_schemes_is_reported_with_sensitive_routes():
    out = A.analyze_openapi(SPEC, "u")
    main = next(f for f in out if f.title.startswith("Public API Specification Lists"))
    assert main.severity == Severity.MEDIUM and "/admin/export" in main.evidence
    assert main.extra["operations"] == 3
    assert any("HTTP (Non-TLS)" in t for t in titles(out))


def test_openapi_with_global_auth_and_one_public_health_check_is_quiet():
    spec = {"openapi": "3.0.0", "components": {"securitySchemes": {"b": {"type": "http", "scheme": "bearer"}}}, "security": [{"b": []}],
            "paths": {"/orders": {"get": {}}, "/health": {"get": {"security": []}}}}
    assert A.analyze_openapi(spec, "u") == []


def test_example_credentials_in_a_spec_are_masked():
    spec = {"openapi": "3.0.0", "components": {"securitySchemes": {"b": {}}}, "security": [{"b": []}],
            "paths": {"/p": {"get": {"description": "use key " + "sk_" + "live_" + "51H8abcdefghijklmnopqrstuv"}}}}
    f = next(f for f in A.analyze_openapi(spec, "u") if f.title.startswith("Credentials"))
    assert "51H8abcdefghijklmnopqrstuv" not in f.evidence


def test_non_openapi_json_is_ignored():
    assert A.analyze_openapi({"hello": "world"}, "u") == []


async def test_api_docs_module_finds_ui_spec_and_graphiql():
    http = FakeHTTP({
        "https://x.test/docs": (200, '<html><div id="swagger-ui"></div><script>SwaggerUIBundle({url: "/openapi.json"})</script></html>', HTML),
        "https://x.test/openapi.json": (200, json.dumps(SPEC), JSON),
        "https://x.test/graphiql": (200, "<html><title>GraphiQL</title></html>", HTML),
    })
    out = await A.APIDocsScanner(http, cfg()).scan("https://x.test/")
    t = titles(out)
    assert "API Documentation UI Is Publicly Accessible" in t
    assert any(x.startswith("Public API Specification Lists") for x in t)
    assert "GraphQL IDE (GraphiQL / Playground) Is Publicly Accessible" in t


async def test_catch_all_spa_produces_nothing():
    class SPA(FakeHTTP):
        async def request(self, url, method="GET", **kw):
            from fsv.core.http_client import Response
            return Response(status=200, headers=HTML, body="<html><div id=root></div></html>", url=url)
    assert await A.APIDocsScanner(SPA(), cfg()).scan("https://x.test/") == []
