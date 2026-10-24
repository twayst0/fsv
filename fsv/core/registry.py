"""
FSV — Module Registry
─────────────────────
Central catalogue of scan modules with their metadata, and the logic that
selects which modules run for a given scan profile.

Metadata per module:
    scope     "site"  → run once against the base target (recon / infra)
              "url"   → run against every crawled URL (request/response)
    category  "passive" → only reads; sends no crafted payloads
              "active"  → sends test payloads / crafted requests
"""

from __future__ import annotations
from functools import lru_cache

from fsv.core.models import ScanProfile


# scope + category metadata, keyed by module name
META: dict[str, dict[str, str]] = {
    # ── recon / infrastructure (site-wide) ──
    "tech":                 {"scope": "site", "category": "passive"},
    "ssl":                  {"scope": "site", "category": "passive"},
    "dns_security":         {"scope": "site", "category": "passive"},
    "subdomain":            {"scope": "site", "category": "passive"},
    "security_txt":         {"scope": "site", "category": "passive"},
    "waf_detect":           {"scope": "site", "category": "passive"},
    "http_methods":         {"scope": "site", "category": "passive"},
    "graphql_introspection":{"scope": "site", "category": "passive"},
    "dir_listing":          {"scope": "site", "category": "passive"},
    "paths":                {"scope": "site", "category": "passive"},
    # ── per-URL passive ──
    "headers":              {"scope": "url",  "category": "passive"},
    "cookies":              {"scope": "url",  "category": "passive"},
    "clickjacking":         {"scope": "url",  "category": "passive"},
    "info_disclosure":      {"scope": "url",  "category": "passive"},
    "mixed_content":        {"scope": "url",  "category": "passive"},
    "csrf":                 {"scope": "url",  "category": "passive"},
    "jwt_analysis":         {"scope": "url",  "category": "passive"},
    "sri":                  {"scope": "url",  "category": "passive"},
    "csp_analyzer":         {"scope": "url",  "category": "passive"},
    "form_security":        {"scope": "url",  "category": "passive"},
    # ── per-URL active (send payloads) ──
    "xss":                  {"scope": "url",  "category": "active"},
    "sqli":                 {"scope": "url",  "category": "active"},
    "open_redirect":        {"scope": "url",  "category": "active"},
    "cors":                 {"scope": "url",  "category": "active"},
    "host_header_injection":{"scope": "url",  "category": "active"},
    "ssti":                 {"scope": "url",  "category": "active"},
}


DESCRIPTIONS: dict[str, str] = {
    "headers":              "Missing/weak HTTP security headers (HSTS, CSP, X-Frame-Options)",
    "ssl":                  "SSL/TLS: HTTPS, cert validity/expiry, weak protocols & ciphers",
    "xss":                  "Reflected Cross-Site Scripting in URL parameters",
    "sqli":                 "Error-based SQL injection in URL parameters",
    "cors":                 "CORS misconfiguration (wildcard, origin reflection, null)",
    "cookies":              "Cookie flags (Secure, HttpOnly, SameSite)",
    "csrf":                 "Missing CSRF protection on POST forms",
    "open_redirect":        "Open redirect in redirect-style parameters",
    "tech":                 "Technology fingerprint + outdated-software hints",
    "paths":                "Exposed sensitive files (.git, .env, backups, admin) w/ calibration",
    "info_disclosure":      "Leaked secrets, stack traces, internal IPs",
    "clickjacking":         "Missing frame protection",
    "http_methods":         "Dangerous HTTP methods (TRACE, PUT, DELETE, CONNECT)",
    "dns_security":         "Email/DNS anti-spoofing records (SPF, DMARC, CAA)",
    "dir_listing":          "Directory listing / auto-index enabled",
    "mixed_content":        "HTTP resources on HTTPS pages",
    "subdomain":            "Subdomain enumeration + sensitive subdomain exposure",
    "security_txt":         "security.txt / responsible-disclosure policy (RFC 9116)",
    "waf_detect":           "WAF/CDN fingerprinting",
    "graphql_introspection":"GraphQL introspection exposure",
    "host_header_injection":"Host header injection (redirect/cache poisoning)",
    "jwt_analysis":         "JWT weaknesses (alg:none, weak HMAC, sensitive claims)",
    "ssti":                 "Server-Side Template Injection (benign math marker)",
    "sri":                  "External scripts/styles loaded without Subresource Integrity",
    "csp_analyzer":         "Deep Content-Security-Policy review (directives, sources, reporting)",
    "form_security":        "Login/password forms: HTTPS action, autocomplete, GET submission",
}


@lru_cache(maxsize=1)
def load_registry() -> dict[str, type]:
    """Import and return {name: ScannerClass} for every module."""
    from fsv.modules.headers              import HeadersScanner
    from fsv.modules.ssl_analyzer         import SSLScanner
    from fsv.modules.xss_scanner          import XSSScanner
    from fsv.modules.sqli_scanner         import SQLiScanner
    from fsv.modules.cors_checker         import CORSScanner
    from fsv.modules.cookie_analyzer      import CookieScanner
    from fsv.modules.csrf_checker         import CSRFScanner
    from fsv.modules.open_redirect        import OpenRedirectScanner
    from fsv.modules.tech_fingerprint     import TechScanner
    from fsv.modules.path_scanner         import PathScanner
    from fsv.modules.info_disclosure      import InfoDisclosureScanner
    from fsv.modules.clickjacking         import ClickjackingScanner
    from fsv.modules.http_methods         import HTTPMethodsScanner
    from fsv.modules.dns_security         import DNSSecurityScanner
    from fsv.modules.dir_listing          import DirListingScanner
    from fsv.modules.mixed_content        import MixedContentScanner
    from fsv.modules.subdomain            import SubdomainScanner
    from fsv.modules.security_txt         import SecurityTxtScanner
    from fsv.modules.waf_detect           import WAFScanner
    from fsv.modules.graphql_introspection import GraphQLScanner
    from fsv.modules.host_header          import HostHeaderScanner
    from fsv.modules.jwt_analysis         import JWTScanner
    from fsv.modules.ssti_detection       import SSTIScanner
    from fsv.modules.sri_checker          import SRIScanner
    from fsv.modules.csp_analyzer         import CSPAnalyzerScanner
    from fsv.modules.form_security        import FormSecurityScanner
    classes = [
        HeadersScanner, SSLScanner, XSSScanner, SQLiScanner, CORSScanner,
        CookieScanner, CSRFScanner, OpenRedirectScanner, TechScanner,
        PathScanner, InfoDisclosureScanner, ClickjackingScanner,
        HTTPMethodsScanner, DNSSecurityScanner, DirListingScanner,
        MixedContentScanner, SubdomainScanner, SecurityTxtScanner,
        WAFScanner, GraphQLScanner, HostHeaderScanner, JWTScanner, SSTIScanner,
        SRIScanner, CSPAnalyzerScanner, FormSecurityScanner,
    ]
    return {c.name: c for c in classes}


def is_site_wide(name: str) -> bool:
    return META.get(name, {}).get("scope") == "site"


def is_passive(name: str) -> bool:
    return META.get(name, {}).get("category", "passive") == "passive"


def select_modules(profile: ScanProfile, available: list[str]) -> list[str]:
    """Return the module names enabled for a profile, preserving `available`."""
    if profile == ScanProfile.PASSIVE:
        return [m for m in available if is_passive(m)]
    # balanced + aggressive run everything available
    return list(available)


def all_names() -> list[str]:
    return list(META.keys())


def describe() -> list[dict[str, str]]:
    """Every module with its metadata — used by CLI, web API and MCP."""
    return [
        {
            "name":        name,
            "scope":       meta["scope"],
            "category":    meta["category"],
            "description": DESCRIPTIONS.get(name, ""),
        }
        for name, meta in META.items()
    ]
