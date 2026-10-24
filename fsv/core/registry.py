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
    # ── per-URL active (send payloads) ──
    "xss":                  {"scope": "url",  "category": "active"},
    "sqli":                 {"scope": "url",  "category": "active"},
    "open_redirect":        {"scope": "url",  "category": "active"},
    "cors":                 {"scope": "url",  "category": "active"},
    "host_header_injection":{"scope": "url",  "category": "active"},
    "ssti":                 {"scope": "url",  "category": "active"},
}


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
    classes = [
        HeadersScanner, SSLScanner, XSSScanner, SQLiScanner, CORSScanner,
        CookieScanner, CSRFScanner, OpenRedirectScanner, TechScanner,
        PathScanner, InfoDisclosureScanner, ClickjackingScanner,
        HTTPMethodsScanner, DNSSecurityScanner, DirListingScanner,
        MixedContentScanner, SubdomainScanner, SecurityTxtScanner,
        WAFScanner, GraphQLScanner, HostHeaderScanner, JWTScanner, SSTIScanner,
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
