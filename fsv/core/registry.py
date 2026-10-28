"""
FSV — Module Registry
─────────────────────
The catalogue of scan modules and the logic that selects which run for a profile.

Single source of truth: every module class declares `name`, `category`, `scope`
and `description` itself; this registry derives everything from the classes
(there used to be a second hand-maintained table that could silently drift).

Plugins
    Third-party modules are discovered, in this order, from
      1. the `fsv.modules` entry-point group (pip-installable packages)
      2. *.py files in ~/.fsv/plugins (override with FSV_PLUGIN_DIR)
    Each must expose BaseScanner subclasses. A broken plugin never breaks FSV:
    it is skipped and listed in `plugin_errors()`.
    Set FSV_NO_PLUGINS=1 to disable discovery entirely.
"""

from __future__ import annotations
import importlib.util
import os
import re
import sys
from importlib import metadata
from pathlib import Path

from fsv.core.models import ScanProfile
from fsv.core.scanner import PLUGIN_API_VERSION, BaseScanner

_VALID_CATEGORY = {"passive", "active"}
_VALID_SCOPE    = {"site", "url"}
_NAME_RE        = re.compile(r"^[a-z][a-z0-9_]{1,40}$")

# Populated by load_registry(); mutated in place so `from registry import META`
# stays valid for callers that imported the dict object.
META: dict[str, dict] = {}
_REGISTRY: dict[str, type[BaseScanner]] = {}
_PLUGIN_ERRORS: list[str] = []
_LOADED = False


def _builtin_classes() -> list[type[BaseScanner]]:
    from fsv.modules.headers               import HeadersScanner
    from fsv.modules.ssl_analyzer          import SSLScanner
    from fsv.modules.xss_scanner           import XSSScanner
    from fsv.modules.sqli_scanner          import SQLiScanner
    from fsv.modules.cors_checker          import CORSScanner
    from fsv.modules.cookie_analyzer       import CookieScanner
    from fsv.modules.csrf_checker          import CSRFScanner
    from fsv.modules.open_redirect         import OpenRedirectScanner
    from fsv.modules.tech_fingerprint      import TechScanner
    from fsv.modules.path_scanner          import PathScanner
    from fsv.modules.info_disclosure       import InfoDisclosureScanner
    from fsv.modules.clickjacking          import ClickjackingScanner
    from fsv.modules.http_methods          import HTTPMethodsScanner
    from fsv.modules.dns_security          import DNSSecurityScanner
    from fsv.modules.dir_listing           import DirListingScanner
    from fsv.modules.mixed_content         import MixedContentScanner
    from fsv.modules.subdomain             import SubdomainScanner
    from fsv.modules.security_txt          import SecurityTxtScanner
    from fsv.modules.waf_detect            import WAFScanner
    from fsv.modules.graphql_introspection import GraphQLScanner
    from fsv.modules.host_header           import HostHeaderScanner
    from fsv.modules.jwt_analysis          import JWTScanner
    from fsv.modules.ssti_detection        import SSTIScanner
    from fsv.modules.sri_checker           import SRIScanner
    from fsv.modules.csp_analyzer          import CSPAnalyzerScanner
    from fsv.modules.form_security         import FormSecurityScanner
    return [
        TechScanner, SSLScanner, DNSSecurityScanner, SubdomainScanner, SecurityTxtScanner,
        WAFScanner, HTTPMethodsScanner, GraphQLScanner, DirListingScanner, PathScanner,
        HeadersScanner, CookieScanner, ClickjackingScanner, InfoDisclosureScanner,
        MixedContentScanner, CSRFScanner, JWTScanner, SRIScanner, CSPAnalyzerScanner,
        FormSecurityScanner, XSSScanner, SQLiScanner, OpenRedirectScanner, CORSScanner,
        HostHeaderScanner, SSTIScanner,
    ] + _extra_builtin_classes()


def _extra_builtin_classes() -> list[type[BaseScanner]]:
    """Modules added after v1.x live in fsv.modules and are listed here."""
    out: list[type[BaseScanner]] = []
    for mod, cls in _EXTRA:
        m = importlib.import_module(f"fsv.modules.{mod}")
        out.append(getattr(m, cls))
    return out


# (module file, class name) — kept separate so adding a module is one line
_EXTRA: list[tuple[str, str]] = [
    ("takeover", "TakeoverScanner"),
    ("js_analysis", "JSAnalysisScanner"),
    ("js_libs", "JSLibsScanner"),
    ("cloud_storage", "CloudStorageScanner"),
    ("debug_mode", "DebugModeScanner"),
    ("supply_chain", "SupplyChainScanner"),
    ("html_leaks", "HTMLLeaksScanner"),
    ("dom_sinks", "DOMSinksScanner"),
    ("well_known", "WellKnownScanner"),
    ("api_docs", "APIDocsScanner"),
    ("https_redirect", "HTTPSRedirectScanner"),
    ("robots_review", "RobotsReviewScanner"),
]


def problems_with(cls: type) -> list[str]:
    """Why a class is not a valid module (empty list = valid). Used by the loader and tests."""
    errs = []
    if not (isinstance(cls, type) and issubclass(cls, BaseScanner)) or cls is BaseScanner:
        return ["not a BaseScanner subclass"]
    if not _NAME_RE.match(getattr(cls, "name", "") or ""):
        errs.append(f"invalid name {getattr(cls, 'name', None)!r} (use [a-z][a-z0-9_]*)")
    if cls.category not in _VALID_CATEGORY:
        errs.append(f"category must be one of {sorted(_VALID_CATEGORY)}, got {cls.category!r}")
    if cls.scope not in _VALID_SCOPE:
        errs.append(f"scope must be one of {sorted(_VALID_SCOPE)}, got {cls.scope!r}")
    if not (cls.__dict__.get("description") or "").strip():
        errs.append("missing class-level `description`")
    pinned = cls.__dict__.get("fsv_api")
    if pinned is not None and pinned != PLUGIN_API_VERSION:
        errs.append(f"written for plugin API {pinned!r}, this FSV provides API {PLUGIN_API_VERSION} — update the plugin")
    return errs


def _register(cls: type[BaseScanner], source: str) -> None:
    errs = problems_with(cls)
    if errs:
        raise ValueError("; ".join(errs))
    if cls.name in _REGISTRY and _REGISTRY[cls.name] is not cls:
        raise ValueError(f"name '{cls.name}' already provided by "
                         f"{_REGISTRY[cls.name].__module__}")
    _REGISTRY[cls.name] = cls
    META[cls.name] = {
        "scope": cls.scope, "category": cls.category,
        "description": cls.description, "external": cls.external, "source": source,
    }


def _plugin_dir() -> Path:
    return Path(os.getenv("FSV_PLUGIN_DIR", os.path.expanduser("~/.fsv/plugins")))


def _scanner_classes_in(module) -> list[type[BaseScanner]]:
    return [obj for obj in vars(module).values()
            if isinstance(obj, type) and issubclass(obj, BaseScanner)
            and obj is not BaseScanner and obj.__module__ == module.__name__]


def _load_plugins() -> None:
    if os.getenv("FSV_NO_PLUGINS", "").lower() in ("1", "true", "yes"):
        return
    # 1) entry points
    try:
        eps = metadata.entry_points(group="fsv.modules")
    except Exception as exc:                      # pragma: no cover
        _PLUGIN_ERRORS.append(f"entry points: {exc}")
        eps = []
    for ep in eps:
        try:
            obj = ep.load()
            for cls in (_scanner_classes_in(obj) if not isinstance(obj, type) else [obj]):
                _register(cls, f"plugin:{ep.name}")
        except Exception as exc:
            _PLUGIN_ERRORS.append(f"entry point '{ep.name}': {exc}")
    # 2) plugin directory
    d = _plugin_dir()
    if d.is_dir():
        for path in sorted(d.glob("*.py")):
            if path.name.startswith("_"):
                continue
            modname = f"fsv_plugin_{path.stem}"
            try:
                spec = importlib.util.spec_from_file_location(modname, path)
                mod = importlib.util.module_from_spec(spec)
                sys.modules[modname] = mod
                spec.loader.exec_module(mod)
                for cls in _scanner_classes_in(mod):
                    _register(cls, f"plugin:{path.name}")
            except Exception as exc:
                sys.modules.pop(modname, None)
                _PLUGIN_ERRORS.append(f"{path.name}: {exc}")


def load_registry(reload: bool = False) -> dict[str, type[BaseScanner]]:
    """Return {name: ScannerClass} for every built-in module and valid plugin."""
    global _LOADED
    if _LOADED and not reload:
        return _REGISTRY
    _REGISTRY.clear(); META.clear(); _PLUGIN_ERRORS.clear()
    for cls in _builtin_classes():
        _register(cls, "builtin")
    _load_plugins()
    _LOADED = True
    return _REGISTRY


def plugin_errors() -> list[str]:
    load_registry()
    return list(_PLUGIN_ERRORS)


def is_site_wide(name: str) -> bool:
    load_registry()
    return META.get(name, {}).get("scope") == "site"


def is_passive(name: str) -> bool:
    load_registry()
    return META.get(name, {}).get("category", "passive") == "passive"


def select_modules(profile: ScanProfile, available: list[str]) -> list[str]:
    """Return the module names enabled for a profile, preserving `available`."""
    if profile == ScanProfile.PASSIVE:
        return [m for m in available if is_passive(m)]
    # balanced + aggressive run everything available
    return list(available)


def all_names() -> list[str]:
    return list(load_registry())


def describe() -> list[dict]:
    """Every module with its metadata — used by CLI, web API and MCP."""
    load_registry()
    return [{"name": name, **meta} for name, meta in META.items()]


# Populate eagerly so `registry.META` is usable right after import (engine uses it).
load_registry()
