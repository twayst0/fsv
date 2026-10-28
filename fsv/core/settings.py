"""
FSV — project configuration file (fsv.toml)
───────────────────────────────────────────
Commit your scan settings next to your code instead of a 200-character command:

    # fsv.toml
    [scan]
    profile   = "balanced"
    max_urls  = 100
    depth     = 3
    exclude   = ["/admin/*", "/logout"]
    seeds     = ["/app/dashboard"]   # pages no link points to (JS-only routes, deep links)
    max_time  = 900
    fail_on   = "high"
    baseline  = ".fsv-baseline.json"
    notify    = "${FSV_WEBHOOK}"  # POST a summary here when high+ findings exist (Slack/Discord/own endpoint)
    ct_logs   = false          # true = also ask crt.sh for subdomains (sends the domain to a 3rd party)
    external  = true           # false = skip modules that contact hosts other than the target

    [scan.headers]
    Authorization = "Bearer ${FSV_API_TOKEN}"   # ${VAR} is read from the environment — never commit secrets

Command-line flags always override the file.
"""

from __future__ import annotations
import os
import re
import tomllib

# key → expected python type(s)
SCAN_KEYS: dict[str, tuple[type, ...]] = {
    "profile": (str,), "crawl": (bool,), "max_urls": (int,), "depth": (int,), "threads": (int,),
    "timeout": (int,), "rate": (int, float), "modules": (list,), "exclude": (list,),
    "headers": (dict,), "cookies": (dict,), "tags": (list,), "robots": (bool,), "max_time": (int,),
    "fail_on": (str,), "baseline": (str,), "ct_logs": (bool,), "external": (bool,), "seeds": (list,), "proxy": (str,), "notify": (str,),
}
_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


class ConfigError(ValueError):
    pass


def _expand(value):
    """Replace ${VAR} from the environment; a missing variable is an error, never silently empty."""
    if isinstance(value, str):
        def sub(m):
            if m.group(1) not in os.environ:
                raise ConfigError(f"environment variable {m.group(1)} (used in fsv.toml) is not set")
            return os.environ[m.group(1)]
        return _ENV.sub(sub, value)
    if isinstance(value, dict):
        return {k: _expand(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand(v) for v in value]
    return value


def load_scan_config(path: str) -> dict:
    """Validated `[scan]` table from a TOML file."""
    try:
        with open(path, "rb") as fh:
            data = tomllib.load(fh)
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML — {exc}") from exc
    unknown_top = set(data) - {"scan"}
    if unknown_top:
        raise ConfigError(f"{path}: unknown section(s) {sorted(unknown_top)} (only [scan] is supported)")
    scan = data.get("scan", {})
    for key, val in scan.items():
        if key not in SCAN_KEYS:
            raise ConfigError(f"{path}: unknown key '{key}' in [scan] (valid: {', '.join(sorted(SCAN_KEYS))})")
        # bool is a subclass of int in Python — don't let `max_urls = true` through
        if isinstance(val, bool) and bool not in SCAN_KEYS[key]:
            raise ConfigError(f"{path}: '{key}' must be {SCAN_KEYS[key][0].__name__}, got a boolean")
        if not isinstance(val, SCAN_KEYS[key]):
            raise ConfigError(f"{path}: '{key}' must be {' or '.join(t.__name__ for t in SCAN_KEYS[key])}, "
                              f"got {type(val).__name__}")
    return _expand(scan)


def find_default(cwd: str | None = None) -> str | None:
    p = os.path.join(cwd or os.getcwd(), "fsv.toml")
    return p if os.path.isfile(p) else None
