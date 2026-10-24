"""
FSV — Certificate Transparency lookup (opt-in)
──────────────────────────────────────────────
Public CT logs list nearly every hostname that ever got a TLS certificate — the
subdomains a wordlist can't guess, including forgotten ones. This is where
dangling-record findings usually come from.

It is OFF by default (ScanConfig.use_ct_logs / --ct-logs) because it sends the
scanned domain name to a third-party service (crt.sh), and FSV is otherwise
local-first.
"""

from __future__ import annotations
import json

MAX_HOSTS = 500


def parse_crtsh(body: str, domain: str) -> list[str]:
    """Hostnames under `domain` from a crt.sh `output=json` response."""
    try:
        rows = json.loads(body)
    except ValueError:
        return []
    suffix = "." + domain.lower()
    out: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        for name in str(row.get("name_value", "")).splitlines():
            n = name.strip().lower().lstrip("*.").rstrip(".")
            if n and (n == domain.lower() or n.endswith(suffix)) and " " not in n and "@" not in n:
                out.add(n)
    return sorted(out)[:MAX_HOSTS]


async def fetch_ct_hosts(http, domain: str) -> list[str]:
    r = await http.request(f"https://crt.sh/?q=%25.{domain}&output=json")
    if not r.ok or r.status != 200:
        return []
    return parse_crtsh(r.body, domain)
