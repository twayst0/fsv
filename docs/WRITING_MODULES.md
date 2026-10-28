# Writing a module (or a plugin)

A module is one class. Everything else — the registry, CLI, dashboard, MCP, profiles — is derived from it.

```python
# ~/.fsv/plugins/robots_secrets.py        (or ship it as a package, see below)
from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence

class RobotsHintsScanner(BaseScanner):
    name        = "robots_hints"          # [a-z][a-z0-9_]*  — unique
    category    = "passive"               # "passive" sends no crafted payloads; "active" does
    scope       = "site"                  # "site": once per scan · "url": once per crawled URL
    description = "Paths that robots.txt tries to hide"      # required, one line
    external    = False                   # True if it contacts hosts other than the target
    fsv_api     = 1                       # optional: the plugin API you wrote this for (fsv.core.scanner.PLUGIN_API_VERSION)

    async def scan(self, url: str) -> list[Finding]:
        r = await self.http.request(url.rstrip("/") + "/robots.txt")   # cached, rate-limited, retried
        if not r.ok or r.status != 200:
            return []
        hidden = [l.split(":", 1)[1].strip() for l in r.body.splitlines() if l.lower().startswith("disallow:")]
        if not any("admin" in h for h in hidden):
            return []
        return [Finding(
            title="robots.txt Advertises an Admin Area", severity=Severity.INFO,
            confidence=Confidence.CERTAIN, url=url, module=self.name,
            description="…", evidence="\n".join(hidden[:10]),
            recommendation="…", cwe="CWE-200")]
```

Run `fsv modules` — it appears with its source. A plugin that fails to import or collides with a built-in name is skipped and listed
(`fsv modules`, `fsv doctor`); it can never break a scan.

`fsv_api` is optional. If you set it and a later FSV changes the module contract, the plugin is refused with a message saying so —
rather than failing in odd ways after an upgrade. The version only changes on incompatible changes (see the Changelog).

**As a package**, expose the class (or a module containing classes) via an entry point:

```toml
[project.entry-points."fsv.modules"]
robots_hints = "mypkg.robots:RobotsHintsScanner"
```

## Rules of the road
* **Fetch through `self.http.request(...)`** (or `self.fetch`). Never open your own connections: you would bypass the cache, the rate limiter and the
  outbound-address policy. For DNS use `fsv.core.dnsutil.resolve` and treat `status == "error"` as *unknown*, not as "missing".
* **Prove it before you report it.** Validate content; compare against a baseline for catch-all servers; use `Confidence.TENTATIVE` when you are guessing.
* **Mask secrets** with `fsv.core.scanner.mask_secret`. Never print a credential into `evidence`.
* **Never test a credential, never claim a resource, never send an exploit.** Detection and remediation only.
* A **title** is part of a finding's identity — keep it stable across scans (put variable details in `evidence`), otherwise triage and diffs reset.
* Set `extra={...}` for machine-readable facts other code can use (the correlation engine reads `extra["flag"]`, `extra["kind"]`…).

## Testing
`tests/helpers.py` provides `FakeHTTP({url: (status, body, headers)})` and `FakeDNS({name: {"TXT": [...], "CNAME": [...]}})` — see
`tests/test_content_modules.py` and `tests/test_dns_modules.py`. No network, no sleeping, deterministic.

```python
async def test_my_module():
    http = FakeHTTP({"https://x.com/robots.txt": (200, "Disallow: /admin/")})
    out = await RobotsHintsScanner(http, ScanConfig(target="https://x.com")).scan("https://x.com")
    assert out[0].title.startswith("robots.txt")
```
