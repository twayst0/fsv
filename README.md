<div align="center">

# FSV

### Web security scanner that finds what checklists miss — and tells you how to fix it

Dangling DNS & subdomain takeover · orphaned cloud buckets · SPF includes that expired · source maps & secrets in your JavaScript ·
end-of-life software · and the **attack paths** that combine small findings into a real compromise.
Runs as a **CLI**, a **dashboard**, an **MCP server** for AI agents, and a **CI step**.

**30 modules** · defensive, detection-only · local-first · `pip install` and go

</div>

---

> ### ⚠ Authorized use only
> FSV is a security **assessment** tool. Use it **only** against systems you own or are **explicitly authorized in writing** to test. Scanning systems without permission is illegal in most jurisdictions. Every entry point (web, CLI, MCP, CI) requires you to confirm authorization, and a shared deployment can additionally require **proof of control** of the target before any payload is sent ([docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)).

---

## Why FSV

Plenty of tools tell you a header is missing. The incidents that actually hurt organisations — including very well-run ones — are quieter, and they
tend to be in places nobody is looking:

| | What it is | Module |
|---|---|---|
| 🪝 | A **DNS record outlived its project** (`blog.example.com → old-app.github.io`): anyone can claim the name and serve content from your domain | `takeover` |
| 🪣 | A page still loads a script from a **storage bucket that no longer exists** — whoever creates it controls your page | `cloud_storage` |
| ✉️ | An **SPF `include:` of an expired domain**, an SPF record over the **10-lookup limit**, a **512-bit DKIM key** — "email auth is set up" but doesn't hold | `dns_security` |
| 🗺️ | **Source maps** and **hard-coded credentials** shipped to every visitor | `js_analysis` |
| 🧱 | **jQuery 3.3.1 / AngularJS 1.x / Vue 2** and **PHP 8.1** past end of support | `js_libs`, `tech` |
| ⛓️ | **XSS + a session cookie without HttpOnly** = account takeover. Two "medium" findings, one critical story | `correlation` |

Details, and how FSV avoids false alarms, in **[docs/DETECTIONS.md](docs/DETECTIONS.md)**.

## Features

- **Attack-path correlation** — reads its own findings and, where a chain is really present, adds one that names the links, tells the story step by step, and states **the cheapest single fix that breaks it**. A chain disappears when one of its links is triaged away.
- **Fix packs** — turn findings into paste-ready **nginx / Apache / Caddy / Express / DNS** configuration (`fsv fixes <scan> nginx`). Only what was actually found; CSP is emitted report-only.
- **CI-ready** — `fsv.toml` project config, **baselines** (gate only on *new* findings), `--fail-on`, SARIF for GitHub code scanning, and a ready-made **GitHub Action**.
- **Triage that sticks** — false positive / accepted risk / fixed / confirmed, stored per host by stable fingerprint, re-applied to every later scan, excluded from the score. Diff any two scans; per-host risk trend.
- **Evidence over guesses** — exposure checks validate *content* (a `.git/HEAD` must look like one; a SPA that answers 200 to everything produces nothing); every finding has a **confidence** (certain / firm / tentative), a CWE, an OWASP Top 10 (2021) category, impact and remediation.
- **Honest failure** — a crashing module is counted, explained and logged; a target that never answered is flagged, not graded "clean"; a broken resolver doesn't turn into a page of "missing SPF".
- **Safe by construction** — secrets are *masked at the source* and never validated; outbound policy blocks cloud-metadata/link-local always (loopback/RFC 1918 optionally) on every lookup and redirect hop; dashboard has CSRF / DNS-rebinding protection and token auth.
- **Extensible** — a module is one class; drop a file in `~/.fsv/plugins` or ship an entry-point package ([docs/WRITING_MODULES.md](docs/WRITING_MODULES.md)). Bring your own JS-library advisories and EOL dates.
- **Fast & polite** — async engine, shared HTTP client with response cache, request coalescing, token-bucket rate limit, retries, size cap, time limit with partial results.
- **Five report formats** — Markdown (OWASP-grouped), JSON, self-contained HTML, SARIF 2.1, CSV.
- **Liquid-glass dashboard** — risk gauge, **attack-path panel**, OWASP breakdown, trend sparkline, inline triage, module picker, scan compare, live progress that survives a page reload.
- **MCP server** — Claude, Cursor or any MCP client can run an authorized assessment, lead with the attack paths, and generate the fixes.
- **Local-first** — results in a local SQLite file. Nothing phones home; the only optional third-party calls are listed in [DEPLOYMENT.md](docs/DEPLOYMENT.md#network-egress).

## Install

```bash
git clone <this repository> && cd fsv
./install.sh && source .venv/bin/activate     # or:  python -m venv .venv && . .venv/bin/activate && pip install .
fsv doctor                                    # checks Python, dependencies, DNS, database, plugins
```

Requires **Python 3.11+**. Docker: see [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) (`docker compose up`).

## Quick start

```bash
fsv scan example.com --authorize                       # full scan of a site you own
fsv scan example.com --authorize --profile passive     # read-only: no payloads sent
fsv web                                                # dashboard → http://127.0.0.1:7474
```

### CLI

```bash
# scope & tuning
fsv scan example.com --authorize --exclude "/admin/*,/logout" --max-urls 100 --max-time 900 --tag prod
fsv scan example.com --authorize --header "Authorization: Bearer X" --cookie "session=abc"    # authenticated
fsv scan example.com --authorize --ct-logs        # also ask Certificate Transparency (crt.sh) for subdomains*
fsv scan example.com --authorize --no-external    # skip modules that contact hosts other than the target

# reports & fixes
fsv scan example.com --authorize -o report.html   # .md .json .html .sarif .csv
fsv report <scan_id> --format fix-nginx           # or fix-apache fix-caddy fix-express fix-dns
fsv fixes  <scan_id> nginx -o nginx-fixes.md

# triage, history, diff
fsv findings <scan_id>
fsv triage <scan_id> <finding_id> false_positive --note "test endpoint"
fsv list --target example.com   ·   fsv diff <before_id> <after_id>   ·   fsv prune --keep 50

# ownership proof (for shared deployments)           # * sends the domain name to crt.sh
fsv verify example.com   ·   fsv verify example.com --check

fsv modules   ·   fsv doctor
```

### In CI

```toml
# fsv.toml  (commit it; ${VAR} is read from the environment — never commit secrets)
[scan]
profile  = "balanced"
max_urls = 100
exclude  = ["/admin/*"]
max_time = 900
fail_on  = "high"
baseline = ".fsv-baseline.json"
[scan.headers]
Authorization = "Bearer ${FSV_API_TOKEN}"
```

```bash
fsv scan staging.example.com --authorize --write-baseline .fsv-baseline.json    # once: accept today's state
fsv scan staging.example.com --authorize                                         # every build: fails only on NEW high+ findings
```

```yaml
# .github/workflows/security.yml   (the action lives in this repository's action.yml)
- uses: <owner>/fsv@<tag-or-sha>
  with:
    target: https://staging.example.com
    authorized: "true"          # you confirm you may test this target
    profile: balanced
    fail-on: high
    baseline: .fsv-baseline.json
```
SARIF is uploaded to GitHub code scanning; the HTML report and log are attached as an artifact.

### MCP (AI agents)

```json
{ "mcpServers": { "fsv": { "command": "fsv-mcp" } } }
```
> *"I own example.com. Use FSV to scan it, tell me the attack paths first, then give me the nginx fixes."*

| Tool | Purpose |
|---|---|
| `fsv_scan` | Full scan (profiles, scope, time-box; CT logs and external checks opt-in) |
| `fsv_quick_check` / `fsv_waf_check` | Passive posture check / WAF-CDN detection |
| `fsv_get_report` | md · json · html · sarif · csv · `fix-*` |
| `fsv_fixes` | Paste-ready nginx / apache / caddy / express / DNS remediation |
| `fsv_triage` | Mark false positive / accepted / fixed (persists per host) |
| `fsv_compare_scans` · `fsv_target_trend` | Before/after a fix · risk over time |
| `fsv_list_scans` · `fsv_scan_stats` · `fsv_list_modules` | History · request stats · catalogue |

Scan results carry an `attack_paths` section so the agent can lead with what matters.

## Modules (30)

| Module | Looks for | Kind |
|---|---|---|
| `takeover` | dangling CNAME / unclaimed SaaS resource / unregistered target domain | passive · site · ↗ |
| `cloud_storage` | orphaned or publicly-listable S3 / GCS / Azure buckets referenced by the site | passive · url · ↗ |
| `dns_security` | SPF (10-lookup limit, dead includes, `+all`), DMARC, DKIM key strength, MTA-STS, dead NS/MX, CAA, DNSSEC | passive · site |
| `js_analysis` | hard-coded credentials, exposed source maps, internal/non-prod hosts in client code | passive · url |
| `js_libs` | known-vulnerable & end-of-life JavaScript libraries | passive · url |
| `paths` | ~100 exposed files/endpoints, each content-validated (`.git`, `.env`, actuator, pprof, tfstate, backups…) | passive · site |
| `tech` | stack fingerprint + **end-of-life** software from a dated table | passive · site |
| `headers` · `csp_analyzer` | security headers · deep CSP review | passive |
| `ssl` | HTTPS, certificate validity, weak protocols/ciphers | passive · site |
| `cookies` | Secure / HttpOnly / SameSite / parent-domain scope | passive |
| `sri` · `mixed_content` · `clickjacking` · `form_security` · `csrf` | page-level hygiene | passive |
| `info_disclosure` · `dir_listing` · `http_methods` · `security_txt` · `waf_detect` · `graphql_introspection` · `jwt_analysis` · `subdomain` | exposure & recon | passive |
| `xss` · `sqli` · `ssti` · `open_redirect` · `cors` · `host_header_injection` | reflected/error-based/marker checks (benign payloads) | **active** |

↗ contacts hosts other than the target (skip with `--no-external`). `passive` = sends no crafted payloads. **Profiles:** `passive` (only passive modules), `balanced` (default), `aggressive` (higher rate/concurrency).

## Configuration

| Variable | Default | Purpose |
|---|---|---|
| `FSV_HOST` / `FSV_PORT` | `127.0.0.1` / `7474` | dashboard bind address |
| `FSV_DB` | `~/.fsv/scans.db` | SQLite database |
| `FSV_TOKEN` | — | shared secret required on every API / WebSocket call (`X-FSV-Token` or `?token=`) |
| `FSV_ALLOWED_HOSTS` | — | extra `Host` names the dashboard answers to (DNS-rebinding guard) |
| `FSV_BLOCK_PRIVATE` | off | refuse loopback / RFC 1918 targets (SSRF protection). Cloud-metadata ranges are *always* refused |
| `FSV_REQUIRE_VERIFICATION` | off | payload-sending scans only against hosts whose owner proved control |
| `FSV_MAX_SCANS` | `3` | concurrent scans |
| `FSV_DISABLED_MODULES` | — | comma-separated module names to turn off |
| `FSV_PLUGIN_DIR` / `FSV_NO_PLUGINS` | `~/.fsv/plugins` / off | plugin discovery |
| `FSV_ADVISORY_FILE` / `FSV_EOL_FILE` | — | your own JS-library advisories / end-of-life dates (JSON) |

## Limits — what FSV is *not*

* It reads HTML; it does **not execute JavaScript**, so content that only exists after client-side rendering isn't discovered.
* Active checks cover common reflected classes with benign markers. It is **not** a replacement for a penetration test, SAST or an SCA pipeline.
* The JS-advisory and end-of-life tables are curated snapshots — cross-check with OSV / endoflife.date for anything important, and extend them with the files above.
* DNS checks are only as good as the resolver (`fsv doctor` tests it). A resolver that can't answer produces *no* DNS findings, not bad ones.
* Findings carry a **confidence**; tentative ones are hints. Triage them, and tell us about false positives — they're the most useful bug reports.

## Documentation

[Detections](docs/DETECTIONS.md) · [Architecture](docs/ARCHITECTURE.md) · [Writing modules](docs/WRITING_MODULES.md) · [Deploying safely](docs/DEPLOYMENT.md) · [Security policy](SECURITY.md) · [Contributing](CONTRIBUTING.md) · [Changelog](CHANGELOG.md)

## License

**FSV Personal Use License** — free for personal, educational, and non-commercial
security research. **Commercial use is prohibited.** See [LICENSE](LICENSE).

## Disclaimer

This software is provided "as is", for lawful, authorized security testing only.
The authors accept no liability for misuse or damage. Always obtain written
permission before testing any system you do not own.
