<div align="center">

# FSV

### Web Vulnerability Scanner & MCP Security Toolkit

A defensive web security scanner in the spirit of **OWASP ZAP**, **Nikto**, and **Skipfish** — rebuilt as a clean, modern engine with a glassmorphism dashboard and a first-class **MCP server** so AI agents can run authorized assessments and produce remediation reports.

**26 modules** · `headers` · `ssl/tls` · `xss` · `sqli` · `ssti` · `cors` · `cookies` · `csrf` · `open-redirect` · `host-header` · `sensitive-files` · `info-disclosure` · `clickjacking` · `tech-fingerprint` · `http-methods` · `dns-security` · `dir-listing` · `mixed-content` · `subdomain-enum` · `waf-detect` · `security.txt` · `graphql-introspection` · `jwt-analysis` · `csp-analyzer` · `sri` · `form-security`

</div>

---

> ### ⚠ Authorized use only
> FSV is a security **assessment** tool. Use it **only** against systems you own or are **explicitly authorized in writing** to test. Scanning systems without permission is illegal in most jurisdictions. Every entry point (web, CLI, MCP) requires you to confirm authorization before a scan runs. You are responsible for how you use it.

---

## Features

- **26 scan modules** covering the most common classes of web vulnerabilities, each finding mapped to a **CWE**, an **OWASP Top 10 (2021)** category, a severity, a **confidence** level (certain/firm/tentative), a CVSS estimate, evidence, and concrete **remediation** steps.
- **Scan profiles** — `passive` (no payloads sent), `balanced` (safe active checks, default), `aggressive` (higher rate & concurrency).
- **Shared HTTP engine** — a single request pipeline with **response caching**, **request coalescing** (concurrent identical GETs share one in-flight fetch), **token-bucket rate limiting**, **automatic retries with backoff**, a response-body size cap, and rich per-scan **statistics** (requests, cache hits, coalesced, retries, errors, status-code breakdown, average latency).
- **Risk score & letter grade** — a weighted 0–100 risk score (confidence-adjusted, with diminishing returns per severity) and an A+→F grade for an at-a-glance verdict.
- **Finding aggregation** — the same issue on 40 pages collapses into one finding carrying every affected URL, instead of 40 duplicate rows.
- **Triage that sticks** — mark a finding *false positive*, *accepted risk*, *fixed* or *confirmed*; the decision is stored per host by a stable fingerprint and re-applied to every future scan, and triaged-away findings drop out of the risk score.
- **Scan diffing** — compare any two scans (before/after a fix) for resolved / new / persisted findings, a risk delta, and an improved/regressed verdict; per-host **risk trend** over time.
- **Five report formats** — Markdown (OWASP-grouped, with an executive summary), JSON, a self-contained **HTML** report, **SARIF 2.1** for GitHub code scanning / CI, and **CSV** for spreadsheets/ticket import.
- **Plugin registry** — modules self-describe their scope (site/url) and category (passive/active); adding a module is one file + one registry line.
- **Smart crawler** — strict same-origin (netloc) BFS that fetches a wave of pages at a time, skips assets and logout/destructive links, honours exclude-path globs, and has an optional `robots.txt` mode.
- **Async engine** — concurrent crawling and scanning on `asyncio` + `aiohttp`, bounded-concurrency semaphore, and live **cancellation**.
- **Liquid-glass dashboard** — a refined glassmorphism UI with an animated risk gauge, count-up stats, an **OWASP Top 10 breakdown**, a per-host **risk-trend sparkline**, inline **triage** controls, a **module picker** + advanced options drawer, **scan comparison**, live progress over WebSocket (lost-event-safe), severity filters, full-text search, keyboard shortcuts, and one-click export in any of the five formats.
- **MCP server** — plug FSV into Claude, Cursor, or any MCP-capable agent. Ask your AI to install FSV and scan a site you own; it gets back structured findings and a report.
- **CLI** — scriptable scans with rich terminal output.
- **Local-first** — results stored in a local SQLite DB (`~/.fsv/scans.db`). Nothing phones home.

## Install

```bash
git clone https://github.com/fsvproject/fsv.git
cd fsv
./install.sh
source .venv/bin/activate
```

Or manually:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

Requires **Python 3.10+**.

## Usage

### Web dashboard

```bash
fsv web
# → http://127.0.0.1:7474
```

Enter a target, tick the authorization box, and run. Progress streams live; findings are grouped by severity and exportable.

### CLI

```bash
# Full scan (authorization flag is mandatory)
fsv scan example.com --authorize

# Scan a single URL, no crawl, write a report
fsv scan "https://example.com/search?q=test" --authorize --no-crawl -o report.md

# Only specific modules, and exclude paths from the crawl
fsv scan example.com --authorize --modules headers,ssl,xss,sqli
fsv scan example.com --authorize --exclude "/admin/*,/logout" --tag prod

# Authenticated scan (extra headers / cookies, repeatable)
fsv scan example.com --authorize --header "Authorization: Bearer X" --cookie "session=abc"

# Export a report in any format (inferred from extension)
fsv scan example.com --authorize -o report.html      # or .md / .json / .sarif / .csv

# CI gate — exit non-zero if a high-or-worse finding exists
fsv scan example.com --authorize --fail-on high

# List past scans / print or export a report
fsv list                       # filter with --target example.com
fsv report <scan_id> --format html -o report.html
fsv findings <scan_id>         # show finding IDs for triage

# Triage a finding (persists per host, carries to future scans)
fsv triage <scan_id> <finding_id> false_positive --note "test endpoint"

# Compare two scans (before/after a fix)
fsv diff <baseline_id> <current_id>

# Housekeeping
fsv prune --keep 50
fsv modules                    # list all modules, --json for machine output
```

### MCP server

Run the server:

```bash
fsv mcp
```

Register it with your AI client. Example `claude_desktop_config.json` / MCP client config:

```json
{
  "mcpServers": {
    "fsv": {
      "command": "fsv-mcp"
    }
  }
}
```

> If you installed in a virtualenv, point `command` at the venv binary, e.g.
> `"/path/to/fsv/.venv/bin/fsv-mcp"`.

Then, in your AI client, you can say things like:

> *"I own example.com. Use FSV to run a security scan and summarize the critical issues with fixes."*

The agent calls `fsv_scan` with `authorized=true`, then `fsv_get_report` for the formatted writeup.

**MCP tools exposed:**

| Tool | Purpose |
|------|---------|
| `fsv_scan` | Full active scan (all modules) |
| `fsv_quick_check` | Fast passive check (headers, SSL, cookies, tech) — no payloads sent |
| `fsv_get_report` | Report for a scan (md / json / html / sarif / csv) |
| `fsv_list_scans` | List recent scans (filter by host) |
| `fsv_compare_scans` | Diff two scans — resolved / new / verdict |
| `fsv_target_trend` | Risk-score trend for a host over time |
| `fsv_triage` | Mark a finding FP / accepted / fixed (persists per host) |
| `fsv_scan_stats` | HTTP statistics for a scan |
| `fsv_list_modules` | Describe all scan modules |

## Scan modules

| Module | Checks for | Typical severity |
|--------|-----------|------------------|
| `headers` | Missing/weak HSTS, CSP, X-Frame-Options, X-Content-Type-Options, etc. | info–high |
| `ssl` | HTTP-only, expired/self-signed certs, weak TLS protocols & ciphers | medium–critical |
| `xss` | Reflected cross-site scripting in URL parameters | high |
| `sqli` | Error-based SQL injection in URL parameters | critical |
| `cors` | Wildcard origin, arbitrary origin reflection, null origin + credentials | medium–critical |
| `cookies` | Missing Secure / HttpOnly / SameSite flags | low–high |
| `csrf` | POST forms lacking CSRF tokens and SameSite protection | high |
| `open_redirect` | External redirects via `next`, `url`, `redirect`, … params | medium |
| `paths` | Exposed `.git`, `.env`, backups, admin panels, API docs (with catch-all calibration) | low–critical |
| `info_disclosure` | Leaked keys/secrets, stack traces, internal IPs | low–critical |
| `clickjacking` | Missing frame protection | medium |
| `tech` | Technology fingerprint + outdated-software hints | info–medium |
| `http_methods` | Dangerous HTTP methods enabled (TRACE, PUT, DELETE, CONNECT) | low–high |
| `dns_security` | Email/DNS anti-spoofing records (SPF, DMARC, CAA) | low–medium |
| `dir_listing` | Directory listing / auto-index enabled | medium |
| `mixed_content` | HTTP resources loaded on HTTPS pages | low–medium |
| `subdomain` | Subdomain enumeration + exposed sensitive subdomains | info–medium |
| `ssti` | Server-Side Template Injection (benign math marker, no RCE) | critical |
| `host_header_injection` | Host header injection → redirect / cache poisoning | low–medium |
| `jwt_analysis` | JWT weaknesses (alg:none, weak HMAC, sensitive claims) | low–high |
| `waf_detect` | WAF/CDN fingerprinting (Cloudflare, AWS, Akamai, …) | info |
| `security_txt` | security.txt / disclosure policy (RFC 9116) | info–low |
| `graphql_introspection` | GraphQL introspection exposure | medium |
| `csp_analyzer` | Deep CSP review (missing object-src/base-uri/frame-ancestors, wildcard sources, report-only, no reporting) | info–medium |
| `sri` | Third-party scripts/styles without Subresource Integrity | low |
| `form_security` | Password forms over HTTP, submitted via GET, missing autocomplete hints | info–high |

### Scan profiles

```bash
fsv scan example.com --authorize --profile passive      # no payloads, safe recon
fsv scan example.com --authorize --profile balanced     # default
fsv scan example.com --authorize --profile aggressive   # all modules, higher rate
```

### MCP tools

`fsv_scan` · `fsv_quick_check` · `fsv_waf_check` · `fsv_get_report` (md/json/html/sarif/csv) · `fsv_list_scans` · `fsv_compare_scans` · `fsv_target_trend` · `fsv_triage` · `fsv_scan_stats` · `fsv_list_modules`

## Architecture

```
fsv/
├── core/
│   ├── engine.py      crawler + orchestration + aggregation
│   ├── scanner.py     BaseScanner (shared fetch helpers)
│   ├── http_client.py cache · coalescing · rate limit · retries · stats
│   ├── models.py      typed models, validation, risk scoring, triage states
│   ├── taxonomy.py    CWE → OWASP Top 10 mapping
│   ├── database.py    SQLite (scans + triage), auto-migrating
│   ├── diff.py        scan comparison
│   └── report.py      md / json / html / sarif / csv
├── modules/           one file per scan module (26)
├── web/               FastAPI API + glassmorphism dashboard (static/)
├── mcp/               MCP server (stdio)
└── cli.py             command-line interface
```

The engine crawls the target within its exact origin, then runs site-wide modules
once (tech, SSL, DNS, paths) and per-URL modules against each discovered URL under a
bounded-concurrency semaphore. Findings are aggregated by a host-scoped fingerprint
(so one issue across many pages is one finding), triage decisions are overlaid, and
the result is sorted by severity then confidence.

### Configuration (environment variables)

| Variable | Default | Purpose |
|----------|---------|---------|
| `FSV_HOST` / `FSV_PORT` | `127.0.0.1` / `7474` | dashboard bind address |
| `FSV_DB` | `~/.fsv/scans.db` | SQLite database path |
| `FSV_TOKEN` | *(unset)* | if set, every `/api` and `/ws` call must send it (`X-FSV-Token` header or `?token=`) — recommended when not bound to loopback |
| `FSV_MAX_SCANS` | `3` | max concurrent scans the web server will run |
| `FSV_DISABLED_MODULES` | *(none)* | comma-separated module names to disable without code changes |

### CI gating

```bash
# fail the build if any high-or-worse finding exists
fsv scan example.com --authorize --fail-on high -o report.sarif
```

## How reports work

FSV reports are **defensive**: each finding explains *what* the issue is, *why* it
matters (impact), and *how to fix it* (remediation), with CWE and OWASP references.
FSV does not generate weaponized exploits — it tells you where you're exposed and
how to close the gap.

## License

**FSV Personal Use License** — free for personal, educational, and non-commercial
security research. **Commercial use is prohibited.** See [LICENSE](LICENSE).

## Disclaimer

This software is provided "as is", for lawful, authorized security testing only.
The authors accept no liability for misuse or damage. Always obtain written
permission before testing any system you do not own.
