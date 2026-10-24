<div align="center">

# FSV

### Web Vulnerability Scanner & MCP Security Toolkit

A defensive web security scanner in the spirit of **OWASP ZAP**, **Nikto**, and **Skipfish** — rebuilt as a clean, modern engine with a glassmorphism dashboard and a first-class **MCP server** so AI agents can run authorized assessments and produce remediation reports.

**23 modules** · `headers` · `ssl/tls` · `xss` · `sqli` · `ssti` · `cors` · `cookies` · `csrf` · `open-redirect` · `host-header` · `sensitive-files` · `info-disclosure` · `clickjacking` · `tech-fingerprint` · `http-methods` · `dns-security` · `dir-listing` · `mixed-content` · `subdomain-enum` · `waf-detect` · `security.txt` · `graphql-introspection` · `jwt-analysis`

</div>

---

> ### ⚠ Authorized use only
> FSV is a security **assessment** tool. Use it **only** against systems you own or are **explicitly authorized in writing** to test. Scanning systems without permission is illegal in most jurisdictions. Every entry point (web, CLI, MCP) requires you to confirm authorization before a scan runs. You are responsible for how you use it.

---

## Features

- **23 scan modules** covering the most common classes of web vulnerabilities, each finding mapped to a **CWE**, a severity, a **confidence** level (certain/firm/tentative), a CVSS estimate, evidence, and concrete **remediation** steps.
- **Scan profiles** — `passive` (no payloads sent), `balanced` (safe active checks, default), `aggressive` (higher rate & concurrency).
- **Shared HTTP engine** — a single request pipeline with **response caching** (identical GETs fetched once, not once per module), **token-bucket rate limiting** (politeness), **automatic retries with backoff**, and per-scan **statistics** (requests, cache hits, retries, errors, bytes).
- **Risk score & letter grade** — a weighted 0–100 risk score and an A+→F grade for an at-a-glance verdict.
- **Plugin registry** — modules self-describe their scope (site/url) and category (passive/active); adding a module is one file + one registry line.
- **Smart crawler** — same-origin BFS that skips assets and logout/destructive links, with an optional `robots.txt` mode.
- **Async engine** — concurrent crawling and scanning on `asyncio` + `aiohttp`, bounded-concurrency semaphore, and live **cancellation**.
- **Liquid-glass dashboard** — a refined black/white glassmorphism UI with an animated risk gauge, count-up stats, staggered finding reveals, toast notifications, live scan progress over WebSocket, severity filters, full-text search, and one-click Markdown/JSON export.
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

# Only specific modules
fsv scan example.com --authorize --modules headers,ssl,xss,sqli

# List past scans / print a report
fsv list
fsv report <scan_id>
fsv modules
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
| `fsv_get_report` | Markdown remediation report for a scan |
| `fsv_list_scans` | List recent scans |
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

### Scan profiles

```bash
fsv scan example.com --authorize --profile passive      # no payloads, safe recon
fsv scan example.com --authorize --profile balanced     # default
fsv scan example.com --authorize --profile aggressive   # all modules, higher rate
```

### MCP tools

`fsv_scan` · `fsv_quick_check` · `fsv_waf_check` · `fsv_get_report` · `fsv_list_scans` · `fsv_compare_scans` (before/after a fix) · `fsv_scan_stats` · `fsv_list_modules`

## Architecture

```
fsv/
├── core/        engine · scanner base · models · report · sqlite
├── modules/     one file per scan module
├── web/         FastAPI API + glassmorphism dashboard (static/)
├── mcp/         MCP server (stdio)
└── cli.py       command-line interface
```

The engine crawls the target within its origin, then runs site-wide modules once
(tech, SSL, paths) and per-URL modules against each discovered URL. Findings are
deduplicated and sorted by severity.

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
