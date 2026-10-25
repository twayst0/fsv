# Architecture

```
            ┌─────────────┐   ┌──────────────┐   ┌─────────────┐
 CLI ───────►              │   │              │   │             │
 Web API ───►  run_scan()   ├──►  modules     ├──►  aggregate   ├──► correlate ──► triage overlay ──► SQLite
 MCP tools ─►  (engine)     │   │ (site + url) │   │ (fingerprint)│   (attack paths)   (per-host)
            └──────┬──────┘   └──────┬───────┘   └─────────────┘
                   │                 │
            ┌──────▼──────┐   ┌──────▼───────┐
            │ Crawler     │   │ HTTPClient   │  cache · request coalescing · token-bucket rate limit ·
            │ same-origin │   │ + guarded    │  retries · body cap · stats      │ DNS: dnsutil (swappable)
            │ BFS waves   │   │   connector  │  metadata/private-range policy on every lookup & redirect hop
            └─────────────┘   └──────────────┘
```

## Pipeline (`fsv/core/engine.py`)
1. **Pre-flight** — `check_target` (address policy), proof-of-control if `FSV_REQUIRE_VERIFICATION` and the scan sends payloads.
2. **Crawl** — exact-origin BFS, a wave of pages at a time, through the shared client (so pages fetched here are free for every module).
   Skips assets, logout/destructive links and `--exclude` globs; GET forms become parameterised URLs; POST forms are never submitted.
3. **Site modules** (once, concurrently) then **URL modules** (URL × module jobs, bounded by a semaphore).
4. **Post-processing** — aggregate findings by fingerprint → add attack paths → sort.
5. **Persist** — triage decisions are overlaid from their own table; the scan JSON is a snapshot.

## Design decisions worth knowing
* **One source of truth for modules.** A module is a class declaring `name / category / scope / description / external`; the registry derives
  everything from the classes (there used to be a second table that could drift). Plugins load the same way and a broken plugin cannot break FSV.
* **Fingerprint = module + title + parameter + *host*** (not path). One missing header on 40 pages is one issue; the same issue in the next scan is
  the *same* issue, which is what makes triage persistence, diffing and baselines work.
* **Triage is not stored in the scan.** The `triage` table (per host + fingerprint) is the single source of truth; an overlay applies it on every read. Re-opening
  a finding really re-opens it. Attack paths follow the state of their links.
* **DNS has four outcomes, not two** (`dnsutil.Answer`: ok / nodata / nxdomain / error). "Doesn't exist" and "couldn't ask" must never be conflated or you
  report phantom dangling records whenever the network hiccups. The backend is injectable, so DNS logic is tested against a fake zone.
* **Validate content, not status codes.** Exposure checks accept a response only if the body is the thing it claims to be.
* **Secrets are masked at the source** (`mask_secret`, `redact_preview`), so reports and logs never become a second copy of a leak.
* **Safety is layered where it can't be bypassed.** The outbound address policy and proof-of-control sit in the engine, so CLI, web, MCP and CI all get them. Request guard (Host / Origin / JSON-only) and token auth belong to the web server, where the browser threat model lives; a CLI user already has a shell.
* **Failures are visible.** A module that crashes is counted, its first error is stored and logged (`-v`), and the dashboard shows a "results may be incomplete" bar.

## Layout
```
fsv/core/      engine · scanner base · registry · http_client · dnsutil · netsafety · ownership
               models · taxonomy (CWE→OWASP) · correlate · diff · baseline · settings · fixes · report · database
               content (page/script collection) · secrets · eol · ct
fsv/modules/   one file per check (31)
fsv/web/       FastAPI + request guard + dashboard (static/)
fsv/mcp/       MCP server (stdio)
fsv/cli.py     command line
tests/         fakes for HTTP and DNS in tests/helpers.py — no network required
```
