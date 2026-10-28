# Changelog

## 2.3.0
**Fixed**
- **Dashboard live progress never connected.** The app-wide auth dependency asked for a `Request`, which a WebSocket does not have, so every `/ws/<scan>` handshake failed with HTTP 500 and the UI silently fell back to polling once a second. Now typed as `HTTPConnection`; regression tests cover the handshake and that the token is still enforced.
- A copy of the "re-attach to a running scan" block was pasted inside the compare-checkbox handler (it re-attached and toasted on every tick); removed.
- Keyboard shortcuts (`T`, `/`) fired while typing in the header/cookie text areas and on `Ctrl/Cmd` combinations.
- Light theme: a ticked checkbox (including "I am authorized") looked unticked, and the logo was washed out.
- The completion toast appeared twice once the WebSocket worked (WebSocket + close event + polling fallback all finished the same scan).
- The dashboard no longer requests Google Fonts: a local-first tool should not phone a third party.
- README: the "FSV and OWASP ZAP" table was broken by a stray module-catalogue row; the Action example pinned `v2.1.0`.

**Deeper scanning** — the biggest accuracy and coverage change since 2.0
- **`--profile deep`** (also in the dashboard and MCP): crawls ≥300 URLs / depth ≥4, **discovers hidden parameters** (one request carries a canary for ~14 common names; those the page echoes are tested, even though no link mentions them), probes **~90 more exposed files** plus backups named after the host (`/example.com.zip`, `/example.sql.gz`), tries every payload shape for a context, and checks whether `robots.txt` Disallow paths really answer. About 1.8× the requests on a small site; never loses a finding a normal scan would report.
- **XSS is now context-aware.** One probe finds every place an input comes back, classifies the syntax (HTML text, quoted/unquoted attribute, URL attribute, JS string, JS code, comment, textarea/title) and checks which of `" ' < >` survived *there*; a context-matched payload then confirms. No more findings for JSON echoes, comments or correctly escaped output; no more misses when only a quote or a script-block breakout is possible. A passed-through-but-filtered payload is reported tentatively.
- **SQLi** counts only a database error that appears *after* injection (a page that always prints one is skipped); `ora-` now needs a real `ORA-12345` code (it matched "flora-"). Deep also tries `id`, `cat`, `sort`… per path.
- **SSTI was broken for the most common template syntax**: the Jinja2/Twig/Nunjucks probe was built with `str.format` and went out as `{7331*7}` instead of `{{7331*7}}`, so that whole class was never detected (and the module had no tests). Fixed; probes for `${}`, `#{}`, `<%= %>` and `{}` too.
- **`ssl` rewritten**: classifies failures from OpenSSL's verdict (expired · not yet valid · self-signed · incomplete chain · hostname mismatch — it used to call *every* failure "self-signed"), reads the certificate (RSA <2048, EC <224, SHA-1/MD5 signature, expiry), and **really tries TLS 1.0 and 1.1** (reading the protocol a modern client negotiates can never reveal that a server still offers them). Pure analysis function, 17 tests.
- **Six new passive modules (38 total)**: `html_leaks` (secrets/internal hosts in HTML comments, pre-filled password fields, trust-bearing hidden fields), `dom_sinks` (DOM XSS and `postMessage` without origin check, static analysis of first-party JS), `well_known` (OIDC/OAuth discovery misconfiguration and **private/symmetric keys published in JWKS**), `api_docs` (reads exposed OpenAPI for unauthenticated/sensitive routes; Swagger UI, GraphiQL, Playground), `https_redirect` (port 80 serving content, redirect hops over HTTP, HSTS without `includeSubDomains`), `robots_review` (sensitive Disallow entries, non-production hosts in the sitemap).
- **Fixed (found by the new end-to-end test):** `form_security` copied a pre-filled password's value into the report's evidence. Previews of deep-list files whose secrets are not key=value (private keys, `.git-credentials`, shell history, tfstate, kubeconfig) are withheld entirely.

**Added**
- **Webhook notifications**: `--notify URL` / `notify` in `fsv.toml` / `FSV_WEBHOOK_URL` post a Slack- and Discord-compatible summary when a scan finds issues at or above `FSV_WEBHOOK_MIN_SEVERITY` (default `high`). Open findings only, no evidence, best-effort (10 s cap, never fails a scan). Sent by the engine, so CLI, dashboard, MCP and CI behave the same.
- **Dashboard**: sort (severity / confidence / module / URL), module filter, expand/collapse all (`E`), **bulk triage** with a checkbox per finding, one-click **re-scan**, a note dialog instead of `window.prompt`, a crawl → recon → scan → done stepper, severity share bars.
- **Dashboard motion**: spring easing, height-animated finding details (no more clipped long findings), cursor spotlight on glass cards, theme cross-fade, animated OWASP bars, toast timers; all of it off under `prefers-reduced-motion`.
- **Accessibility**: findings are keyboard-operable (`Enter`/`Space`, `aria-expanded`), triage is a real button with an arrow-key menu, dialogs trap focus and restore it, live region on progress, visible focus rings, skip link.
- **Plugin API version**: `fsv.core.scanner.PLUGIN_API_VERSION`; a plugin may pin `fsv_api = 1` and is refused with a clear message if a later FSV changes the contract.
- **Engineering**: `ruff` and `pip-audit` in CI, Dependabot (pip, Actions, Docker), unused imports removed.

## 2.2.1
- **Licence: MIT.** FSV is now released under the MIT License (2.2.0 was AGPL-3.0, earlier versions a custom non-commercial licence). The CLA now says contributions come in under MIT and create no co-ownership.
- Author shown as `twayst0` everywhere.
- **Official MCP Registry**: `server.json` (`io.github.twayst0/fsv`, runs as `uvx fsv mcp`); the publish workflow registers each new version via GitHub OIDC.
- The PyPI description carries the registry's ownership marker (`mcp-name: io.github.twayst0/fsv`); README shows the no-install `uvx fsv mcp` setup.

## 2.2.0
**Licence: GNU AGPL-3.0** (was a custom non-commercial licence). FSV is now open source: free for everyone,
companies included; whoever distributes a modified FSV or runs it as a network service must publish their
changes. Commercial licences without the AGPL obligations are available from the copyright holder (the CLA keeps
that possible). Releases up to 2.1.0 remain under their original licence.

- **Logo**: the FSV globe mark, as a vector (`docs/assets/logo.svg`) in the README hero, the dashboard header and favicon.
- **`fsv badge <scan_id>`**: a dated security-grade badge (SVG) for your own README.
- Fixed: the dashboard's GitHub button, the SARIF `informationUri` and the User-Agent pointed at a repository that isn't FSV's; the README's Action example now uses `twayst0/fsv@v2.1.0`.
- One-button release: running "Publish to PyPI" from the Actions tab uploads to PyPI, then creates the tag and GitHub release.
- **Proxy support**: `--proxy http://host:port` or `--proxy env` (HTTPS_PROXY/HTTP_PROXY, honours NO_PROXY); `proxy` in `fsv.toml`. Refused on shared deployments (`FSV_BLOCK_PRIVATE`), where it would blind the private-address guard. `fsv doctor` points it out when a proxy is set in the environment. Tested end to end with a target name only the proxy can resolve.
- Fixed: through a proxy the bare target `http://host` was requested without a path, which stricter proxies reject.
- Release workflow (`.github/workflows/release.yml`) creates the tag and GitHub release with notes from this file.

## 2.1.0
**Packaging & project**
- Published as `pip install fsv`: PEP 621 `pyproject.toml` (single version source, requirements.txt as the dependency list), PyPI page `docs/PYPI.md`, release workflow with Trusted Publishing (`.github/workflows/publish.yml`), and a CI job that builds, `twine check`s and test-installs the wheel on every push.
- Fixed: the dependency said `mcp>=1.1`, but `fsv-mcp` needs `mcp.server.mcpserver`, which only exists from mcp 2.0 — an existing mcp 1.x install would have broken the MCP server.
- Contact details, CLA draft (`CLA.md`), private security reporting by email.

**MCP, supply chain, robustness**
- `supply_chain` module (32 modules): scripts/styles from compromised or abandoned CDNs (polyfill.io and its sister domains, rawgit) or from expired domains anyone can register — guarded against filtered resolvers that answer NXDOMAIN for everything (found when the first real-world run flagged jquery.com).
- MCP: `security_review` prompt (authorization-first guided review), `fsv_verify_ownership` tool, `fsv mcp-config --client claude-code|claude-desktop|cursor|vscode`; end-to-end stdio test.
- Engine: a URL that timed out is remembered for the scan — a hanging endpoint now costs one timeout instead of one per module (hostile-server run: 66 s → 4 s); `stats.unresponsive_urls`.
- `info_disclosure`: the email pattern backtracked quadratically — 33 s on one 2 MB page; now possessive/linear, and bodies are capped at 600 kB.
- `tests/test_e2e_hostile.py`: whole-engine runs against real local servers that misbehave (catch-all SPA, redirect loop, 20 MB body, hang, 500s).
- README & visuals: monochrome metallic glass theme, MCP quick start, FSV-and-ZAP comparison.

**Tested against real applications** (OWASP PyGoat, Django) — these came out of it:
- New `debug_mode` module (31 modules): Django `DEBUG=True`, Werkzeug console, Rails/Symfony/Laravel Ignition/Express/ASP.NET debug error pages — which only appear on errors, so the crawler never saw them.
- Crawler discovery: robots.txt paths, sitemaps, Django debug-404 route lists, and API paths in same-origin JavaScript (action-like paths such as `/labs/start/…` are never requested). On PyGoat: 3 → 39 URLs. `--seed` / `seeds` / MCP `seed_urls` for pages nothing links to; MCP scans can now be authenticated (`headers`, `cookies`).
- False positives removed: anti-CSRF cookies (`csrftoken`, `XSRF-TOKEN`) no longer "missing HttpOnly" or session cookies in attack paths; HSTS not demanded over plain HTTP; CSP/Permissions/Referrer only on HTML; `X-XSS-Protection` no longer demanded (and X-Frame-Options left to `clickjacking`); `Allow: PUT` no longer "dangerous" (TRACE is now verified by echo); open redirect that only bounced back to the site's own login; Host-header "injection" when the app rejected the host with a 400; CSRF on forms posting to another site; `/admin` + `/admin/` reported twice as a "sensitive file"; robots.txt/sitemap reported as exposures; noisy "on line" stack-trace signature; HTML matched as a hard-coded password.
- Severity calibration: missing CSP/HSTS medium (was high), CSRF token missing medium (was high).
- `CSP Wildcard Source` check could never fire (spaces were stripped before matching `default-src *`).

**Docs**
- README redesigned: animated, self-contained SVGs (hero radar, terminal replay, detections, attack-path chain, pipeline) that respect `prefers-reduced-motion`, plus real dashboard screenshots (WebP).
- `examples/demo_site.py` — a deliberately vulnerable, loopback-only demo target; the README visuals are generated from a real scan of it (`scripts/build_readme_assets.sh [--screenshots]`).
- `tests/test_assets.py` keeps the images honest (well-formed, no scripts or external loads, alt text, files exist).
- Dashboard header pluralises correctly ("1 scan · 1 target").

## 2.0.0
**Detection** — 30 modules (was 23)
- `takeover`: dangling CNAME / unclaimed SaaS resource / unregistered target domain; opt-in Certificate-Transparency discovery.
- `cloud_storage`: orphaned (claimable) and publicly-listable S3 / GCS / Azure buckets referenced by pages and scripts.
- `dns_security` rewritten: SPF lookup-limit and dead `include:`/`redirect=`, DMARC subtleties, DKIM key strength, MTA-STS, dead NS/MX, DNSSEC.
- `js_analysis` (credentials, source maps, internal hosts), `js_libs` (vulnerable / end-of-life libraries), `csp_analyzer`, `sri`, `form_security`.
- `paths`: ~100 checks, **all content-validated** (+ actuator, pprof, tfstate, `.npmrc`, Docker config, Laravel/Symfony debug, Elasticsearch …).
- `tech`: end-of-life software judged against a dated table (PHP 8.0/8.1 were missed by the old "major < 8" rule).
- **Attack-path correlation**: chains of findings that are worse together, with the cheapest fix that breaks each.

**Workflow**
- Fix packs (nginx / Apache / Caddy / Express / DNS), baselines, `fsv.toml`, `--fail-on`, GitHub Action, SARIF, `fsv doctor`, `fsv verify`.
- Plugins (`~/.fsv/plugins`, `fsv.modules` entry points). Registry now derives from module classes (single source of truth).

**Safety**
- Outbound policy on every lookup and redirect hop (cloud-metadata always blocked; `FSV_BLOCK_PRIVATE`), proof-of-control for payload-sending scans (`FSV_REQUIRE_VERIFICATION`), secrets masked at the source.

**Fixes**
- Registrable domain via the public-suffix list (`example.co.uk`, not `co.uk`) in DNS modules.
- Cookie `SameSite=None` check could never fire; multiple `Set-Cookie` headers were collapsed; non-session cookies no longer rated Medium.
- Source-map URL was corrupted on short scripts. Triage state could stay stuck after a finding was re-opened (triage table is now authoritative).
- DNS findings are skipped (with an explanation) when the domain doesn't resolve, instead of a page of "missing record".
- Module failures are recorded with a reason and logged; unreachable targets are flagged.

## 1.2.0
Dashboard CSRF / DNS-rebinding guard, token auth in the UI, content-validated sensitive files, secret redaction, scan time limit, GET-form discovery, safer DB initialisation, CI.

## 1.1.0
OWASP mapping, triage, scan diff, aggregation, HTML/SARIF/CSV reports, request coalescing, new modules (CSP, SRI, forms).

## 1.0.0
Initial release.
