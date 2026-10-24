# Changelog

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
