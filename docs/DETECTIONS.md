# What FSV looks for that checklists miss

Most scanners tell you a header is missing. The incidents that actually hurt organisations — including
well-resourced ones — are usually quieter: a DNS record nobody remembers, an include that expired, a
source map left in a build. This is the list of those checks, why each matters, and how FSV is careful
not to cry wolf.

Everything here is **detection only**. FSV never claims a subdomain, registers a domain, creates a
bucket, or tests whether a discovered credential works.

## 1. Dangling DNS & subdomain takeover — `takeover`
**The problem.** `blog.example.com → old-project.github.io`. The project is deleted, the record stays.
Anyone can now create `old-project.github.io` and serve content from *your* subdomain — with access to
parent-domain cookies, and past any CORS/CSP/OAuth rule that trusts `*.example.com`.

**Why it is missed.** A normal "does it resolve" check fails on a dangling record and silently drops it. FSV asks
for the **CNAME explicitly**, follows the chain, and separates four outcomes:

| Outcome | Rating |
|---|---|
| target domain itself is unregistered (anyone can register it) | High, certain |
| target is a platform where released names are free (Azure, Beanstalk…) and now NXDOMAIN | High |
| target is a platform that still resolves but answers its "nothing here" page (GitHub Pages, Heroku, S3, Shopify…) | High |
| CNAME to a missing name at an unknown provider | Medium |

A resolver *error* is never reported as "dangling". Candidate names come from a wordlist, links on the page, and
(opt-in, `--ct-logs`) Certificate-Transparency logs.

## 2. Orphaned & public cloud storage — `cloud_storage`
Pages reference buckets for images, downloads and often **scripts**.
* **Orphaned**: the bucket no longer exists, so anyone can create it and serve files from the name your site trusts. Rated
  *Critical* if it is a `<script>` source (that is full control of the page), High otherwise.
* **Public listing**: the bucket lets anyone list its contents. One request with `max-keys=1`; objects are never fetched.

## 3. Email-authentication that *looks* configured — `dns_security`
* **SPF `include:` of a domain that no longer exists.** Whoever registers it can publish their own SPF record and become an
  authorised sender for you. Extremely common after a mail-provider change.
* **More than 10 DNS lookups** → PermError: SPF silently fails for *all* mail, usually right after someone adds one more SaaS.
* **DKIM keys under 1024 bit** (512-bit RSA is factorable in hours on rented hardware; 768-bit has been factored in research) and `t=y` testing mode.
* DMARC: `p=none` with no `rua` (does nothing), `sp=none` leaving subdomains spoofable, `pct<100`, duplicates.
* MTA-STS published but the policy file unreachable; delegated NS or MX that do not resolve.
* Registrable domain is computed with the public-suffix list (`example.co.uk`, not `co.uk`) and checks are skipped, with an
  explanation, when the domain does not resolve at all — a broken resolver must not produce a page of "missing record".

## 4. What shipped inside the front-end — `js_analysis`, `js_libs`
* **Source maps** that hand over the original source (and the credentials/comments inside `sourcesContent`).
* **Hard-coded credentials**: provider-specific formats (AWS, Stripe, GitHub, GitLab, npm, Slack, SendGrid, DB URLs,
  private keys…) plus an entropy-gated generic rule. Always reported **masked**, never validated.
* **Internal / non-production hostnames** in client code.
* **Vulnerable and end-of-life libraries** (jQuery, jQuery UI, Bootstrap, AngularJS, Lodash, Moment, Underscore, Vue 2,
  DOMPurify, axios) by version found in the URL or banner. A match means *inside the affected range*, not
  *exploitable here*; findings say so. Bring your own advisories with `FSV_ADVISORY_FILE`.

## 5. Exposure by configuration — `paths`, `tech`
~100 sensitive paths, **every one content-validated** (a `.git/HEAD` must look like a git HEAD, a heap dump must start with
`JAVA PROFILE`). On a catch-all/SPA server that returns 200 for everything, nothing is reported. Includes Spring Actuator
(`/env`, `/heapdump`), pprof, Laravel Telescope / logs, Symfony profiler, Terraform state, `.npmrc`, Docker config,
Elasticsearch, WordPress debug logs and user enumeration. End-of-life PHP / Apache / IIS / OpenSSL / Python / Drupal are
judged against a **dated** table, so "PHP 8.1" is flagged the day it stops getting fixes.

### Deep profile (`--profile deep`)
Adds ~90 more validated paths — `.git/index` and reflog, shell/DB history, `.git-credentials`, kubeconfig, SQLite/SQL/zip backups,
private keys (`privkey.pem`), Tomcat/Jenkins/H2/Jolokia/Solr/Elasticsearch/CouchDB consoles, Rails/Laravel/Django debug pages — plus
backups named after the host (`/example.com.zip`, `/example.sql.gz`). Secrets that a key=value masker cannot see (URLs with passwords,
typed commands, private keys) are **withheld** from the report entirely.

### Full profile (`--profile full`) — exhaustive
Everything in deep, then: the crawl reaches ≥1000 URLs at depth 6 and also follows what a plain `<a href>` crawl ignores
(`<link rel=next/prev/alternate/canonical>`, `<meta http-equiv=refresh>`, frames, `data-href`/`data-url` attributes used by JS routers,
`onclick="location.href=…"`, up to 150 scripts for quoted API routes). `content_discovery` tries ~600 common directory and page names that
nothing links to (admin, backup, staging, uploads, installers…) — calibrated first against random impossible names so a catch-all
server (200 or 403 for everything) yields nothing — and reports them as one aggregated finding, with administrative-sounding names called
out. `backup_files` asks for `.bak`, `.old`, `~`, `.orig`, `.swp`… of every crawled script/config and reports only a response that *looks
like source code* (`<?php`, `<%@`, an ini section…) and is not an HTML page; contents are never copied into the report.
SQLi gets **boolean-based** detection (`… AND 1=1` answers like the original, `… AND 1=2` does not — twice in a row, the injected text
removed from the comparison; tentative). The hidden-parameter list grows from 38 to 160 names. A full scan can send tens of thousands
of requests: the dashboard pre-selects a 1-hour limit, and `--max-time` is recommended on the CLI.

## 6. Debug mode on error pages — `debug_mode`
A crawler reads pages that work; debug pages only appear when something fails. One request for a path
that cannot exist shows what the site does with a 404: Django's `DEBUG=True` page (which also lists every
URL pattern), Rails and Symfony development pages, Laravel Ignition, Express stack traces, ASP.NET detailed
errors. Two direct checks complete it: Werkzeug's `/console` and Ignition's `/_ignition/health-check`
(`can_execute_commands: true`, the CVE-2021-3129 precondition). Signatures must all match, so a custom
404 page that merely mentions "debug" does not fire.

## 7. Third-party script supply chain — `supply_chain`
Every `<script src>` from another site runs with your page's full authority. In 2024 polyfill.io changed owners
and served malware to over 100,000 sites; the same operator ran bootcdn, bootcss and staticfile. FSV flags
scripts and stylesheets from those domains (a dated list, with what happened) and from domains that **no longer
exist** — expired, so anyone can register them and serve code into your pages. "No longer exists" needs
NXDOMAIN for both NS and SOA of the registrable domain, *and* a resolver that demonstrably answers for names that
exist (`iana.org`, `example.com`): behind filtered or captive DNS — where everything looks NXDOMAIN — nothing is
claimed. Only DNS is queried; the third-party files are never fetched.

## 8. Attack paths — `correlation`
Individually "medium" findings that combine into a compromise. FSV reads its own findings (sending nothing more) and adds a
finding when a chain is *actually present*:

| Chain | Why it is worse together |
|---|---|
| XSS **+** session cookie without HttpOnly | one crafted link = account takeover |
| no HSTS / no HTTPS **+** session cookie without Secure | session readable on any hostile network |
| takeover-able subdomain **+** session cookie scoped to the parent domain | the claimant receives your users' sessions |
| dangling SPF include **+** DMARC not enforcing | perfectly authenticated phishing as your domain |
| no SPF/DMARC enforcement at all | your domain can be spoofed |

Each chain names its links, tells the story step by step, and states **the cheapest single fix that breaks it**. If a link is
triaged away (false positive / accepted / fixed), the chain is marked *superseded* and stops counting.

---

## 9. Input handling that is actually exploitable — `xss`, `sqli`, `ssti`
**XSS is judged by context, not by "the payload appeared".** FSV sends one probe (`<token>"'<><token>`), finds every place it comes back,
classifies the syntax around it (HTML text · double/single/unquoted attribute · start of a URL attribute · JS string · JS code · comment ·
textarea/title) and checks which of `" ' < >` survived *there*. Only a spot whose breakout character is unescaped is tested with a
context-matched payload. Escaped output, comments, JSON echoes and non-HTML responses are not reported; a context that passes the
characters but filters the concrete payload is reported **tentatively** (a filter is not a fix).
**SQL injection** counts only an error that appears *after* injection (a page that always prints `SQLSTATE` is skipped), and `ora-`
must be a real `ORA-12345` code. **SSTI** probes every common syntax (`{{…}}`, `${…}`, `#{…}`, `<%= … %>`, `{…}`) with a benign product.
**Deep profile:** one request carries a unique canary for ~14 common parameter names (`q`, `search`, `lang`, `redirect`…); names whose
canary comes back are parameters the page reads and are then tested, even though no link mentions them. SQLi also tries the names
SQL-backed pages usually read (`id`, `cat`, `sort`…) once per path.

## 10. Client-side flows no server-side check can see — `dom_sinks`, `html_leaks`
FSV cannot run JavaScript, but it can *read* it. `dom_sinks` looks in inline scripts and first-party bundles (libraries are skipped) for
URL sources (`location.hash/search/href`, `document.referrer`, `window.name`) reaching `innerHTML`, `document.write`, `eval`,
`setTimeout("…")`, jQuery `.html()`/`$(location.hash)` or `location =` — directly (firm) or through a variable (tentative; sanitisers such
as DOMPurify/`textContent`/`encodeURIComponent` clear it) — and for `message` handlers that never read `event.origin`.
`html_leaks` reads what never renders: credentials, private IPs and server paths in comments (masked), a pre-filled password field,
hidden `role`/`price`/`is_admin`/`user_id` fields.

## 11. Transport and identity configuration — `ssl`, `https_redirect`, `well_known`, `api_docs`
`ssl` classifies a failed handshake from OpenSSL's own verdict (expired · not yet valid · self-signed · incomplete chain · hostname
mismatch — earlier versions called *every* failure "self-signed"), reads the certificate (RSA <2048, EC <224, SHA-1/MD5 signature,
expiry), and actually **tries TLS 1.0 and 1.1**: reading the protocol a modern client negotiates can never show that a server still offers
the old ones. `https_redirect` follows port 80 hop by hop (serves content / goes through another host over HTTP / never reaches HTTPS).
`well_known` reads OIDC discovery and JWKS — a **private or symmetric key in the JWKS** lets anyone mint tokens. `api_docs` reads exposed
OpenAPI documents and reports unauthenticated or sensitive-looking operations; it also flags Swagger UI, GraphiQL and Playground.

## Coverage: finding the pages first
Links are only part of a modern site. Before crawling, FSV also reads `robots.txt` paths, sitemaps
(including sitemap indexes), the URL list a Django debug 404 page discloses, and paths quoted in
same-origin JavaScript (`fetch('/api/items')`). Discovered paths that read like actions
(`/labs/start/…`, `/cart/clear`, `…/delete…`) are never requested. Pages nothing links to can be
added with `--seed` (or `seeds = [...]` in `fsv.toml`). Scan stats show where URLs came from
(`stats.discovered`).

### Honest limits
* The crawler reads HTML; it does not run JavaScript, so content that only exists after client-side rendering is not discovered.
* Active checks cover the common reflected classes (XSS, error-based SQLi, SSTI marker, open redirect, CORS, host header). It is
  not a replacement for a penetration test or a SAST/SCA pipeline.
* The advisory and end-of-life tables are curated snapshots. Cross-check anything important against OSV / endoflife.date.
* DNS-based checks are only as good as the resolver they run through (`fsv doctor` tests it).
* Every finding carries a **confidence** (certain / firm / tentative). Tentative findings count half in the risk score.
