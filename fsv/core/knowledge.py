"""
FSV — Vulnerability Knowledge Base
──────────────────────────────────
A single source of truth that turns a bare finding into a *teaching* finding.

Every module only has to state the essentials (title, severity, where, CWE).
This module enriches each finding with the three things a reader actually needs:

    • impact            — what this weakness *triggers*: what an attacker gains,
                          what breaks, what the blast radius is.
    • attack_scenario   — a concrete, step-by-step story of how it is abused
                          (defensive framing: "an attacker could…", no payload kits).
    • owasp             — the OWASP Top 10 (2021) category it maps to.
    • references         — authoritative links (merged with the module's own).
    • remediation_steps  — an ordered, actionable fix list.

Enrichment is keyed by CWE, so adding one CWE entry upgrades every finding that
carries it across all modules at once. Modules may still override any field.
"""

from __future__ import annotations
from datetime import datetime, timezone


# ── OWASP Top 10 (2021) catalogue ────────────────────────────────────────────

OWASP_TOP10: dict[str, str] = {
    "A01": "A01:2021 – Broken Access Control",
    "A02": "A02:2021 – Cryptographic Failures",
    "A03": "A03:2021 – Injection",
    "A04": "A04:2021 – Insecure Design",
    "A05": "A05:2021 – Security Misconfiguration",
    "A06": "A06:2021 – Vulnerable and Outdated Components",
    "A07": "A07:2021 – Identification and Authentication Failures",
    "A08": "A08:2021 – Software and Data Integrity Failures",
    "A09": "A09:2021 – Security Logging and Monitoring Failures",
    "A10": "A10:2021 – Server-Side Request Forgery (SSRF)",
}


# ── per-CWE knowledge ─────────────────────────────────────────────────────────
# Each entry: impact, attack_scenario, owasp (A0x key), refs, remediation steps.

KB: dict[str, dict] = {
    # ── Injection family ──────────────────────────────────────────────────
    "CWE-79": {
        "name": "Cross-Site Scripting (XSS)",
        "owasp": "A03",
        "impact": (
            "Lets an attacker run arbitrary JavaScript in the browser of any user who "
            "views the affected page. That script runs with the victim's session, so it "
            "can steal session cookies and auth tokens, perform actions as the victim "
            "(transfer funds, change email/password), capture keystrokes and form data, "
            "deface the page, redirect to phishing, or pivot to internal apps the victim "
            "can reach. Stored XSS can turn a single page into a self-spreading worm."
        ),
        "attack_scenario": (
            "1. The attacker finds that a parameter is reflected into the page without "
            "encoding.\n"
            "2. They craft a link (or a stored comment/profile field) containing a script.\n"
            "3. A logged-in victim opens the link or views the page.\n"
            "4. The script executes in the victim's authenticated context and exfiltrates "
            "the session cookie / CSRF token to the attacker, who replays it to take over "
            "the account."
        ),
        "remediation_steps": [
            "Context-aware output encoding: HTML-encode in HTML body, attribute-encode in "
            "attributes, JS-encode in script contexts, URL-encode in URLs.",
            "Prefer a framework that auto-escapes by default (React, Angular, Vue, Django, "
            "Rails) and never bypass it (no dangerouslySetInnerHTML / |safe / html_safe on "
            "untrusted data).",
            "Deploy a strict Content-Security-Policy with nonces/hashes and without "
            "'unsafe-inline' / 'unsafe-eval' as defence-in-depth.",
            "Set HttpOnly on session cookies so stolen script cannot read them.",
            "Validate and canonicalise input on the server; reject unexpected types/charsets.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html",
            "https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html",
        ],
    },
    "CWE-89": {
        "name": "SQL Injection",
        "owasp": "A03",
        "impact": (
            "Gives an attacker direct influence over the database query. Depending on the "
            "DB and privileges this means: reading every row in every table (full data "
            "breach — users, password hashes, PII, payment data), modifying or deleting "
            "records, bypassing authentication (login as any user), and on many setups "
            "escalating to command execution on the database host or lateral movement into "
            "the internal network. It is one of the highest-impact web weaknesses."
        ),
        "attack_scenario": (
            "1. The attacker appends a SQL metacharacter to a parameter and observes a "
            "database error or a change in results.\n"
            "2. They confirm injection with boolean/time-based probes.\n"
            "3. They enumerate the schema, then dump credential and PII tables.\n"
            "4. Cracked or reused password hashes are replayed against admin panels and "
            "other services, turning one injectable parameter into a full compromise."
        ),
        "remediation_steps": [
            "Use parameterised queries / prepared statements everywhere — never build SQL "
            "by string concatenation or interpolation of user input.",
            "Prefer a mature ORM (SQLAlchemy, Django ORM, Hibernate, Prisma) and keep raw "
            "SQL escape hatches parameterised.",
            "Apply least-privilege DB accounts (the web user should not be able to DROP, "
            "or read other schemas).",
            "Disable verbose/stack-trace DB errors in production; return generic errors.",
            "Add allow-list input validation and a WAF as defence-in-depth, not as the "
            "primary control.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "CWE-94": {
        "name": "Code Injection",
        "owasp": "A03",
        "impact": (
            "Server-side evaluation of attacker input leads to remote code execution. The "
            "attacker can run commands on the application server, read/modify any file the "
            "process can access, harvest secrets and cloud credentials, and use the host as "
            "a foothold into the internal network. This is typically a full-server compromise."
        ),
        "attack_scenario": (
            "1. The attacker supplies a template/expression marker in an input that is "
            "evaluated server-side.\n"
            "2. A benign arithmetic probe (e.g. 7*7 → 49) confirms evaluation.\n"
            "3. From there, template/expression gadgets are chained to reach the runtime "
            "and execute OS commands — reading environment secrets and deploying a shell."
        ),
        "remediation_steps": [
            "Never pass user input into a template engine, eval(), or expression evaluator.",
            "Use logic-less templates and render untrusted data only as data (auto-escaped "
            "variables), never as template source.",
            "Sandbox the template engine and disable dangerous builtins where supported.",
            "Run the app as a low-privilege user with a read-only filesystem where possible.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html",
        ],
    },
    "CWE-1336": {
        "name": "Server-Side Template Injection",
        "owasp": "A03",
        "impact": (
            "The template engine evaluates attacker-controlled input, which usually escalates "
            "to remote code execution on the server — exposing secrets, source code, cloud "
            "credentials and the internal network."
        ),
        "attack_scenario": (
            "1. Input is embedded into a server-side template.\n"
            "2. An arithmetic marker confirms evaluation.\n"
            "3. Engine-specific gadgets are chained to reach the runtime and run commands."
        ),
        "remediation_steps": [
            "Render untrusted data as data, never as template source.",
            "Use auto-escaping, logic-less templates; disable or sandbox risky features.",
            "Isolate rendering in a low-privilege, locked-down process.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Template_Injection_Prevention_Cheat_Sheet.html",
        ],
    },

    # ── Broken access control / request forgery ──────────────────────────
    "CWE-352": {
        "name": "Cross-Site Request Forgery (CSRF)",
        "owasp": "A01",
        "impact": (
            "An attacker can make an authenticated victim's browser submit state-changing "
            "requests (change email/password, transfer money, change settings, delete data) "
            "without the victim's intent. The victim's valid session is abused silently — no "
            "credential theft is needed, only that they are logged in and visit a hostile page."
        ),
        "attack_scenario": (
            "1. The attacker hosts a page with an auto-submitting form (or image) targeting a "
            "sensitive endpoint that lacks an anti-CSRF token.\n"
            "2. A logged-in victim visits that page.\n"
            "3. The browser automatically attaches the victim's session cookie, and the "
            "action (e.g. email change → account takeover) executes server-side."
        ),
        "remediation_steps": [
            "Require a per-session, unpredictable anti-CSRF token on every state-changing "
            "request and validate it server-side.",
            "Set SameSite=Lax (or Strict) on session cookies.",
            "For APIs, require a custom header / double-submit token and verify Origin/Referer.",
            "Re-authenticate or require a second factor for the most sensitive actions.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },
    "CWE-601": {
        "name": "Open Redirect",
        "owasp": "A01",
        "impact": (
            "The site will bounce users to an arbitrary external URL. This supercharges "
            "phishing (the link genuinely starts on the trusted domain), can be chained to "
            "steal OAuth tokens / SSO codes via redirect_uri abuse, and is used to bypass "
            "allow-list filters and leak credentials in the Referer."
        ),
        "attack_scenario": (
            "1. The attacker crafts a link to the trusted site with a redirect parameter "
            "pointing to their own look-alike domain.\n"
            "2. The victim trusts the visible domain and clicks.\n"
            "3. They land on the attacker's phishing clone — or, in an OAuth flow, the auth "
            "code is delivered to the attacker's endpoint, granting account access."
        ),
        "remediation_steps": [
            "Avoid redirecting to user-supplied URLs; use server-side mapping of IDs → URLs.",
            "If external redirects are needed, enforce a strict allow-list of hosts.",
            "Reject absolute URLs, protocol-relative (//evil) and backslash tricks; only "
            "allow relative paths.",
            "In OAuth/SSO, exact-match redirect_uri against pre-registered values.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html",
        ],
    },
    "CWE-918": {
        "name": "Server-Side Request Forgery (SSRF)",
        "owasp": "A10",
        "impact": (
            "The server can be coerced into making requests to attacker-chosen destinations, "
            "including internal-only services and cloud metadata endpoints. This leaks cloud "
            "credentials (e.g. instance metadata), reaches internal admin panels and "
            "databases behind the firewall, and can pivot into the internal network."
        ),
        "attack_scenario": (
            "1. The attacker supplies an internal URL to a feature that fetches remote "
            "resources.\n"
            "2. The server fetches the cloud metadata service and returns temporary "
            "credentials.\n"
            "3. Those credentials are used to access cloud storage and escalate."
        ),
        "remediation_steps": [
            "Allow-list destination hosts/protocols; deny by default.",
            "Resolve and validate the IP (block private, loopback, link-local, metadata ranges) "
            "and re-check after redirects.",
            "Disable unused URL schemes (file:, gopher:, ftp:) and block redirects to internal IPs.",
            "Require authentication on internal services; don't rely on network position alone.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html",
        ],
    },

    # ── Cryptographic / transport failures ───────────────────────────────
    "CWE-319": {
        "name": "Cleartext Transmission",
        "owasp": "A02",
        "impact": (
            "Data travels unencrypted (or an HTTPS page pulls HTTP resources), so anyone on "
            "the network path — public Wi-Fi, a compromised router, a malicious ISP — can "
            "read session cookies and credentials or tamper with the content (inject scripts), "
            "defeating the protection HTTPS was supposed to give."
        ),
        "attack_scenario": (
            "1. The victim uses the site over a shared network.\n"
            "2. An on-path attacker captures the cleartext request (or modifies an http:// "
            "script the https:// page loads).\n"
            "3. The stolen session cookie is replayed, or the injected script runs in the page."
        ),
        "remediation_steps": [
            "Serve everything over HTTPS and redirect HTTP → HTTPS.",
            "Load all sub-resources over HTTPS (fix mixed content); use protocol-relative or "
            "absolute https URLs.",
            "Send HSTS with a long max-age, includeSubDomains and preload.",
            "Mark cookies Secure so they are never sent over HTTP.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
    },
    "CWE-311": {
        "name": "Missing Encryption of Sensitive Data (no HTTPS)",
        "owasp": "A02",
        "impact": (
            "The site is served over plain HTTP, so all traffic — credentials, session "
            "cookies, personal data — travels unencrypted. Anyone on the network path can read "
            "or modify it (SSL-strip, script injection), and browsers flag the site as 'Not "
            "Secure'."
        ),
        "attack_scenario": (
            "1. A victim uses the site on a shared/public network.\n"
            "2. An on-path attacker reads the cleartext session cookie or injects content.\n"
            "3. The session is hijacked or the page is tampered with."
        ),
        "remediation_steps": [
            "Obtain a TLS certificate (e.g. free via Let's Encrypt) and serve everything over HTTPS.",
            "Redirect all HTTP traffic to HTTPS (301) and send HSTS.",
            "Mark cookies Secure; fix any mixed content.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
    },
    "CWE-525": {
        "name": "Sensitive Information Cacheable",
        "owasp": "A05",
        "impact": (
            "Authenticated or sensitive responses that are cacheable can be stored by browsers, "
            "shared proxies or a CDN and later served to a different user — leaking private data "
            "and enabling web-cache deception."
        ),
        "attack_scenario": (
            "1. A sensitive response is cached by a shared proxy/CDN.\n"
            "2. Another user (or an attacker crafting a cache-deception path) is served the "
            "cached private content."
        ),
        "remediation_steps": [
            "Send Cache-Control: no-store, no-cache, must-revalidate, private on sensitive responses.",
            "Ensure the CDN/proxy never caches responses that set cookies.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "CWE-1104": {
        "name": "Use of Unmaintained Third-Party Components",
        "owasp": "A06",
        "impact": (
            "Unmaintained or outdated components stop receiving security fixes, so any newly "
            "discovered vulnerability in them stays exploitable — frequently enabling RCE, data "
            "disclosure or auth bypass with public exploit code available."
        ),
        "attack_scenario": (
            "1. The attacker fingerprints the outdated component/version.\n"
            "2. They match it to a published vulnerability with a known exploit.\n"
            "3. They run the exploit against the unpatched instance."
        ),
        "remediation_steps": [
            "Upgrade to a current, maintained release and track the component's advisories.",
            "Maintain an SBOM and run Software Composition Analysis in CI.",
            "Replace abandoned dependencies with maintained alternatives.",
        ],
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ],
    },
    "CWE-598": {
        "name": "Sensitive Data in GET Request",
        "owasp": "A05",
        "impact": (
            "Credentials or other secrets sent in the URL query string are written to browser "
            "history, proxy and server access logs, and leaked in the Referer header — exposing "
            "them well beyond the single request."
        ),
        "attack_scenario": (
            "1. A password is submitted via GET and lands in the URL.\n"
            "2. It is persisted in logs/history/Referer.\n"
            "3. Anyone with access to those reads the credential later."
        ),
        "remediation_steps": [
            "Use POST (or a request body) for all sensitive data; never put secrets in URLs.",
            "Scrub any secrets already captured in logs and rotate them.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-295": {
        "name": "Improper Certificate Validation",
        "owasp": "A02",
        "impact": (
            "An invalid, expired, self-signed or mis-issued certificate breaks the trust "
            "guarantee of TLS. Users are trained to click through warnings, and an on-path "
            "attacker can present their own certificate to run a man-in-the-middle, reading "
            "and modifying all traffic including credentials and sessions."
        ),
        "attack_scenario": (
            "1. The certificate is expired/self-signed, so clients can't distinguish the real "
            "server from an impostor.\n"
            "2. An on-path attacker intercepts the TLS handshake and presents their own cert.\n"
            "3. Traffic is decrypted, credentials captured, responses tampered with."
        ),
        "remediation_steps": [
            "Install a valid certificate from a trusted CA (e.g. Let's Encrypt) and automate renewal.",
            "Serve the full chain; match the hostname (include all SANs).",
            "Monitor expiry and alert well ahead of time.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html",
        ],
    },
    "CWE-326": {
        "name": "Inadequate Encryption Strength",
        "owasp": "A02",
        "impact": (
            "Weak TLS protocols (SSLv3/TLS 1.0/1.1) or weak ciphers can be downgraded or "
            "broken, allowing decryption of traffic and man-in-the-middle attacks against "
            "sessions and credentials."
        ),
        "attack_scenario": (
            "1. The server still offers an obsolete protocol/cipher.\n"
            "2. An attacker forces a downgrade and exploits a known weakness (e.g. BEAST/POODLE-class).\n"
            "3. Session data is recovered."
        ),
        "remediation_steps": [
            "Disable SSLv2/3 and TLS 1.0/1.1; require TLS 1.2+ (prefer 1.3).",
            "Use strong AEAD cipher suites and enable forward secrecy (ECDHE).",
            "Test with SSL Labs / testssl.sh and track the grade over time.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/TLS_Cipher_String_Cheat_Sheet.html",
        ],
    },
    "CWE-327": {
        "name": "Broken/Risky Cryptographic Algorithm",
        "owasp": "A02",
        "impact": (
            "Use of a broken algorithm means attackers can forge, decrypt or tamper with "
            "protected data, undermining confidentiality and integrity guarantees."
        ),
        "attack_scenario": (
            "1. A weak algorithm is in use.\n2. The attacker leverages its known flaws to "
            "forge or decrypt protected values."
        ),
        "remediation_steps": [
            "Replace broken algorithms with vetted modern primitives (AES-GCM, SHA-256+, Argon2 for passwords).",
            "Use well-reviewed libraries and keep them current.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html",
        ],
    },

    # ── Security misconfiguration ────────────────────────────────────────
    "CWE-693": {
        "name": "Protection Mechanism Failure (missing security header)",
        "owasp": "A05",
        "impact": (
            "A missing security header removes a browser-enforced defence layer. Depending on "
            "the header this leaves users exposed to clickjacking, XSS, MIME-sniffing attacks, "
            "protocol-downgrade / SSL-strip, or referrer/credential leakage — turning otherwise "
            "minor bugs into exploitable ones."
        ),
        "attack_scenario": (
            "1. The header that would have blocked a given attack class is absent.\n"
            "2. The attacker uses the corresponding technique (framing the page, injecting "
            "script, downgrading to HTTP) that the header would have stopped.\n"
            "3. The attack succeeds because the browser had no policy to enforce."
        ),
        "remediation_steps": [
            "Add the missing header(s) at the web server / framework / CDN layer for all responses.",
            "Ship a strict Content-Security-Policy, HSTS, X-Content-Type-Options: nosniff and "
            "frame-ancestors protection.",
            "Verify with securityheaders.com and a CSP evaluator, then lock the config in CI.",
        ],
        "references": [
            "https://owasp.org/www-project-secure-headers/",
        ],
    },
    "CWE-1021": {
        "name": "Improper Restriction of Rendered UI Layers (clickjacking / weak CSP)",
        "owasp": "A05",
        "impact": (
            "Without frame protection the page can be invisibly framed by a hostile site and "
            "overlaid, so victims are tricked into clicking buttons they can't see "
            "(clickjacking) — confirming payments, granting permissions, changing settings. A "
            "weak CSP similarly fails to contain injected script."
        ),
        "attack_scenario": (
            "1. The attacker frames the target page inside an invisible iframe on their site.\n"
            "2. They overlay a decoy UI aligned with a sensitive button.\n"
            "3. The victim clicks the decoy and unknowingly performs the real, sensitive action."
        ),
        "remediation_steps": [
            "Send Content-Security-Policy: frame-ancestors 'self' (or 'none').",
            "Also send X-Frame-Options: DENY/SAMEORIGIN for legacy browsers.",
            "Tighten CSP: remove 'unsafe-inline'/'unsafe-eval', use nonces/hashes, avoid wildcards.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html",
        ],
    },
    "CWE-16": {
        "name": "Configuration Weakness",
        "owasp": "A05",
        "impact": (
            "A misconfigured service/setting widens the attack surface — exposing debugging "
            "features, permissive policies or management interfaces that attackers probe for "
            "footholds."
        ),
        "attack_scenario": (
            "1. The attacker discovers the weak setting during reconnaissance.\n"
            "2. They abuse it to gather information or reach functionality that should be "
            "restricted."
        ),
        "remediation_steps": [
            "Apply a hardened baseline; disable debug/dev features in production.",
            "Review defaults; least-privilege everywhere; keep an eye on policy records.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-548": {
        "name": "Directory Listing Exposure",
        "owasp": "A05",
        "impact": (
            "Auto-indexing exposes the full file listing of a directory, revealing backups, "
            "source, config files, uploads and other artifacts that were never meant to be "
            "browsable — a reconnaissance goldmine that often leads directly to secrets."
        ),
        "attack_scenario": (
            "1. The attacker browses a directory and sees every file.\n"
            "2. They spot a backup/config/source file.\n"
            "3. Downloading it yields credentials or source they use to go deeper."
        ),
        "remediation_steps": [
            "Disable directory listing (Apache: Options -Indexes; nginx: autoindex off).",
            "Keep non-public files out of the web root; return 403/404 for sensitive paths.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-650": {
        "name": "Dangerous HTTP Methods Enabled",
        "owasp": "A05",
        "impact": (
            "Methods like PUT/DELETE can let an attacker upload a web shell or delete content; "
            "TRACE enables Cross-Site Tracing to steal headers; CONNECT can turn the server "
            "into a proxy. Each expands what an attacker can do beyond normal browsing."
        ),
        "attack_scenario": (
            "1. The attacker finds PUT enabled.\n2. They upload a script to the web root.\n"
            "3. Requesting that script executes attacker code on the server."
        ),
        "remediation_steps": [
            "Allow only the methods each endpoint needs (usually GET/POST/HEAD).",
            "Disable WebDAV/PUT/DELETE/TRACE/CONNECT unless explicitly required and secured.",
            "Enforce method + authorization checks server-side, not just at the proxy.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-942": {
        "name": "Overly Permissive CORS",
        "owasp": "A05",
        "impact": (
            "A permissive CORS policy (wildcard, reflected origin, or null + credentials) lets "
            "malicious websites read authenticated responses from this origin using the "
            "victim's cookies — effectively cross-origin data theft of private API responses, "
            "profile data and anti-CSRF tokens."
        ),
        "attack_scenario": (
            "1. The server reflects any Origin and allows credentials.\n"
            "2. A victim visits the attacker's site while logged in here.\n"
            "3. Attacker JS makes a credentialed cross-origin request and reads the private "
            "response the browser now permits."
        ),
        "remediation_steps": [
            "Reflect only an explicit allow-list of trusted origins; never echo arbitrary Origin.",
            "Never combine Access-Control-Allow-Origin: * (or null) with Allow-Credentials: true.",
            "Scope allowed methods/headers tightly and avoid wildcards when credentials are used.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
        ],
    },
    "CWE-346": {
        "name": "Origin Validation Error",
        "owasp": "A05",
        "impact": (
            "The application trusts an origin/host value it should not, enabling cross-origin "
            "data exposure or request forgery depending on context."
        ),
        "attack_scenario": (
            "1. The attacker supplies a crafted Origin/Host.\n2. The server echoes or trusts "
            "it, loosening a security decision in the attacker's favour."
        ),
        "remediation_steps": [
            "Validate Origin/Host against a strict allow-list.",
            "Do not reflect attacker-controlled origin/host values into security-relevant logic.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Origin_Resource_Sharing_Cheat_Sheet.html",
        ],
    },
    "CWE-644": {
        "name": "Host Header Injection",
        "owasp": "A05",
        "impact": (
            "If the app uses the Host header to build links, reset URLs or cache keys, an "
            "attacker can poison password-reset emails (sending the reset link to their own "
            "domain → account takeover) or poison the web cache so other users are served "
            "attacker-controlled content."
        ),
        "attack_scenario": (
            "1. The attacker sends a password-reset request with a spoofed Host header.\n"
            "2. The app builds the reset link from that header.\n"
            "3. The victim receives an email whose reset link points to the attacker's host; "
            "when clicked, the token leaks and the account is taken over."
        ),
        "remediation_steps": [
            "Use a hard-coded canonical domain for all generated links; don't trust the Host header.",
            "Validate Host against an allow-list of expected virtual hosts; reject others.",
            "Keep the Host out of cache keys unless validated.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },

    # ── Information exposure ──────────────────────────────────────────────
    "CWE-200": {
        "name": "Information Exposure",
        "owasp": "A05",
        "impact": (
            "Leaked technical detail (versions, stack traces, internal IPs/paths, "
            "framework banners) hands attackers a map of the system. It narrows which exploits "
            "to try, reveals internal architecture, and often exposes secrets outright — "
            "accelerating every later stage of an attack."
        ),
        "attack_scenario": (
            "1. During recon the attacker reads the leaked version/trace/path.\n"
            "2. They look up known vulnerabilities for that exact version or learn the internal "
            "layout.\n"
            "3. They launch a precise, pre-validated exploit instead of guessing."
        ),
        "remediation_steps": [
            "Suppress version banners (Server, X-Powered-By) and verbose errors in production.",
            "Return generic error pages; log details server-side only.",
            "Keep debug endpoints, source maps and internal hostnames out of production.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-215": {
        "name": "Information Exposure Through Debug Information",
        "owasp": "A05",
        "impact": (
            "Debug output (stack traces, framework debug pages, phpinfo) reveals file paths, "
            "library versions, configuration and sometimes secrets — a direct aid to further "
            "attacks."
        ),
        "attack_scenario": (
            "1. The attacker triggers an error.\n2. A debug trace reveals the stack, paths and "
            "versions.\n3. They tailor an exploit to the disclosed internals."
        ),
        "remediation_steps": [
            "Disable debug mode in production (DEBUG=False, display_errors=Off).",
            "Remove phpinfo/test pages; return generic error responses.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-532": {
        "name": "Sensitive Information in Logs/Responses",
        "owasp": "A09",
        "impact": (
            "Secrets or personal data exposed in responses, comments or logs can be harvested "
            "directly — API keys, tokens and credentials that grant access to other systems."
        ),
        "attack_scenario": (
            "1. The attacker finds a key/token in the page source, a comment, or an exposed log.\n"
            "2. They use it to authenticate to the backing service and access its data."
        ),
        "remediation_steps": [
            "Never embed secrets in client-delivered content; keep them server-side in a vault.",
            "Rotate any exposed secret immediately and scan the repo/CI for leaks.",
            "Scrub PII and secrets from logs and error responses.",
        ],
        "references": ["https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html"],
    },
    "CWE-538": {
        "name": "File/Directory Exposure",
        "owasp": "A05",
        "impact": (
            "A sensitive file is publicly downloadable. Exposed .git/.env/backups/config files "
            "frequently contain database credentials, API keys, private keys and full source — "
            "handing an attacker the keys to the application and often the infrastructure."
        ),
        "attack_scenario": (
            "1. The attacker requests a well-known sensitive path and gets 200.\n"
            "2. They download the .env/.git/backup and read live credentials and secrets.\n"
            "3. They log straight into the database / cloud / admin with those credentials."
        ),
        "remediation_steps": [
            "Remove the file from the web root; it should never be deployed publicly.",
            "Block dotfiles and backup extensions at the web server (deny .git, .env, *.sql, *.bak).",
            "Rotate every credential that was exposed; assume it is compromised.",
            "Serve the app from a build artifact that excludes VCS and config files.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },
    "CWE-213": {
        "name": "Intentional Information Exposure",
        "owasp": "A05",
        "impact": "Reveals internal detail that aids reconnaissance and targeting.",
        "attack_scenario": "The attacker reads exposed metadata and uses it to plan further attacks.",
        "remediation_steps": [
            "Minimise technical disclosure in responses and headers.",
        ],
        "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
    },

    # ── Cookies / auth ────────────────────────────────────────────────────
    "CWE-614": {
        "name": "Sensitive Cookie Without Secure Flag",
        "owasp": "A05",
        "impact": (
            "A session cookie without Secure can be sent over plain HTTP, so an on-path "
            "attacker can capture it and hijack the session even on an otherwise-HTTPS site."
        ),
        "attack_scenario": (
            "1. The attacker induces an HTTP request to the domain.\n2. The cookie is sent in "
            "cleartext and captured.\n3. The session is replayed to impersonate the user."
        ),
        "remediation_steps": [
            "Set Secure on all session/auth cookies.",
            "Also set HttpOnly and SameSite; serve over HTTPS with HSTS.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "CWE-1004": {
        "name": "Sensitive Cookie Without HttpOnly",
        "owasp": "A05",
        "impact": (
            "Without HttpOnly, JavaScript can read the cookie, so any XSS on the site "
            "immediately escalates to full session theft and account takeover."
        ),
        "attack_scenario": (
            "1. An XSS flaw lets attacker script run.\n2. It reads document.cookie (allowed "
            "because HttpOnly is missing).\n3. The session cookie is exfiltrated and replayed."
        ),
        "remediation_steps": [
            "Set HttpOnly on all session/auth cookies.",
            "Combine with Secure + SameSite and a strict CSP.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "CWE-1275": {
        "name": "Weak SameSite Cookie Attribute",
        "owasp": "A05",
        "impact": (
            "A missing/None SameSite lets the cookie ride cross-site requests, enabling CSRF "
            "and some cross-site information leaks."
        ),
        "attack_scenario": (
            "1. SameSite is None/absent.\n2. A hostile page triggers a cross-site request that "
            "carries the cookie.\n3. A state-changing action runs as the victim."
        ),
        "remediation_steps": [
            "Set SameSite=Lax (default for most) or Strict for sensitive sessions.",
            "Pair with anti-CSRF tokens for defence-in-depth.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html",
        ],
    },
    "CWE-347": {
        "name": "Improper Cryptographic Signature Verification (JWT)",
        "owasp": "A02",
        "impact": (
            "Weak JWT handling (alg:none, weak HMAC secret, or confusion attacks) lets an "
            "attacker forge tokens and authenticate as any user, including admins — a direct "
            "authentication bypass and privilege escalation."
        ),
        "attack_scenario": (
            "1. The attacker captures a JWT and inspects its header/claims.\n"
            "2. They set alg to none, or brute-force a weak HMAC secret, and re-sign a token "
            "with admin claims.\n"
            "3. The server accepts the forged token and grants admin access."
        ),
        "remediation_steps": [
            "Reject alg:none; pin the expected algorithm server-side (don't trust the header).",
            "Use long, random secrets for HMAC or asymmetric keys (RS/ES) with proper key mgmt.",
            "Validate exp/nbf/iss/aud; keep token lifetimes short; support revocation.",
        ],
        "references": [
            "https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html",
        ],
    },
    "CWE-345": {
        "name": "Insufficient Verification of Data Authenticity",
        "owasp": "A08",
        "impact": (
            "Data/code accepted without integrity verification can be tampered with in transit "
            "or at rest, enabling supply-chain and content-injection attacks."
        ),
        "attack_scenario": (
            "1. A resource is loaded without integrity checks.\n2. An attacker (CDN/MITM) swaps "
            "it for a malicious version.\n3. The tampered code runs in users' browsers."
        ),
        "remediation_steps": [
            "Add Subresource Integrity (integrity + crossorigin) to third-party scripts/styles.",
            "Pin dependency versions and verify signatures/hashes in the build.",
        ],
        "references": [
            "https://developer.mozilla.org/en-US/docs/Web/Security/Subresource_Integrity",
        ],
    },
    "CWE-523": {
        "name": "Unprotected Transport of Credentials (weak HSTS)",
        "owasp": "A02",
        "impact": (
            "A short/narrow HSTS policy leaves a window where the first or a sub-domain request "
            "can be downgraded to HTTP and intercepted (SSL-strip), exposing the session."
        ),
        "attack_scenario": (
            "1. HSTS max-age is short or omits subdomains.\n2. An on-path attacker strips TLS "
            "on an unprotected request.\n3. The cleartext session is captured."
        ),
        "remediation_steps": [
            "Set Strict-Transport-Security: max-age=31536000; includeSubDomains; preload.",
            "Submit the domain to the HSTS preload list once stable.",
        ],
        "references": ["https://hstspreload.org/"],
    },

    # ── Components ────────────────────────────────────────────────────────
    "CWE-1035": {
        "name": "Vulnerable/Outdated Component",
        "owasp": "A06",
        "impact": (
            "Running a version with publicly documented vulnerabilities means attackers have "
            "ready-made, reliable exploits. Impact depends on the component but often includes "
            "RCE, auth bypass or data disclosure — with exploit code already public."
        ),
        "attack_scenario": (
            "1. The attacker fingerprints the exact component version.\n"
            "2. They match it to a published CVE with a known exploit.\n"
            "3. They run the exploit against the unpatched instance."
        ),
        "remediation_steps": [
            "Upgrade to a current, supported release and track the component's advisories.",
            "Maintain a dependency inventory (SBOM) and automate vulnerability scanning in CI.",
            "Apply security patches promptly; remove unused components.",
        ],
        "references": [
            "https://owasp.org/www-project-dependency-check/",
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ],
    },
    "CWE-937": {
        "name": "Using Components with Known Vulnerabilities",
        "owasp": "A06",
        "impact": (
            "Known-vulnerable components expose the app to pre-packaged exploits, frequently "
            "leading to RCE, data breach or auth bypass."
        ),
        "attack_scenario": (
            "1. Version fingerprinting reveals a vulnerable library/server.\n"
            "2. A public exploit for its CVE is launched."
        ),
        "remediation_steps": [
            "Patch/upgrade affected components; subscribe to their security advisories.",
            "Automate SCA scanning and fail builds on high-severity known CVEs.",
        ],
        "references": [
            "https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/",
        ],
    },
}


# Fallback used when a CWE isn't in the KB yet.
_GENERIC = {
    "owasp": "A05",
    "impact": (
        "This weakness increases the attack surface of the application. Depending on context "
        "it can aid reconnaissance, weaken a security control, or be chained with other issues "
        "to reach sensitive data or functionality."
    ),
    "attack_scenario": (
        "An attacker notes this weakness during assessment and combines it with other findings "
        "to advance toward a higher-impact objective."
    ),
    "remediation_steps": [
        "Review the affected component against a hardened baseline and least-privilege design.",
        "Apply the vendor/framework guidance referenced below and re-test.",
    ],
    "references": ["https://owasp.org/www-project-web-security-testing-guide/"],
}


def cwe_number(cwe: str | None) -> str:
    if not cwe:
        return ""
    return cwe.replace("CWE-", "").strip()


def cwe_url(cwe: str | None) -> str:
    n = cwe_number(cwe)
    return f"https://cwe.mitre.org/data/definitions/{n}.html" if n else ""


def owasp_category(cwe: str | None) -> str:
    """Return the full OWASP Top-10 label for a CWE (or empty string)."""
    entry = KB.get(cwe or "", {})
    key = entry.get("owasp")
    return OWASP_TOP10.get(key, "") if key else ""


def enrich(finding) -> None:
    """
    Fill in impact / attack_scenario / owasp / remediation_steps / references
    on a Finding *in place*, from the knowledge base keyed by CWE. Anything the
    module already set is preserved (modules always win).
    """
    kb = KB.get(finding.cwe or "", _GENERIC)

    if not getattr(finding, "impact", ""):
        finding.impact = kb.get("impact", _GENERIC["impact"])
    if not getattr(finding, "attack_scenario", ""):
        finding.attack_scenario = kb.get("attack_scenario", _GENERIC["attack_scenario"])
    if not getattr(finding, "owasp", ""):
        finding.owasp = OWASP_TOP10.get(kb.get("owasp", "A05"), OWASP_TOP10["A05"])
    if not getattr(finding, "remediation_steps", None):
        finding.remediation_steps = list(kb.get("remediation_steps", _GENERIC["remediation_steps"]))

    # merge references (module refs first, then KB refs, deduped, keep order)
    merged: list[str] = list(finding.references or [])
    for ref in kb.get("references", []):
        if ref not in merged:
            merged.append(ref)
    cu = cwe_url(finding.cwe)
    if cu and cu not in merged:
        merged.append(cu)
    finding.references = merged

    if not getattr(finding, "detected_at", ""):
        finding.detected_at = datetime.now(timezone.utc).isoformat()


def remediation_priority(finding) -> int:
    """
    A fix-ordering score (higher = fix first). Combines severity with confidence so
    a CERTAIN critical sorts above a TENTATIVE one.
    """
    sev = {"critical": 500, "high": 200, "medium": 70, "low": 20, "info": 5}
    conf = {"certain": 3, "firm": 2, "tentative": 1}
    s = sev.get(getattr(finding.severity, "value", str(finding.severity)), 5)
    c = conf.get(getattr(finding.confidence, "value", str(finding.confidence)), 2)
    return s * c
