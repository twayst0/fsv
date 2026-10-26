<p align="center">
  <img src="https://raw.githubusercontent.com/twayst0/fsv/main/docs/assets/hero.svg" alt="FSV — finds what checklists miss" width="100%">
</p>

# FSV — web security scanner & MCP server

<!-- mcp-name: io.github.twayst0/fsv -->

**For the problems nobody is watching:** dangling DNS and subdomain takeover, orphaned cloud buckets,
scripts from compromised or expired CDN domains, SPF includes that no longer exist, debug mode left on in
production, secrets in your JavaScript, end-of-life software — and the **attack paths** that turn small
findings into a real compromise, each with the cheapest fix that breaks it.

Runs as a **CLI**, a **dashboard**, an **MCP server** for AI assistants (Claude, Cursor, VS Code), and a **CI step**.
Detection only: it never exploits, never claims a resource, never tests a credential.

> **Authorized use only.** Scan only systems you own or are explicitly authorized in writing to test.

## Install

```bash
pip install fsv            # Python 3.11+
fsv doctor                 # checks dependencies, DNS, database
```

## Scan

```bash
fsv scan example.com --authorize                     # full scan of a site you own
fsv scan example.com --authorize --profile passive   # read-only: no payloads sent
fsv fixes <scan_id> nginx                            # paste-ready config for what was found
fsv web                                              # dashboard → http://127.0.0.1:7474
```

## Connect your AI assistant

```bash
fsv mcp-config --client claude-code      # prints:  claude mcp add fsv -- /path/to/fsv-mcp
fsv mcp-config --client claude-desktop   # or: cursor · vscode
```

Then ask: *“Use the **security_review** prompt on https://my-site.example — I own it.”*
The assistant confirms authorization, runs a passive check and a full scan, leads with attack paths and
hands you the fixes.

## What it finds

<p align="center">
  <img src="https://raw.githubusercontent.com/twayst0/fsv/main/docs/assets/detections.svg" alt="Detection cards: dangling DNS, orphaned bucket, dead SPF include, source map and secrets, end-of-life software, attack path, compromised CDN, debug mode" width="100%">
</p>

32 modules — DNS takeover, cloud storage, script supply chain, SPF/DMARC/DKIM, JavaScript secrets and
source maps, vulnerable and end-of-life libraries, ~100 content-validated exposure checks, framework debug
pages, headers/CSP/cookies, and benign active checks for common reflected issues. Findings carry severity,
confidence, CWE, OWASP Top 10 category and remediation; reports in Markdown, JSON, HTML, SARIF and CSV.

## Links

- Source, full documentation and screenshots: https://github.com/twayst0/fsv
- Changelog: https://github.com/twayst0/fsv/blob/main/CHANGELOG.md
- Security policy: https://github.com/twayst0/fsv/blob/main/SECURITY.md
- Contact: statways1707@gmail.com · Discord **.tways**

**License:** MIT — free for everyone, including commercial use.
