# Security policy

## Reporting a vulnerability in FSV
Please report privately — do not open a public issue. Use GitHub's **"Report a vulnerability"** (Security → Advisories) on this repository.
Include the version (`fsv --version`), what you did, what you expected, and what happened. We aim to acknowledge within 3 working days.

In scope: the dashboard / API (auth bypass, CSRF, SSRF, injection, path traversal), the MCP server, the ownership-verification and
outbound-address controls, secret handling in reports/logs, and anything that makes FSV act against a target the operator did not choose.

## Using FSV responsibly
FSV is for systems you own or are **explicitly authorised in writing** to test. It refuses to run without an authorisation confirmation, and a shared
deployment can additionally require proof of control (`docs/DEPLOYMENT.md`). If FSV finds a problem in someone else's system by accident, report it to them
via their `security.txt` / disclosure channel and do not publish details before they have had time to fix it.

## Supported versions
Only the latest release receives security fixes.
