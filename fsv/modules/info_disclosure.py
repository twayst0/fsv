"""FSV Module — Information Disclosure"""

from __future__ import annotations
import re
from fsv.core.scanner import BaseScanner, mask_secret
from fsv.core.models import Finding, Severity


# Patterns that should never appear in a public response body.
LEAK_PATTERNS: list[tuple[str, str, Severity]] = [
    (r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----",
     "Private key material", Severity.CRITICAL),
    (r"AKIA[0-9A-Z]{16}",
     "AWS Access Key ID", Severity.CRITICAL),
    (r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}",
     "AWS Secret Access Key", Severity.CRITICAL),
    (r"(?i)(api[_-]?key|apikey)\s*[=:]\s*['\"][A-Za-z0-9_\-]{16,}['\"]",
     "Hard-coded API key", Severity.HIGH),
    (r"(?i)(secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "Hard-coded secret/password", Severity.HIGH),
    (r"ghp_[A-Za-z0-9]{36}",
     "GitHub personal access token", Severity.CRITICAL),
    (r"xox[baprs]-[A-Za-z0-9-]{10,}",
     "Slack token", Severity.HIGH),
    (r"(?i)bearer\s+[A-Za-z0-9\-._~+/]{20,}",
     "Bearer token in response", Severity.MEDIUM),
    (r"eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
     "JSON Web Token (JWT)", Severity.LOW),
    (r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}",
     "Email address exposure", Severity.INFO),
]

# Verbose framework error/stack-trace signatures.
STACK_TRACE_SIGNATURES = [
    "traceback (most recent call last)",
    "stack trace:",
    "exception in thread",
    "at java.lang.",
    "java.lang.nullpointerexception",
    "system.nullreferenceexception",
    "fatal error:",
    "warning: include(",
    "notice: undefined",
    "undefined index",
    "on line",
    "<b>fatal error</b>",
    "django.core.exceptions",
    "werkzeug.exceptions",
    "ruby on rails",
    "actionview::",
]


class InfoDisclosureScanner(BaseScanner):
    name = "info_disclosure"
    category    = "passive"
    scope       = "url"
    description = "Leaked secrets, stack traces, internal IPs"

    async def scan(self, url: str) -> list[Finding]:
        status, headers, body = await self.fetch(url)
        if status == -1 or not body:
            return []

        findings: list[Finding] = []
        seen_titles: set[str] = set()

        # ── Secret / key leakage ──────────────────────────
        for pattern, label, sev in LEAK_PATTERNS:
            # Skip generic email/JWT matches to avoid noise unless clearly a leak
            match = re.search(pattern, body)
            if match:
                if label in seen_titles:
                    continue
                # Emails are extremely common; only flag as INFO once
                raw = match.group(0)
                # emails / IPs are evidence on their own; keys and tokens get masked
                # so the report doesn't become another place the secret leaks from
                snippet = (raw if "email" in label.lower() or raw.startswith("-----BEGIN")
                           else mask_secret(raw[:120]))
                findings.append(Finding(
                    title       = f"Possible Information Disclosure: {label}",
                    severity    = sev,
                    url         = url,
                    module      = self.name,
                    description = (
                        f"The response body appears to contain {label.lower()}. "
                        "Secrets embedded in client-facing responses can be harvested by anyone."
                    ),
                    evidence    = f"Matched pattern for {label}: {snippet}",
                    recommendation = (
                        "Remove secrets from all client-facing output. Rotate any exposed "
                        "credentials immediately. Store secrets in environment variables or a "
                        "secrets manager — never in source that reaches the browser."
                    ),
                    references  = [
                        "https://owasp.org/www-project-web-security-testing-guide/",
                        "https://cwe.mitre.org/data/definitions/200.html",
                    ],
                    cwe         = "CWE-200",
                ))
                seen_titles.add(label)

        # ── Verbose errors / stack traces ─────────────────
        body_lower = body.lower()
        for sig in STACK_TRACE_SIGNATURES:
            if sig in body_lower:
                findings.append(Finding(
                    title       = "Verbose Error Message / Stack Trace Disclosure",
                    severity    = Severity.MEDIUM,
                    url         = url,
                    module      = self.name,
                    description = (
                        "The application returned a detailed error message or stack trace. "
                        "This reveals internal paths, framework versions, and logic that aid "
                        "an attacker in planning further attacks."
                    ),
                    evidence    = f"Error signature matched: '{sig}'",
                    recommendation = (
                        "Disable debug mode in production. Return generic error pages to users "
                        "and log detailed errors server-side only."
                    ),
                    references  = ["https://cwe.mitre.org/data/definitions/209.html"],
                    cwe         = "CWE-209",
                ))
                break

        # ── Internal IP leakage ───────────────────────────
        internal_ip = re.search(
            r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3}"
            r"|172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b",
            body,
        )
        if internal_ip:
            findings.append(Finding(
                title       = "Internal IP Address Disclosure",
                severity    = Severity.LOW,
                url         = url,
                module      = self.name,
                description = (
                    "An internal/private IP address was found in the response, revealing "
                    "details about the internal network topology."
                ),
                evidence    = f"Internal IP found: {internal_ip.group(0)}",
                recommendation = "Remove internal IP references from client-facing responses.",
                references  = ["https://cwe.mitre.org/data/definitions/200.html"],
                cwe         = "CWE-200",
            ))

        return findings
