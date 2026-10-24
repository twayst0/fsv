"""
FSV — credential-pattern detection (never validates a credential)
─────────────────────────────────────────────────────────────────
Finds strings that *look like* live credentials in text FSV was already allowed
to fetch (JavaScript, source maps). It never sends a discovered credential
anywhere or tests whether it works — the finding is "this is exposed", and the
fix is "rotate it".

Provider-specific formats are high confidence. The generic key/secret
assignment rule is gated by Shannon entropy and a placeholder filter, and is
reported as tentative.
"""

from __future__ import annotations
import math
import re
from dataclasses import dataclass

from fsv.core.models import Confidence, Severity
from fsv.core.scanner import mask_secret


@dataclass(frozen=True)
class Rule:
    key:      str
    label:    str
    pattern:  re.Pattern
    severity: Severity
    confidence: Confidence = Confidence.FIRM
    note:     str = ""
    group:    int = 0          # which capture group is the secret (0 = whole match)


def _r(key, label, rx, sev, conf=Confidence.FIRM, note="", group=0, flags=0) -> Rule:
    return Rule(key, label, re.compile(rx, flags), sev, conf, note, group)


RULES: tuple[Rule, ...] = (
    _r("private_key", "private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
       Severity.CRITICAL, Confidence.CERTAIN),
    _r("aws_secret", "AWS secret access key",
       r"(?i)aws.{0,30}?secret.{0,30}?['\"]([A-Za-z0-9/+=]{40})['\"]", Severity.CRITICAL, Confidence.FIRM, group=1),
    _r("aws_key_id", "AWS access key ID", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", Severity.MEDIUM, Confidence.FIRM,
       note="An access key ID alone is not enough to authenticate, but it identifies the account "
            "and is usually stored next to the secret."),
    _r("stripe_secret", "Stripe live secret key", r"\b[sr]k_live_[0-9a-zA-Z]{20,}\b", Severity.CRITICAL, Confidence.CERTAIN),
    _r("github", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b", Severity.CRITICAL, Confidence.CERTAIN),
    _r("gitlab", "GitLab token", r"\bglpat-[A-Za-z0-9_\-]{20}\b", Severity.CRITICAL, Confidence.CERTAIN),
    _r("npm", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b", Severity.CRITICAL, Confidence.CERTAIN),
    _r("slack_token", "Slack token", r"\bxox[abprs]-[0-9A-Za-z\-]{10,}\b", Severity.HIGH, Confidence.FIRM),
    _r("slack_webhook", "Slack webhook URL",
       r"https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{20,}", Severity.HIGH, Confidence.CERTAIN),
    _r("sendgrid", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", Severity.HIGH, Confidence.CERTAIN),
    _r("mapbox_secret", "Mapbox secret token", r"\bsk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b", Severity.HIGH, Confidence.FIRM),
    _r("azure_storage", "Azure storage connection string",
       r"DefaultEndpointProtocol=https?;AccountName=[^;\"']+;AccountKey=[A-Za-z0-9+/=]{40,}", Severity.CRITICAL, Confidence.CERTAIN),
    _r("service_account", "GCP service-account key",
       r"\"type\"\s*:\s*\"service_account\"[\s\S]{0,400}?\"private_key\"", Severity.CRITICAL, Confidence.CERTAIN),
    _r("db_url", "database URL with embedded password",
       r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|amqps?)://[^\s:/@'\"<>]+:([^\s@'\"/<>]{3,})@[^\s'\"<>]+",
       Severity.CRITICAL, Confidence.FIRM, group=1),
    _r("mailgun", "Mailgun API key", r"\bkey-[0-9a-f]{32}\b", Severity.MEDIUM, Confidence.TENTATIVE),
    _r("google_api", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.LOW, Confidence.FIRM,
       note="Google API keys in front-end code are common and not secret by design, but an "
            "unrestricted key can be used by anyone against your quota and billing. Confirm it has "
            "HTTP-referrer and API restrictions."),
)

_GENERIC = re.compile(
    r"""(?ix)\b(?:api[_-]?key|apikey|secret(?:[_-]?key)?|client[_-]?secret|access[_-]?token|
        auth[_-]?token|private[_-]?key|passwd|password)\b["']?\s*[:=]\s*["']([A-Za-z0-9_\-+/=.]{16,80})["']""")

_PLACEHOLDER = re.compile(
    r"(?i)(x{4,}|\*{3,}|your[_-]|example|placeholder|changeme|change[_-]me|dummy|sample|test|"
    r"lorem|insert|todo|<.*>|\{\{|\$\{|process\.env|undefined|null)")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    return -sum((n / len(s)) * math.log2(n / len(s)) for n in counts.values())


def _looks_random(s: str) -> bool:
    if _PLACEHOLDER.search(s):
        return False
    if len(set(s)) < 8:
        return False
    # camelCase/snake identifiers (words) score low; random keys score high
    return shannon_entropy(s) >= 3.6 and not re.fullmatch(r"[a-z]+(?:[_\-][a-z]+)+", s)


@dataclass(frozen=True)
class Hit:
    rule:     Rule
    masked:   str
    offset:   int


def find_secrets(text: str, *, max_hits: int = 25) -> list[Hit]:
    """Credential-looking strings in `text`, masked; deduplicated by (rule, secret)."""
    hits: list[Hit] = []
    seen: set[tuple[str, str]] = set()

    def add(rule: Rule, raw: str, pos: int) -> None:
        k = (rule.key, raw)
        if k in seen or len(hits) >= max_hits:
            return
        seen.add(k)
        shown = raw if rule.key == "private_key" else mask_secret(raw[:120])
        hits.append(Hit(rule, shown, pos))

    for rule in RULES:
        for m in rule.pattern.finditer(text):
            raw = m.group(rule.group) if rule.group else m.group(0)
            if rule.key == "aws_key_id" and any(h.rule.key == "aws_secret" for h in hits):
                continue                                   # the secret finding already covers it
            if rule.key == "service_account":
                raw = '"type": "service_account" … "private_key"'
            add(rule, raw, m.start())

    generic_rule = Rule("generic", "hard-coded credential", _GENERIC, Severity.MEDIUM,
                        Confidence.TENTATIVE,
                        "Matched a credential-named assignment holding a high-entropy value. "
                        "Review it: it may be a real secret or an opaque identifier.")
    covered = {h.masked for h in hits}
    for m in _GENERIC.finditer(text):
        val = m.group(1)
        if _looks_random(val) and mask_secret(val) not in covered:
            add(generic_rule, val, m.start())
    return hits
