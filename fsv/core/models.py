"""FSV Data Models"""

from __future__ import annotations
from enum import Enum
from typing import Any
from urllib.parse import urlparse
import hashlib
import uuid

from pydantic import BaseModel, Field, field_validator

from fsv.core.taxonomy import owasp_for_cwe


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH:     4,
    Severity.MEDIUM:   3,
    Severity.LOW:      2,
    Severity.INFO:     1,
}


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"

    @property
    def finished(self) -> bool:
        return self in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED)


class Confidence(str, Enum):
    """How sure FSV is about a finding (Burp-style)."""
    CERTAIN   = "certain"
    FIRM      = "firm"
    TENTATIVE = "tentative"


class FindingStatus(str, Enum):
    """
    Triage state of a finding.
      open           — untriaged (default)
      confirmed      — verified as a real issue
      false_positive — not a real issue; excluded from risk score
      accepted_risk  — real, but the owner accepts it; excluded from risk score
      fixed          — remediated; excluded from risk score
      superseded     — set automatically on an attack-path finding when one of its
                       links was triaged away (not user-settable)
    """
    OPEN           = "open"
    CONFIRMED      = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK  = "accepted_risk"
    FIXED          = "fixed"
    SUPERSEDED     = "superseded"

    @property
    def counts_toward_risk(self) -> bool:
        return self in (FindingStatus.OPEN, FindingStatus.CONFIRMED)

    @classmethod
    def user_settable(cls) -> list["FindingStatus"]:
        return [m for m in cls if m is not cls.SUPERSEDED]


class ScanProfile(str, Enum):
    """
    Preset scan intensity.
      passive    — no payloads sent; headers/SSL/DNS/fingerprint only
      balanced   — passive + safe active checks, polite rate (default)
      aggressive — all modules, higher concurrency & rate
      deep       — all modules, as thorough as FSV gets: crawls wider and deeper, hunts for hidden parameters,
                   probes a larger list of exposed files and tries more payload shapes. Slower and noisier
                   (more requests) — for targets you own and can afford to hit harder
    """
    PASSIVE    = "passive"
    BALANCED   = "balanced"
    AGGRESSIVE = "aggressive"
    DEEP       = "deep"


def finding_fingerprint(module: str, title: str, parameter: str | None, url: str) -> str:
    """
    Stable identity of an issue across scans of the same host. Paths are left
    out on purpose: a missing header on 40 pages is one issue, not 40.
    """
    host = urlparse(url).netloc.lower()
    raw  = f"{module}|{title}|{parameter or ''}|{host}"
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


class Finding(BaseModel):
    """A single vulnerability or informational finding."""
    id:             str       = ""
    title:          str
    severity:       Severity
    url:            str
    module:         str
    description:    str
    evidence:       str       = ""
    recommendation: str       = ""
    references:     list[str] = []
    cvss_score:     float | None = None
    cwe:            str | None   = None
    owasp:          str | None   = None
    parameter:      str | None   = None
    confidence:     Confidence   = Confidence.FIRM
    affected_urls:  list[str]    = []
    fingerprint:    str          = ""
    status:         FindingStatus = FindingStatus.OPEN
    triage_note:    str          = ""
    extra:          dict[str, Any] = {}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())[:8]
        if not self.owasp:
            self.owasp = owasp_for_cwe(self.cwe)
        if not self.fingerprint:
            self.fingerprint = finding_fingerprint(
                self.module, self.title, self.parameter, self.url
            )
        if not self.affected_urls:
            self.affected_urls = [self.url]


_LIMITS = {
    "max_urls":     (1, 2000),
    "timeout":      (1, 120),
    "depth":        (0, 6),
    "threads":      (1, 64),
    "max_retries":  (0, 5),
    "max_duration": (0, 86_400),
}


class ScanConfig(BaseModel):
    """Configuration for a single scan."""
    target:       str
    modules:      list[str]  = []          # empty = all enabled
    max_urls:     int        = 50
    timeout:      int        = 10
    crawl:        bool       = True
    user_agent:   str        = ""
    headers:      dict[str, str] = {}
    cookies:      dict[str, str] = {}
    depth:        int        = 2
    threads:      int        = 10
    profile:      ScanProfile = ScanProfile.BALANCED
    rate_per_sec: float      = 20.0
    max_retries:  int        = 2
    rotate_ua:    bool       = False
    respect_robots: bool     = False
    max_duration: int        = 0                         # seconds; 0 = no limit
    use_ct_logs:  bool       = False                     # query crt.sh for subdomains (sends the domain to a 3rd party)
    allow_external: bool     = True                      # allow modules that contact hosts other than the target
    exclude_paths: list[str] = Field(default_factory=list)   # glob patterns, e.g. "/admin/*"
    seed_urls:    list[str]  = Field(default_factory=list)   # extra same-origin entry points
    tags:         list[str]  = Field(default_factory=list)   # free-form labels for history
    proxy:        str        = ""                        # http(s)://host:port, "env" = HTTPS_PROXY/HTTP_PROXY, "" = direct

    @field_validator("target")
    @classmethod
    def _normalize_target(cls, v: str) -> str:
        return normalize_target(v)

    @property
    def deep(self) -> bool:
        return self.profile == ScanProfile.DEEP

    @field_validator("max_urls", "timeout", "depth", "threads", "max_retries", "max_duration")
    @classmethod
    def _clamp(cls, v: int, info) -> int:
        lo, hi = _LIMITS[info.field_name]
        return max(lo, min(hi, int(v)))

    @field_validator("rate_per_sec")
    @classmethod
    def _clamp_rate(cls, v: float) -> float:
        return max(0.5, min(200.0, float(v)))

    @field_validator("exclude_paths", "tags", "seed_urls")
    @classmethod
    def _strip_list(cls, v: list[str]) -> list[str]:
        return [s.strip() for s in v if s and s.strip()]


def normalize_target(raw: str) -> str:
    """
    Normalise user input into an absolute http(s) URL.
    Raises ValueError for anything that is not a usable web target.
    """
    v = (raw or "").strip()
    if not v:
        raise ValueError("target is empty")
    if "://" not in v:
        v = "https://" + v
    p = urlparse(v)
    if p.scheme.lower() not in ("http", "https"):
        raise ValueError(f"unsupported scheme '{p.scheme}' — only http/https")
    if not p.hostname:
        raise ValueError("target has no hostname")
    if any(c.isspace() for c in v):
        raise ValueError("target contains whitespace")
    try:
        _ = p.port   # raises ValueError on a non-numeric port (e.g. javascript:alert(1))
    except ValueError:
        raise ValueError("target has an invalid port")
    return p._replace(scheme=p.scheme.lower(), netloc=p.netloc.lower(),
                      fragment="").geturl()


class ScanProgress(BaseModel):
    """Real-time progress update streamed over WebSocket."""
    scan_id:  str
    phase:    str
    current:  int
    total:    int
    message:  str
    pct:      float = 0.0
    findings: int   = 0

    def model_post_init(self, __context: Any) -> None:
        if self.total > 0:
            self.pct = round((self.current / self.total) * 100, 1)


_RISK_WEIGHTS = {
    Severity.CRITICAL: 40,
    Severity.HIGH:     18,
    Severity.MEDIUM:   7,
    Severity.LOW:      2,
    Severity.INFO:     0,
}

# Tentative findings count for less — they are hints, not proof.
_CONFIDENCE_FACTOR = {
    Confidence.CERTAIN:   1.0,
    Confidence.FIRM:      1.0,
    Confidence.TENTATIVE: 0.5,
}


class ScanResult(BaseModel):
    """Complete result of a finished scan."""
    scan_id:      str
    target:       str
    status:       ScanStatus
    started_at:   str
    finished_at:  str       = ""
    duration_s:   float     = 0.0
    urls_scanned: int       = 0
    urls:         list[str]     = []
    findings:     list[Finding] = []
    tech_stack:   list[str]     = []
    error:        str | None    = None
    stats:        dict[str, Any] = {}
    profile:      str           = "balanced"
    modules_run:  list[str]     = []
    module_errors: dict[str, int] = {}
    module_error_samples: dict[str, str] = {}      # first error message per module (why it failed)
    tags:         list[str]     = []

    # ── counting (only findings that still count toward risk) ──────────

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.status.counts_toward_risk]

    def _count(self, sev: Severity) -> int:
        return sum(1 for f in self.active_findings if f.severity == sev)

    @property
    def critical_count(self) -> int:
        return self._count(Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return self._count(Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return self._count(Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return self._count(Severity.LOW)

    @property
    def info_count(self) -> int:
        return self._count(Severity.INFO)

    @property
    def suppressed_count(self) -> int:
        return len(self.findings) - len(self.active_findings)

    @property
    def risk_score(self) -> int:
        """
        Weighted 0–100 risk score. Each severity contributes a diminishing
        amount so a handful of criticals dominates but ten lows don't eclipse
        one critical. Triaged-away findings (false positive / accepted / fixed)
        don't count; tentative ones count half. Higher = worse.
        """
        score = 0.0
        for sev, w in _RISK_WEIGHTS.items():
            bucket = sorted(
                (_CONFIDENCE_FACTOR[f.confidence] for f in self.active_findings
                 if f.severity == sev),
                reverse=True,
            )
            for i, factor in enumerate(bucket):
                score += w * factor * (0.7 ** i)   # each additional finding worth less
        return int(min(100, round(score)))

    @property
    def grade(self) -> str:
        """Letter grade from the risk score (A best, F worst)."""
        s = self.risk_score
        if self.critical_count > 0:            return "F"
        if s >= 60:                            return "F"
        if s >= 40:                            return "D"
        if s >= 22:                            return "C"
        if s >= 10:                            return "B"
        if s >= 3:                             return "A"
        return "A+"

    def counts(self) -> dict[str, int]:
        return {
            "critical":   self.critical_count,
            "high":       self.high_count,
            "medium":     self.medium_count,
            "low":        self.low_count,
            "info":       self.info_count,
            "total":      len(self.active_findings),
            "suppressed": self.suppressed_count,
        }

    def owasp_breakdown(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for f in self.active_findings:
            key = f.owasp or "other"
            out[key] = out.get(key, 0) + 1
        return dict(sorted(out.items()))

    def summary_dict(self) -> dict:
        return {
            "scan_id":      self.scan_id,
            "target":       self.target,
            "status":       self.status.value,
            "started_at":   self.started_at,
            "finished_at":  self.finished_at,
            "duration_s":   self.duration_s,
            "urls_scanned": self.urls_scanned,
            "tech_stack":   self.tech_stack,
            "risk_score":   self.risk_score,
            "grade":        self.grade,
            "profile":      self.profile,
            "stats":        self.stats,
            "modules_run":  self.modules_run,
            "module_errors":self.module_errors,
            "module_error_samples": self.module_error_samples,
            "tags":         self.tags,
            "error":        self.error,
            "counts":       self.counts(),
            "owasp":        self.owasp_breakdown(),
        }
