"""FSV Data Models"""

from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, HttpUrl
import uuid
from datetime import datetime


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


class Confidence(str, Enum):
    """How sure FSV is about a finding (Burp-style)."""
    CERTAIN   = "certain"
    FIRM      = "firm"
    TENTATIVE = "tentative"


class ScanProfile(str, Enum):
    """
    Preset scan intensity.
      passive    — no payloads sent; headers/SSL/DNS/fingerprint only
      balanced   — passive + safe active checks, polite rate (default)
      aggressive — all modules, higher concurrency & rate
    """
    PASSIVE    = "passive"
    BALANCED   = "balanced"
    AGGRESSIVE = "aggressive"


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
    parameter:      str | None   = None
    confidence:     Confidence   = Confidence.FIRM
    extra:          dict[str, Any] = {}

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = str(uuid.uuid4())[:8]


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


class ScanProgress(BaseModel):
    """Real-time progress update streamed over WebSocket."""
    scan_id:  str
    phase:    str
    current:  int
    total:    int
    message:  str
    pct:      float = 0.0

    def model_post_init(self, __context: Any) -> None:
        if self.total > 0:
            self.pct = round((self.current / self.total) * 100, 1)


class ScanResult(BaseModel):
    """Complete result of a finished scan."""
    scan_id:      str
    target:       str
    status:       ScanStatus
    started_at:   str
    finished_at:  str       = ""
    duration_s:   float     = 0.0
    urls_scanned: int       = 0
    findings:     list[Finding] = []
    tech_stack:   list[str]     = []
    error:        str | None    = None
    stats:        dict[str, Any] = {}
    profile:      str           = "balanced"

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def risk_score(self) -> int:
        """
        Weighted 0–100 risk score. Each severity contributes a diminishing
        amount so a handful of criticals dominates but ten lows don't eclipse
        one critical. Higher = worse.
        """
        weights = {
            Severity.CRITICAL: 40,
            Severity.HIGH:     18,
            Severity.MEDIUM:   7,
            Severity.LOW:      2,
            Severity.INFO:     0,
        }
        score = 0.0
        # diminishing returns per severity bucket
        counts = {
            Severity.CRITICAL: self.critical_count,
            Severity.HIGH:     self.high_count,
            Severity.MEDIUM:   self.medium_count,
            Severity.LOW:      self.low_count,
            Severity.INFO:     self.info_count,
        }
        for sev, n in counts.items():
            w = weights[sev]
            for i in range(n):
                score += w * (0.7 ** i)   # each additional finding worth less
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

    def summary_dict(self) -> dict:
        return {
            "scan_id":     self.scan_id,
            "target":      self.target,
            "status":      self.status,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "duration_s":  self.duration_s,
            "urls_scanned":self.urls_scanned,
            "tech_stack":  self.tech_stack,
            "risk_score":  self.risk_score,
            "grade":       self.grade,
            "profile":     self.profile,
            "stats":       self.stats,
            "counts": {
                "critical": self.critical_count,
                "high":     self.high_count,
                "medium":   self.medium_count,
                "low":      self.low_count,
                "info":     self.info_count,
                "total":    len(self.findings),
            },
        }
