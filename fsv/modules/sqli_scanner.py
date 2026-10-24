"""
FSV Module — SQL Injection Detection

Three complementary, non-destructive techniques:
  1. Error-based   — a metacharacter triggers a database error signature.
  2. Boolean-based — a TRUE condition returns the original page while a FALSE
                     condition returns a clearly different one (content-length
                     inference). No data is read or modified.
  3. Time-based    — (aggressive profile only) a benign SLEEP/pg_sleep/WAITFOR
                     makes the response measurably slower than a baseline.

None of the payloads alter or exfiltrate data; they only *prove* that input
reaches the SQL parser. Destructive statements are never sent.
"""

from __future__ import annotations
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from fsv.core.scanner import BaseScanner
from fsv.core.models import Finding, Severity, Confidence
from fsv.config import (
    SQLI_PAYLOADS, SQLI_ERROR_SIGNATURES, SQLI_BOOLEAN_PAIRS,
    SQLI_TIME_PAYLOADS, SQLI_TIME_DELAY,
)


class SQLiScanner(BaseScanner):
    name = "sqli"

    async def scan(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        if not params:
            return []

        aggressive = getattr(self.scan_config.profile, "value", "") == "aggressive"
        findings: list[Finding] = []

        for param in params:
            f = await self._error_based(parsed, params, param)
            if f is None:
                f = await self._boolean_based(parsed, params, param)
            if f is None and aggressive:
                f = await self._time_based(parsed, params, param)
            if f:
                findings.append(f)

        return findings

    def _mutate(self, parsed, params, param, value) -> str:
        test_params = {k: v[0] for k, v in params.items()}
        test_params[param] = value
        return urlunparse(parsed._replace(query=urlencode(test_params)))

    # ── 1) error-based ─────────────────────────────────────────────────────
    async def _error_based(self, parsed, params, param) -> Finding | None:
        base_val = params[param][0]
        for payload in SQLI_PAYLOADS:
            test_url = self._mutate(parsed, params, param, base_val + payload)
            status, _, body = await self.fetch(test_url)
            if status == -1 or not body:
                continue
            low = body.lower()
            for sig in SQLI_ERROR_SIGNATURES:
                if sig in low:
                    return Finding(
                        title       = "SQL Injection (Error-Based)",
                        severity    = Severity.CRITICAL,
                        confidence  = Confidence.FIRM,
                        url         = urlunparse(parsed),
                        module      = self.name,
                        parameter   = param,
                        description = (
                            f"The `{param}` parameter is vulnerable to SQL injection. Injecting a "
                            "SQL metacharacter produced a database error, proving user input reaches "
                            "the SQL parser unsanitised."
                        ),
                        evidence    = (
                            f"Parameter: {param}\nPayload: {payload}\n"
                            f"DB error signature matched: '{sig}'\nTest URL: {test_url[:220]}"
                        ),
                        recommendation = (
                            "Use parameterised queries / prepared statements; never concatenate "
                            "input into SQL. Use an ORM, apply least-privilege DB accounts, and "
                            "disable verbose DB errors in production."
                        ),
                        cwe         = "CWE-89",
                        cvss_score  = 9.8,
                        extra       = {"payload": payload, "db_error": sig, "technique": "error"},
                    )
        return None

    # ── 2) boolean-based ───────────────────────────────────────────────────
    async def _boolean_based(self, parsed, params, param) -> Finding | None:
        base_val = params[param][0]
        # baseline (unmodified) response length
        _, _, base_body = await self.fetch(self._mutate(parsed, params, param, base_val))
        if not base_body:
            return None
        base_len = len(base_body)

        for true_p, false_p in SQLI_BOOLEAN_PAIRS:
            _, _, t_body = await self.fetch(self._mutate(parsed, params, param, base_val + true_p))
            _, _, f_body = await self.fetch(self._mutate(parsed, params, param, base_val + false_p))
            if not t_body or not f_body:
                continue
            tl, fl = len(t_body), len(f_body)
            # TRUE ≈ baseline, FALSE clearly different → injectable inference.
            true_matches = abs(tl - base_len) <= max(20, base_len * 0.02)
            false_differs = abs(fl - base_len) > max(60, base_len * 0.10)
            if true_matches and false_differs and abs(tl - fl) > max(60, base_len * 0.10):
                return Finding(
                    title       = "SQL Injection (Boolean-Based Blind)",
                    severity    = Severity.CRITICAL,
                    confidence  = Confidence.TENTATIVE,
                    url         = urlunparse(parsed),
                    module      = self.name,
                    parameter   = param,
                    description = (
                        f"The `{param}` parameter appears vulnerable to blind SQL injection. A "
                        "logically TRUE condition returned a page matching the baseline while a "
                        "FALSE condition returned a clearly different response — classic boolean "
                        "inference. No data was read or altered."
                    ),
                    evidence    = (
                        f"Parameter: {param}\n"
                        f"baseline length: {base_len}\n"
                        f"TRUE  ('{true_p}') length: {tl}\n"
                        f"FALSE ('{false_p}') length: {fl}"
                    ),
                    recommendation = (
                        "Use parameterised queries / prepared statements, validate input types, "
                        "and apply least-privilege DB accounts. Blind SQLi is as dangerous as "
                        "error-based — treat as critical."
                    ),
                    cwe         = "CWE-89",
                    cvss_score  = 9.0,
                    extra       = {"technique": "boolean", "base_len": base_len,
                                   "true_len": tl, "false_len": fl},
                )
        return None

    # ── 3) time-based (aggressive only) ─────────────────────────────────────
    async def _time_based(self, parsed, params, param) -> Finding | None:
        base_val = params[param][0]
        # Measure a baseline round-trip.
        t0 = time.monotonic()
        await self.http.request(self._mutate(parsed, params, param, base_val), cache=False)
        baseline = time.monotonic() - t0

        d = SQLI_TIME_DELAY
        for tmpl in SQLI_TIME_PAYLOADS:
            payload = tmpl.format(d=d)
            t1 = time.monotonic()
            r = await self.http.request(
                self._mutate(parsed, params, param, base_val + payload), cache=False)
            elapsed = time.monotonic() - t1
            if r.status == -1:
                continue
            # Delayed response must be clearly slower than baseline by ~the delay.
            if elapsed >= baseline + (d * 0.7):
                # Confirm with a control that should NOT sleep.
                ctrl = payload.replace(f"SLEEP({d})", "SLEEP(0)") \
                              .replace(f"pg_sleep({d})", "pg_sleep(0)") \
                              .replace(f"0:0:{d}", "0:0:0") \
                              .replace(f"PG_SLEEP({d})", "PG_SLEEP(0)")
                t2 = time.monotonic()
                await self.http.request(
                    self._mutate(parsed, params, param, base_val + ctrl), cache=False)
                ctrl_elapsed = time.monotonic() - t2
                if ctrl_elapsed < baseline + (d * 0.5):
                    return Finding(
                        title       = "SQL Injection (Time-Based Blind)",
                        severity    = Severity.CRITICAL,
                        confidence  = Confidence.FIRM,
                        url         = urlunparse(parsed),
                        module      = self.name,
                        parameter   = param,
                        description = (
                            f"The `{param}` parameter appears vulnerable to time-based blind SQL "
                            f"injection. A benign SLEEP({d}) payload delayed the response by "
                            "~the sleep duration while a SLEEP(0) control returned promptly — proving "
                            "the injected SQL executed. No data was read or modified."
                        ),
                        evidence    = (
                            f"Parameter: {param}\nPayload: {payload}\n"
                            f"baseline: {baseline:.2f}s | delayed: {elapsed:.2f}s | "
                            f"control(SLEEP 0): {ctrl_elapsed:.2f}s"
                        ),
                        recommendation = (
                            "Use parameterised queries / prepared statements; validate input; apply "
                            "least-privilege DB accounts and query timeouts. Time-based blind SQLi "
                            "allows full data extraction — treat as critical."
                        ),
                        cwe         = "CWE-89",
                        cvss_score  = 9.0,
                        extra       = {"technique": "time", "baseline_s": round(baseline, 2),
                                       "delayed_s": round(elapsed, 2)},
                    )
        return None
