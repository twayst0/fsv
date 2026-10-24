"""
FSV — Report Generators
───────────────────────
Turns a ScanResult into human- and machine-readable reports:

  • generate_markdown         — a detailed, remediation-focused assessment report
  • generate_remediation_plan — a prioritised, do-this-first fix plan
  • generate_html             — a self-contained, shareable/printable HTML report
  • generate_json             — the full structured result
  • generate_sarif            — SARIF 2.1.0 for CI / code-scanning ingestion

Every finding is rendered with *where* it was found, *what it triggers* (impact),
*how it is abused* (attack scenario), and *how to fix it* (ordered steps) — the
enrichment attached by core.knowledge.
"""

from __future__ import annotations
import json
import html as _html
from datetime import datetime

from fsv.core.models import ScanResult, Severity
from fsv.core import knowledge


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]


# ══════════════════════════════════════════════════════════════════════════════
# Markdown
# ══════════════════════════════════════════════════════════════════════════════

def generate_markdown(result: ScanResult) -> str:
    L: list[str] = []
    a = L.append

    a("# FSV Security Assessment Report")
    a("")
    a(f"**Target:** `{result.target}`  ")
    a(f"**Scan ID:** `{result.scan_id}`  ")
    a(f"**Profile:** {result.profile}  ")
    a(f"**Started:** {result.started_at}  ")
    a(f"**Finished:** {result.finished_at}  ")
    a(f"**Duration:** {result.duration_s:.1f}s  ")
    a(f"**URLs analysed:** {result.urls_scanned}  ")
    if result.tech_stack:
        a(f"**Technology:** {', '.join(result.tech_stack)}  ")
    a("")

    # ── Executive summary ─────────────────────────────────────────────────
    a("## 1. Executive Summary")
    a("")
    a(f"FSV assessed `{result.target}` and recorded a risk score of "
      f"**{result.risk_score}/100** — overall security grade **{result.grade}**.")
    a("")
    a(_verdict_line(result))
    a("")
    a("| Severity | Count | What it means |")
    a("|----------|:-----:|---------------|")
    a(f"| 🔴 Critical | {result.critical_count} | Exploitable now; immediate action |")
    a(f"| 🟠 High     | {result.high_count} | Serious; fix in this cycle |")
    a(f"| 🟡 Medium   | {result.medium_count} | Meaningful risk; schedule a fix |")
    a(f"| 🔵 Low      | {result.low_count} | Hardening / defence-in-depth |")
    a(f"| ⚪ Info     | {result.info_count} | Informational / recon surface |")
    a(f"| **Total**   | **{len(result.findings)}** | |")
    a("")

    if not result.findings:
        a("✅ **No findings.** No weaknesses were detected within the configured scan scope. "
          "Note that a clean automated scan is not proof of security — consider a manual review "
          "for authorization logic and business-logic flaws, which scanners cannot see.")
        _append_methodology(a, result)
        return "\n".join(L)

    # ── Top priorities ────────────────────────────────────────────────────
    a("## 2. Top Priorities")
    a("")
    a("Fix these first (ranked by severity × confidence):")
    a("")
    for i, f in enumerate(result.top_findings(5), 1):
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        a(f"{i}. {emoji} **{f.title}** — `{f.location}`  \n   {_first_sentence(f.impact)}")
    a("")

    # ── OWASP coverage ────────────────────────────────────────────────────
    a("## 3. OWASP Top 10 (2021) Mapping")
    a("")
    cov = result.owasp_coverage
    if cov:
        a("| OWASP Category | Findings |")
        a("|----------------|:--------:|")
        for cat, n in cov.items():
            a(f"| {cat} | {n} |")
    a("")

    # ── Findings by severity ──────────────────────────────────────────────
    a("## 4. Detailed Findings")
    a("")
    idx = 0
    for sev in _SEV_ORDER:
        group = [f for f in result.findings if f.severity == sev]
        if not group:
            continue
        emoji = SEVERITY_EMOJI.get(sev, "⚪")
        a(f"### {emoji} {sev.value.upper()} ({len(group)})")
        a("")
        for f in group:
            idx += 1
            _render_finding_md(a, idx, f)

    _append_methodology(a, result)
    return "\n".join(L)


def _render_finding_md(a, idx: int, f) -> None:
    a(f"#### {idx}. {f.title}")
    a("")
    meta = [f"**Severity:** {f.severity.value.upper()}",
            f"**Confidence:** {f.confidence.value if hasattr(f.confidence,'value') else f.confidence}"]
    if f.cwe:
        meta.append(f"**CWE:** [{f.cwe}]({knowledge.cwe_url(f.cwe)})")
    if f.owasp:
        meta.append(f"**OWASP:** {f.owasp}")
    if f.cvss_score is not None:
        meta.append(f"**CVSS:** {f.cvss_score}")
    a(" · ".join(meta))
    a("")
    a(f"- **Location (where):** `{f.location}`")
    a(f"- **Module:** `{f.module}`")
    a("")
    a("**Description**  ")
    a(f.description)
    a("")
    if f.impact:
        a("**Impact — what this triggers**  ")
        a(f.impact)
        a("")
    if f.attack_scenario:
        a("**How it is exploited (attack scenario)**  ")
        a(f.attack_scenario)
        a("")
    if f.evidence:
        a("**Evidence**")
        a("```")
        a(f.evidence[:800])
        a("```")
        a("")
    steps = f.remediation_steps or ([] if not f.recommendation else None)
    if steps:
        a("**Remediation — how to fix**")
        for i, s in enumerate(steps, 1):
            a(f"{i}. {s}")
        a("")
    elif f.recommendation:
        a("**Remediation — how to fix**  ")
        a(f.recommendation)
        a("")
    if f.references:
        a("**References**")
        for r in f.references:
            a(f"- {r}")
        a("")
    a("---")
    a("")


def _append_methodology(a, result: ScanResult) -> None:
    a("## Appendix A — Methodology & Scope")
    a("")
    a("FSV is a defensive assessment tool. It crawls the target within its own origin "
      "(skipping logout/destructive links and static assets), runs site-wide recon modules "
      "once and per-URL modules against each discovered URL, then deduplicates and ranks "
      "findings. Active checks use benign markers/timing probes — no data is read, modified "
      "or exfiltrated, and no weaponised exploit is produced.")
    a("")
    if result.stats:
        s = result.stats
        a("**Scan statistics**  ")
        a(f"- Requests sent: {s.get('requests', 0)}  ")
        a(f"- Cache hits: {s.get('cache_hits', 0)}  ")
        a(f"- Retries: {s.get('retries', 0)}  ")
        a(f"- Errors: {s.get('errors', 0)}  ")
        a(f"- Bytes received: {s.get('bytes_in', 0):,}  ")
        a("")
    a("**Limitations.** Automated scanning cannot find broken authorization, business-logic "
      "flaws, or chained multi-step attacks. Treat this report as a strong baseline, not a "
      "certificate of security.")
    a("")
    a("*Generated by FSV — for authorized security testing only.*")


def _verdict_line(result: ScanResult) -> str:
    if result.critical_count:
        return (f"> ⚠ **{result.critical_count} critical** issue(s) require immediate attention — "
                "they are likely exploitable as-is.")
    if result.high_count:
        return f"> **{result.high_count} high-severity** issue(s) should be fixed this cycle."
    if result.medium_count:
        return "> Mostly medium/low issues — schedule hardening work."
    return "> Only low/informational findings — a healthy posture; keep hardening."


def _first_sentence(text: str) -> str:
    if not text:
        return ""
    s = text.strip().split(". ")[0]
    return (s + ".") if not s.endswith(".") else s


# ══════════════════════════════════════════════════════════════════════════════
# Prioritised remediation plan
# ══════════════════════════════════════════════════════════════════════════════

def generate_remediation_plan(result: ScanResult) -> str:
    L: list[str] = []
    a = L.append
    a(f"# Remediation Plan — {result.target}")
    a("")
    a(f"Risk score **{result.risk_score}/100** (grade **{result.grade}**) · "
      f"{len(result.findings)} finding(s).")
    a("")
    if not result.findings:
        a("Nothing to remediate within scope. ✅")
        return "\n".join(L)

    ranked = sorted(result.findings, key=knowledge.remediation_priority, reverse=True)
    # de-dup by (title, cwe) so repeated findings collapse into one action
    seen: set = set()
    step_no = 0
    for f in ranked:
        key = (f.title, f.cwe)
        if key in seen:
            continue
        seen.add(key)
        step_no += 1
        count = sum(1 for g in result.findings if (g.title, g.cwe) == key)
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        a(f"## {step_no}. {emoji} {f.title}  "
          f"({f.severity.value.upper()}{' ×' + str(count) if count > 1 else ''})")
        if f.owasp:
            a(f"*{f.owasp}* · `{f.cwe or 'n/a'}`")
        a("")
        locs = sorted({g.location for g in result.findings if (g.title, g.cwe) == key})
        a(f"**Where:** " + ", ".join(f"`{x}`" for x in locs[:6]) +
          (f" (+{len(locs)-6} more)" if len(locs) > 6 else ""))
        a("")
        steps = f.remediation_steps or ([f.recommendation] if f.recommendation else [])
        for i, s in enumerate(steps, 1):
            a(f"{i}. {s}")
        a("")
    return "\n".join(L)


# ══════════════════════════════════════════════════════════════════════════════
# JSON
# ══════════════════════════════════════════════════════════════════════════════

def generate_json(result: ScanResult) -> str:
    return json.dumps(
        {
            **result.summary_dict(),
            "findings": [f.model_dump() for f in result.findings],
        },
        indent=2,
        ensure_ascii=False,
    )


# ══════════════════════════════════════════════════════════════════════════════
# SARIF 2.1.0 (CI / code-scanning)
# ══════════════════════════════════════════════════════════════════════════════

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}


def generate_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rule_id = (f.cwe or f.module or "finding").replace(" ", "_")
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription": {"text": (f.description or f.title)[:1000]},
                "helpUri": knowledge.cwe_url(f.cwe) or "https://owasp.org/",
                "properties": {"security-severity": str(f.cvss_score or 0.0),
                               "tags": ["security", f.module]},
            }
        results.append({
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{f.title}: {_first_sentence(f.impact) or f.description[:200]}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.url},
                }
            }],
            "properties": {
                "severity": f.severity.value,
                "confidence": f.confidence.value if hasattr(f.confidence, "value") else str(f.confidence),
                "parameter": f.parameter or "",
                "owasp": f.owasp,
            },
        })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FSV",
                "informationUri": "https://github.com/fsvproject/fsv",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ══════════════════════════════════════════════════════════════════════════════
# HTML (self-contained, printable)
# ══════════════════════════════════════════════════════════════════════════════

_SEV_COLOR = {
    "critical": "#ff4d4d", "high": "#ff9f45", "medium": "#ffd93d",
    "low": "#4dabf7", "info": "#9aa0a6",
}


def generate_html(result: ScanResult) -> str:
    e = _html.escape
    grade_color = {"A+": "#37d67a", "A": "#37d67a", "B": "#ffd93d", "C": "#ff9f45",
                   "D": "#ff9f45", "F": "#ff4d4d"}.get(result.grade, "#ccc")

    rows = []
    for sev in _SEV_ORDER:
        n = len([f for f in result.findings if f.severity == sev])
        rows.append(
            f'<div class="chip" style="--c:{_SEV_COLOR[sev.value]}">'
            f'<b>{n}</b><span>{sev.value}</span></div>'
        )
    chips = "".join(rows)

    owasp_rows = "".join(
        f"<tr><td>{e(cat)}</td><td style='text-align:center'>{n}</td></tr>"
        for cat, n in result.owasp_coverage.items()
    ) or "<tr><td colspan=2>—</td></tr>"

    cards = []
    idx = 0
    for sev in _SEV_ORDER:
        for f in [x for x in result.findings if x.severity == sev]:
            idx += 1
            c = _SEV_COLOR[sev.value]
            steps = f.remediation_steps or ([f.recommendation] if f.recommendation else [])
            steps_html = "".join(f"<li>{e(s)}</li>" for s in steps)
            refs_html = "".join(
                f'<li><a href="{e(r)}" target="_blank" rel="noopener">{e(r)}</a></li>'
                for r in (f.references or [])
            )
            cards.append(f"""
            <div class="card" style="--c:{c}">
              <div class="card-h">
                <span class="sev" style="background:{c}">{sev.value.upper()}</span>
                <h3>{idx}. {e(f.title)}</h3>
              </div>
              <div class="kv">
                <span>📍 <code>{e(f.location)}</code></span>
                <span>{e(f.cwe or '')}</span>
                <span>{e(f.owasp or '')}</span>
                <span>{('CVSS ' + str(f.cvss_score)) if f.cvss_score is not None else ''}</span>
                <span>confidence: {e(f.confidence.value if hasattr(f.confidence,'value') else str(f.confidence))}</span>
              </div>
              <p>{e(f.description)}</p>
              {f'<div class="block"><h4>Impact — what it triggers</h4><p>{e(f.impact)}</p></div>' if f.impact else ''}
              {f'<div class="block"><h4>How it is exploited</h4><pre class="scenario">{e(f.attack_scenario)}</pre></div>' if f.attack_scenario else ''}
              {f'<div class="block"><h4>Evidence</h4><pre>{e(f.evidence[:800])}</pre></div>' if f.evidence else ''}
              {f'<div class="block"><h4>Remediation</h4><ol>{steps_html}</ol></div>' if steps_html else ''}
              {f'<div class="block"><h4>References</h4><ul class="refs">{refs_html}</ul></div>' if refs_html else ''}
            </div>""")
    cards_html = "".join(cards) or "<p class='ok'>✅ No findings within scope.</p>"

    return f"""<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>FSV Report — {e(result.target)}</title>
<style>
  :root {{ color-scheme: dark; }}
  * {{ box-sizing: border-box; }}
  body {{ margin:0; font:15px/1.6 -apple-system,Segoe UI,Roboto,sans-serif;
         background:#0b0d10; color:#e6e8eb; padding:0 0 60px; }}
  .wrap {{ max-width: 980px; margin: 0 auto; padding: 0 20px; }}
  header {{ padding:40px 0 24px; border-bottom:1px solid #20242b; margin-bottom:28px; }}
  h1 {{ font-size:26px; margin:0 0 6px; }}
  .muted {{ color:#9aa0a6; font-size:13px; }}
  .grade {{ display:inline-flex; align-items:center; justify-content:center;
            width:92px; height:92px; border-radius:20px; font-size:40px; font-weight:800;
            border:2px solid var(--g); color:var(--g); float:right; }}
  .chips {{ display:flex; gap:10px; flex-wrap:wrap; margin:18px 0; }}
  .chip {{ border:1px solid #20242b; border-left:4px solid var(--c); border-radius:10px;
           padding:8px 14px; min-width:88px; }}
  .chip b {{ font-size:22px; color:var(--c); display:block; }}
  .chip span {{ font-size:12px; color:#9aa0a6; text-transform:uppercase; }}
  h2 {{ font-size:18px; margin:34px 0 12px; border-bottom:1px solid #20242b; padding-bottom:6px; }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  td,th {{ border:1px solid #20242b; padding:7px 10px; text-align:left; }}
  .card {{ border:1px solid #20242b; border-left:4px solid var(--c); border-radius:12px;
           padding:18px 20px; margin:16px 0; background:#0f1217; }}
  .card-h {{ display:flex; align-items:center; gap:12px; }}
  .card-h h3 {{ margin:0; font-size:17px; }}
  .sev {{ font-size:11px; font-weight:700; color:#0b0d10; padding:3px 9px; border-radius:20px; }}
  .kv {{ display:flex; flex-wrap:wrap; gap:14px; color:#9aa0a6; font-size:12.5px; margin:10px 0; }}
  .kv code {{ color:#88ffbb; }}
  code {{ background:#171b21; padding:1px 6px; border-radius:5px; font-size:13px; }}
  .block {{ margin-top:12px; }}
  .block h4 {{ margin:0 0 6px; font-size:13px; text-transform:uppercase; letter-spacing:.04em; color:#b6bcc4; }}
  pre {{ background:#070809; border:1px solid #20242b; border-radius:8px; padding:12px;
         overflow:auto; font-size:12.5px; white-space:pre-wrap; word-break:break-word; }}
  pre.scenario {{ color:#cfd3d8; }}
  ol,ul {{ margin:0; padding-left:20px; }} li {{ margin:3px 0; }}
  .refs a {{ color:#4dabf7; word-break:break-all; }}
  .ok {{ color:#37d67a; font-size:18px; }}
  footer {{ margin-top:40px; color:#6b7178; font-size:12px; text-align:center; }}
</style></head><body><div class="wrap">
<header>
  <div class="grade" style="--g:{grade_color}">{result.grade}</div>
  <h1>FSV Security Assessment</h1>
  <div class="muted">Target <code>{e(result.target)}</code> · risk {result.risk_score}/100 ·
    profile {e(result.profile)} · {result.urls_scanned} URL(s) · {result.duration_s:.1f}s</div>
  {f'<div class="muted">Tech: {e(", ".join(result.tech_stack))}</div>' if result.tech_stack else ''}
  <div class="chips">{chips}</div>
</header>
<h2>OWASP Top 10 (2021) Mapping</h2>
<table><tr><th>Category</th><th>Findings</th></tr>{owasp_rows}</table>
<h2>Findings ({len(result.findings)})</h2>
{cards_html}
<footer>Generated by FSV — for authorized security testing only.</footer>
</div></body></html>"""
