"""
FSV — Report generators

    markdown  human-readable remediation report
    json      full machine-readable result
    html      self-contained, printable report (no external assets)
    sarif     SARIF 2.1.0 for GitHub code scanning / CI dashboards
    csv       one row per finding, for spreadsheets / ticket import
"""

from __future__ import annotations
import csv
import html as _html
import io
import json

from fsv import __version__
from fsv.core.models import ScanResult, Severity, Finding, FindingStatus
from fsv.core.taxonomy import owasp_label, cwe_url, OWASP_2021


SEVERITY_EMOJI = {
    Severity.CRITICAL: "🔴",
    Severity.HIGH:     "🟠",
    Severity.MEDIUM:   "🟡",
    Severity.LOW:      "🔵",
    Severity.INFO:     "⚪",
}

FORMATS = ("md", "json", "html", "sarif", "csv")


def render(result: ScanResult, fmt: str) -> tuple[str, str]:
    """Return (content, media_type) for a format name."""
    fmt = fmt.lower().lstrip(".")
    if fmt in ("md", "markdown"):
        return generate_markdown(result), "text/markdown; charset=utf-8"
    if fmt == "json":
        return generate_json(result), "application/json"
    if fmt == "html":
        return generate_html(result), "text/html; charset=utf-8"
    if fmt == "sarif":
        return generate_sarif(result), "application/sarif+json"
    if fmt == "csv":
        return generate_csv(result), "text/csv; charset=utf-8"
    raise ValueError(f"unknown report format '{fmt}' (choose: {', '.join(FORMATS)})")


def format_for_path(path: str) -> str:
    low = path.lower()
    for ext, fmt in ((".sarif", "sarif"), (".sarif.json", "sarif"), (".json", "json"),
                     (".html", "html"), (".htm", "html"), (".csv", "csv")):
        if low.endswith(ext):
            return fmt
    return "md"


def _executive_summary(r: ScanResult) -> str:
    c = r.counts()
    if r.status.value == "failed":
        return f"The scan failed before completing: {r.error or 'unknown error'}."
    if c["total"] == 0:
        return ("No open issues were found by the enabled checks. Automated scanning cannot "
                "prove the absence of vulnerabilities; pair it with manual review.")
    parts = []
    if c["critical"] or c["high"]:
        parts.append(f"**{c['critical']} critical and {c['high']} high** severity issue(s) "
                     "need attention first")
    if c["medium"]:
        parts.append(f"{c['medium']} medium")
    if c["low"] or c["info"]:
        parts.append(f"{c['low']} low and {c['info']} informational")
    top = r.owasp_breakdown()
    top_cat = max(top, key=top.get) if top else None
    tail = (f" The most common category is {owasp_label(top_cat)}."
            if top_cat and top_cat != "other" else "")
    return (f"Overall grade **{r.grade}** (risk {r.risk_score}/100). "
            + "; ".join(parts) + "." + tail)


# ── markdown ──────────────────────────────────────────────────────────────────

def generate_markdown(result: ScanResult) -> str:
    lines: list[str] = []
    a = lines.append
    c = result.counts()

    a("# FSV Security Scan Report")
    a("")
    a(f"**Target:** `{result.target}`  ")
    a(f"**Scan ID:** `{result.scan_id}`  ")
    a(f"**Profile:** {result.profile}  ")
    a(f"**Status:** {result.status.value}  ")
    a(f"**Started:** {result.started_at}  ")
    a(f"**Finished:** {result.finished_at}  ")
    a(f"**Duration:** {result.duration_s:.1f}s  ")
    a(f"**URLs Scanned:** {result.urls_scanned}  ")
    if result.tech_stack:
        a(f"**Tech Stack:** {', '.join(result.tech_stack)}  ")
    a(f"**Risk:** {result.grade} ({result.risk_score}/100)")
    a("")
    a("## Executive summary")
    a("")
    a(_executive_summary(result))
    a("")

    a("## Summary")
    a("")
    a("| Severity | Count |")
    a("|----------|-------|")
    a(f"| 🔴 Critical | {c['critical']} |")
    a(f"| 🟠 High     | {c['high']} |")
    a(f"| 🟡 Medium   | {c['medium']} |")
    a(f"| 🔵 Low      | {c['low']} |")
    a(f"| ⚪ Info     | {c['info']} |")
    a(f"| **Total**   | **{c['total']}** |")
    if c["suppressed"]:
        a(f"| Triaged out (false positive / accepted / fixed) | {c['suppressed']} |")
    a("")

    owasp = result.owasp_breakdown()
    if owasp:
        a("### By OWASP Top 10 (2021)")
        a("")
        a("| Category | Findings |")
        a("|----------|----------|")
        for k, n in owasp.items():
            a(f"| {owasp_label(k) if k != 'other' else 'Other / uncategorized'} | {n} |")
        a("")

    if result.module_errors:
        a("> ⚠ Some modules raised errors and may have incomplete coverage: "
          + ", ".join(f"`{m}` ×{n}" for m, n in result.module_errors.items()))
        a("")

    if not result.findings:
        a("✅ No vulnerabilities detected.")
        return "\n".join(lines)

    a("---")
    a("")
    a("## Findings")
    a("")

    for i, f in enumerate(result.findings, 1):
        emoji = SEVERITY_EMOJI.get(f.severity, "⚪")
        status = "" if f.status == FindingStatus.OPEN else f"  _[{f.status.value}]_"
        a(f"### {i}. {emoji} {f.title}{status}")
        a("")
        a(f"- **Severity:** {f.severity.value.upper()} · **Confidence:** {f.confidence.value}")
        a(f"- **Module:** `{f.module}`")
        a(f"- **URL:** `{f.url}`")
        if len(f.affected_urls) > 1:
            a(f"- **Affected URLs:** {len(f.affected_urls)}")
        if f.parameter:
            a(f"- **Parameter:** `{f.parameter}`")
        if f.cwe:
            link = cwe_url(f.cwe)
            a(f"- **CWE:** [{f.cwe}]({link})" if link else f"- **CWE:** {f.cwe}")
        if f.owasp:
            a(f"- **OWASP:** {owasp_label(f.owasp)}")
        if f.cvss_score is not None:
            a(f"- **CVSS:** {f.cvss_score}")
        if f.triage_note:
            a(f"- **Triage note:** {f.triage_note}")
        a("")
        a("**Description:**")
        a(f.description)
        a("")
        if f.evidence:
            a("**Evidence:**")
            a(f"```\n{f.evidence[:800]}\n```")
            a("")
        if len(f.affected_urls) > 1:
            a("<details><summary>Affected URLs</summary>")
            a("")
            for u in f.affected_urls[:50]:
                a(f"- `{u}`")
            if len(f.affected_urls) > 50:
                a(f"- … and {len(f.affected_urls) - 50} more")
            a("")
            a("</details>")
            a("")
        if f.recommendation:
            a("**Recommendation:**")
            a(f.recommendation)
            a("")
        if f.references:
            a("**References:**")
            for ref in f.references:
                a(f"- {ref}")
            a("")
        a("---")
        a("")

    a("")
    a(f"*Report generated by FSV v{__version__} — for authorized security testing only.*")
    return "\n".join(lines)


# ── json ──────────────────────────────────────────────────────────────────────

def generate_json(result: ScanResult) -> str:
    return json.dumps(
        {
            **result.summary_dict(),
            "urls":     result.urls,
            "findings": [f.model_dump(mode="json") for f in result.findings],
        },
        indent=2,
        ensure_ascii=False,
    )


# ── csv ───────────────────────────────────────────────────────────────────────

_CSV_COLS = ["severity", "confidence", "status", "title", "module", "url", "affected",
             "parameter", "cwe", "owasp", "cvss_score", "description", "recommendation",
             "fingerprint"]


def generate_csv(result: ScanResult) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(_CSV_COLS)
    for f in result.findings:
        w.writerow([
            f.severity.value, f.confidence.value, f.status.value, f.title, f.module, f.url,
            len(f.affected_urls), f.parameter or "", f.cwe or "", f.owasp or "",
            "" if f.cvss_score is None else f.cvss_score, f.description, f.recommendation,
            f.fingerprint,
        ])
    return buf.getvalue()


# ── sarif ─────────────────────────────────────────────────────────────────────

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5", Severity.HIGH: "8.0", Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0", Severity.INFO: "0.0",
}


def _rule_id(f: Finding) -> str:
    slug = "".join(ch if ch.isalnum() else "-" for ch in f.title.lower()).strip("-")
    while "--" in slug:
        slug = slug.replace("--", "-")
    return f"fsv/{f.module}/{slug[:60]}"


def generate_sarif(result: ScanResult) -> str:
    rules: dict[str, dict] = {}
    results = []
    for f in result.findings:
        rid = _rule_id(f)
        if rid not in rules:
            tags = ["security", f.module]
            if f.cwe:
                tags.append(f"external/cwe/{f.cwe.lower()}")
            if f.owasp:
                tags.append(f"owasp/{f.owasp}")
            rules[rid] = {
                "id": rid,
                "name": f.title,
                "shortDescription": {"text": f.title},
                "fullDescription":  {"text": f.description[:1000]},
                "help": {"text": f.recommendation or f.description,
                         "markdown": f.recommendation or f.description},
                "helpUri": (f.references[0] if f.references else cwe_url(f.cwe)) or
                           "https://owasp.org/www-project-top-ten/",
                "properties": {
                    "tags": tags,
                    "security-severity": (str(f.cvss_score) if f.cvss_score is not None
                                          else _SECURITY_SEVERITY[f.severity]),
                    "precision": {"certain": "very-high", "firm": "high",
                                  "tentative": "medium"}[f.confidence.value],
                },
            }
        suppressed = not f.status.counts_toward_risk
        entry = {
            "ruleId": rid,
            "level": _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.title}"
                        + (f" (parameter `{f.parameter}`)" if f.parameter else "")},
            "locations": [
                {"physicalLocation": {"artifactLocation": {"uri": u}}}
                for u in f.affected_urls[:20]
            ],
            "partialFingerprints": {"fsv/v1": f.fingerprint},
            "properties": {"confidence": f.confidence.value, "evidence": f.evidence[:500]},
        }
        if suppressed:
            entry["suppressions"] = [{
                "kind": "external",
                "status": "accepted",
                "justification": f"{f.status.value}: {f.triage_note}".strip(": "),
            }]
        results.append(entry)

    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "FSV",
                "version": __version__,
                "informationUri": "https://github.com/fsvproject/fsv",
                "rules": list(rules.values()),
            }},
            "invocations": [{
                "executionSuccessful": result.status.value == "completed",
                "startTimeUtc": result.started_at,
                "endTimeUtc": result.finished_at or result.started_at,
            }],
            "properties": {"target": result.target, "scan_id": result.scan_id,
                           "grade": result.grade, "risk_score": result.risk_score},
            "results": results,
        }],
    }
    return json.dumps(doc, indent=2, ensure_ascii=False)


# ── html ──────────────────────────────────────────────────────────────────────

_SEV_HEX = {"critical": "#d92d43", "high": "#e07a1f", "medium": "#c9a400",
            "low": "#2f7de1", "info": "#7a808c"}


def generate_html(result: ScanResult) -> str:
    """A single self-contained HTML file — no external assets, printable, shareable."""
    e = _html.escape
    c = result.counts()
    g = result.grade
    gcolor = {"A+": "#2f9e5e", "A": "#2f9e5e", "B": "#c9a400", "C": "#e07a1f",
              "D": "#e07a1f", "F": "#d92d43"}.get(g, "#7a808c")

    def chip(sev: str, n: int) -> str:
        return (f'<span class="chip" style="--c:{_SEV_HEX[sev]}">'
                f'<b>{n}</b> {sev}</span>')

    def finding_block(i: int, f: Finding) -> str:
        meta = [e(f.confidence.value), f"<code>{e(f.module)}</code>"]
        if f.cwe:
            meta.append(f'<a href="{e(cwe_url(f.cwe) or "")}" target="_blank" rel="noopener">{e(f.cwe)}</a>')
        if f.owasp:
            meta.append(e(f"{f.owasp} {OWASP_2021.get(f.owasp, '')}"))
        if f.parameter:
            meta.append(f"param <code>{e(f.parameter)}</code>")
        if f.cvss_score is not None:
            meta.append(f"CVSS {f.cvss_score}")
        if f.status != FindingStatus.OPEN:
            meta.append(f'<span class="st">{e(f.status.value)}</span>')
        extra = ""
        if len(f.affected_urls) > 1:
            items = "".join(f"<li><code>{e(u)}</code></li>" for u in f.affected_urls[:50])
            more = (f"<li>… and {len(f.affected_urls) - 50} more</li>"
                    if len(f.affected_urls) > 50 else "")
            extra = (f'<details><summary>{len(f.affected_urls)} affected URLs</summary>'
                     f'<ul class="urls">{items}{more}</ul></details>')
        refs = ""
        if f.references:
            links = "".join(
                f'<li><a href="{e(r)}" target="_blank" rel="noopener">{e(r)}</a></li>'
                for r in f.references)
            refs = f'<div class="refs"><b>References</b><ul>{links}</ul></div>'
        opened = "open" if f.severity.value in ("critical", "high") else ""
        return f"""
<details class="f" data-sev="{f.severity.value}" {opened}>
  <summary>
    <span class="sev" style="background:{_SEV_HEX[f.severity.value]}">{e(f.severity.value)}</span>
    <span class="ft">{e(f.title)}</span>
  </summary>
  <div class="fb">
    <div class="meta">{' · '.join(meta)}</div>
    <div class="url"><code>{e(f.url)}</code></div>
    <p>{e(f.description)}</p>
    {'<pre>' + e(f.evidence[:800]) + '</pre>' if f.evidence else ''}
    {'<p><b>Remediation.</b> ' + e(f.recommendation) + '</p>' if f.recommendation else ''}
    {'<p class="note"><b>Triage.</b> ' + e(f.triage_note) + '</p>' if f.triage_note else ''}
    {extra}
    {refs}
  </div>
</details>"""

    findings_html = "".join(finding_block(i, f) for i, f in enumerate(result.active_findings, 1))
    tech = " ".join(f'<span class="tag">{e(t)}</span>' for t in result.tech_stack)
    filters = "".join(
        f'<button class="fil" data-sev="{s}">{s} {c[s]}</button>'
        for s in ("critical", "high", "medium", "low", "info") if c[s])

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>FSV Report — {e(result.target)}</title>
<style>
:root{{color-scheme:light dark;--bg:#0b0b0f;--card:#16161c;--line:#26262f;--tx:#ececef;--mut:#9a9aa6}}
@media(prefers-color-scheme:light){{:root{{--bg:#f4f4f7;--card:#fff;--line:#e3e3ea;--tx:#15151a;--mut:#64646f}}}}
*{{box-sizing:border-box}}
body{{margin:0;font:15px/1.6 system-ui,-apple-system,"Segoe UI",sans-serif;background:var(--bg);color:var(--tx)}}
.wrap{{max-width:900px;margin:0 auto;padding:32px 20px 80px}}
h1{{font-size:22px;margin:0 0 4px}}
.sub{{color:var(--mut);font-size:13px;word-break:break-all}}
.hero{{display:flex;gap:22px;align-items:center;background:var(--card);border:1px solid var(--line);border-radius:16px;padding:22px;margin:20px 0}}
.grade{{width:92px;height:92px;border-radius:20px;display:grid;place-items:center;font-size:40px;font-weight:800;color:#fff;background:{gcolor};flex:none}}
.score{{font-size:13px;color:var(--mut)}}
.chips,.filters{{display:flex;flex-wrap:wrap;gap:8px;margin-top:10px}}
.chip{{border:1px solid var(--line);border-left:3px solid var(--c);border-radius:8px;padding:4px 10px;font-size:12px}}
.chip b{{color:var(--c)}}
.summary{{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px;margin:14px 0}}
.tag{{display:inline-block;background:var(--line);border-radius:6px;padding:2px 8px;font-size:12px;margin:2px}}
.filters{{margin:18px 0 6px}}
.fil{{background:var(--card);border:1px solid var(--line);color:var(--tx);border-radius:999px;padding:5px 12px;font-size:12px;cursor:pointer;text-transform:capitalize}}
.fil.off{{opacity:.35}}
.f{{background:var(--card);border:1px solid var(--line);border-radius:12px;margin:10px 0;overflow:hidden}}
.f summary{{display:flex;gap:10px;align-items:center;padding:12px 14px;cursor:pointer;list-style:none}}
.f summary::-webkit-details-marker{{display:none}}
.sev{{color:#fff;border-radius:6px;padding:2px 9px;font-size:11px;text-transform:uppercase;font-weight:700;flex:none}}
.ft{{font-weight:650}}
.fb{{padding:0 14px 14px;border-top:1px solid var(--line)}}
.meta{{color:var(--mut);font-size:12px;margin:10px 0}}
.meta code,.url code{{font-family:ui-monospace,monospace}}
.st{{background:var(--line);border-radius:5px;padding:1px 7px}}
.url{{font-size:12px;color:var(--mut);word-break:break-all;margin-bottom:8px}}
pre{{background:var(--bg);border:1px solid var(--line);border-radius:8px;padding:10px;overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-word}}
.urls{{max-height:200px;overflow:auto;font-size:12px}}
.refs ul{{margin:4px 0}}
.refs a{{color:#3b82f6;font-size:12px;word-break:break-all}}
.note{{color:var(--mut)}}
footer{{color:var(--mut);font-size:12px;text-align:center;margin-top:30px}}
@media print{{.filters{{display:none}}.f{{break-inside:avoid}}.f[data-sev]{{}}details{{open:open}}}}
</style></head><body><div class="wrap">
<h1>FSV Security Scan Report</h1>
<div class="sub">{e(result.target)} · {e(result.profile)} · {e(result.started_at[:19].replace('T',' '))} UTC · scan {e(result.scan_id[:8])}</div>
<div class="hero">
  <div class="grade">{g}</div>
  <div>
    <div class="score">risk score {result.risk_score}/100 · {c['total']} findings · {result.urls_scanned} URLs · {result.duration_s:.1f}s</div>
    <div class="chips">{chip('critical',c['critical'])}{chip('high',c['high'])}{chip('medium',c['medium'])}{chip('low',c['low'])}{chip('info',c['info'])}</div>
    <div>{tech}</div>
  </div>
</div>
<div class="summary">{e(_executive_summary(result))}</div>
<div class="filters">{filters}</div>
{findings_html or '<p>✅ No findings that count toward risk.</p>'}
<footer>Generated by FSV v{e(__version__)} — authorized security testing only. Not a guarantee of security.</footer>
</div>
<script>
document.querySelectorAll('.fil').forEach(function(b){{
  b.addEventListener('click',function(){{
    b.classList.toggle('off');
    var hide=new Set([].concat.apply([],[].map.call(document.querySelectorAll('.fil.off'),function(x){{return x.dataset.sev}})));
    document.querySelectorAll('.f').forEach(function(f){{
      f.style.display=hide.has(f.dataset.sev)?'none':'';
    }});
  }});
}});
</script>
</body></html>"""
