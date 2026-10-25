"""
FSV — README badge for a scan:  [ FSV security | A · 2026-10-25 ]

A static SVG in the flat shields.io shape, monochrome to match FSV. It carries the scan date, because a
grade is a statement about one moment — an undated "A" would keep claiming safety long after it stopped
being true.
"""
from __future__ import annotations
from html import escape

from fsv.core.models import ScanResult

# grade → right-hand fill (brightest = best) and text colour
_FILL = {"A": ("#e9e9ee", "#0b0b0d"), "B": ("#c9c9d0", "#0b0b0d"), "C": ("#9a9aa4", "#0b0b0d"),
         "D": ("#5f5f68", "#ffffff"), "F": ("#26262b", "#ffffff")}


def _width(text: str) -> int:
    # Verdana 11px averages ~6.6px per character; generous enough that nothing clips
    return int(len(text) * 6.6) + 12


def render(result: ScanResult, label: str = "FSV security") -> str:
    grade = result.grade
    date = (result.finished_at or result.started_at or "")[:10]
    value = f"{grade} · {date}" if date else grade
    fill, ink = _FILL.get(grade, _FILL["F"])
    lw, vw = _width(label), _width(value)
    w = lw + vw
    title = f"{label}: grade {grade} (risk {result.risk_score}/100), scanned {date or 'unknown date'}"
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="20" role="img" aria-label="{escape(title)}">'
        f'<title>{escape(title)}</title>'
        f'<linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#fff" stop-opacity=".18"/>'
        f'<stop offset="1" stop-opacity=".12"/></linearGradient>'
        f'<clipPath id="r"><rect width="{w}" height="20" rx="3"/></clipPath>'
        f'<g clip-path="url(#r)"><rect width="{lw}" height="20" fill="#0b0b0d"/>'
        f'<rect x="{lw}" width="{vw}" height="20" fill="{fill}"/><rect width="{w}" height="20" fill="url(#s)"/></g>'
        f'<g text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
        f'<text x="{lw/2:.1f}" y="14" fill="#f4f4f6">{escape(label)}</text>'
        f'<text x="{lw + vw/2:.1f}" y="14" fill="{ink}" font-weight="bold">{escape(value)}</text></g></svg>\n'
    )
