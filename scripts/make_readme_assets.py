#!/usr/bin/env python3
"""
Generates the animated SVGs used in README.md  →  docs/assets/*.svg

    python scripts/make_readme_assets.py

Design rules (they are what makes these render everywhere GitHub shows them):
  • self-contained — no external fonts, images or scripts (GitHub loads SVGs in <img> mode)
  • animation is CSS @keyframes only; the *un-animated* state is a complete, readable picture,
    so `prefers-reduced-motion` and renderers without animation still show the full content
  • every animated element is driven by one master loop per file, so all parts stay in sync
  • text that quotes a scan comes from docs/assets/demo-scan.json (a real scan of examples/demo_site.py)
"""
from __future__ import annotations
import json
import math
import os
from html import escape as esc

from fsv import __version__
from fsv.core import registry

SHORT_VERSION = ".".join(__version__.split(".")[:2])   # "2.4.0" → "2.4": the hero must never advertise an old release
NMOD = len(registry.load_registry())      # the README says how many modules there are; never type the number by hand

HERE = os.path.dirname(os.path.abspath(__file__))
ASSETS = os.path.join(HERE, "..", "docs", "assets")

# Monochrome, metallic: graphite glass, chrome type. Severity is a luminance ladder (brightest = worst),
# always paired with its label, so nothing depends on telling hues apart.
C = dict(bg="#0a0a0c", panel="#141417", line="#2a2a30", text="#f4f4f6", mut="#a3a3ad", faint="#62626c",
         crit="#ffffff", high="#dcdce2", med="#b4b4bd", low="#8c8c96", ok="#e9e9ee", info="#6e6e78",
         accent="#c7c7cf")
SEV = {"critical": C["crit"], "high": C["high"], "medium": C["med"], "low": C["low"], "info": C["info"]}
SANS = '-apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Helvetica,Arial,sans-serif'
MONO = 'ui-monospace,SFMono-Regular,Menlo,Consolas,"Liberation Mono",monospace'

# Shared by every file: brushed-graphite background, chrome text/edge gradients, glass highlight.
METAL_DEFS = """
<radialGradient id="bgm" cx="30%" cy="-20%" r="140%"><stop offset="0" stop-color="#1d1d22"/><stop offset=".55" stop-color="#0e0e11"/><stop offset="1" stop-color="#060607"/></radialGradient>
<linearGradient id="chrome" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff"/><stop offset=".48" stop-color="#d6d6dc"/><stop offset=".52" stop-color="#9c9ca6"/><stop offset="1" stop-color="#ececf0"/></linearGradient>
<linearGradient id="rim" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff" stop-opacity=".42"/><stop offset=".25" stop-color="#ffffff" stop-opacity=".12"/><stop offset="1" stop-color="#ffffff" stop-opacity=".05"/></linearGradient>
<linearGradient id="glass" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#ffffff" stop-opacity=".085"/><stop offset=".5" stop-color="#ffffff" stop-opacity=".035"/><stop offset="1" stop-color="#ffffff" stop-opacity=".02"/></linearGradient>
<pattern id="brush" width="4" height="4" patternUnits="userSpaceOnUse"><rect width="4" height="1" fill="#fff" fill-opacity=".012"/></pattern>"""

BASE_CSS = f"""
text{{font-family:{SANS};fill:{C['text']}}}
.m{{font-family:{MONO}}}
.mut{{fill:{C['mut']}}} .faint{{fill:{C['faint']}}}
.b{{font-weight:700}}
@media (prefers-reduced-motion:reduce){{*{{animation:none!important}}}}
"""


def svg(w: int, h: int, title: str, desc: str, defs: str, body: str, css: str = "") -> str:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" width="{w}" height="{h}" '
            f'role="img" aria-labelledby="t d">\n<title id="t">{esc(title)}</title>\n<desc id="d">{esc(desc)}</desc>\n'
            f'<defs>{METAL_DEFS}{defs}</defs>\n<style>{BASE_CSS}{css}</style>\n{body}\n</svg>\n')


class Loop:
    """Keyframes for one master loop of T seconds. Each call returns a ready-to-use style attribute."""
    def __init__(self, T: float, prefix: str):
        self.T, self.prefix, self.n, self.css = T, prefix, 0, []

    def _pct(self, t: float) -> float:
        return max(0.0, min(100.0, t / self.T * 100))

    def anim(self, stops: list[tuple[float, str]], ease: str = "linear") -> str:
        """Register keyframes and return the `animation` shorthand VALUE (so several can be comma-joined)."""
        name = f"{self.prefix}{self.n}"; self.n += 1
        rows, last = [], -1.0
        for t, decl in stops:
            p = self._pct(t)
            p = max(p, last + 0.001) if p <= last else p
            rows.append(f"{p:.3f}%{{{decl}}}"); last = p
        if not rows[0].startswith("0.000%"):
            rows.insert(0, f"0%{{{stops[0][1]}}}")
        if self._pct(stops[-1][0]) < 100:
            rows.append(f"100%{{{stops[-1][1]}}}")
        self.css.append(f"@keyframes {name}{{{''.join(rows)}}}")
        return f"{name} {self.T}s {ease} infinite"

    def custom(self, stops: list[tuple[float, str]], ease: str = "linear") -> str:
        """Like anim() but returns a complete `animation:` declaration."""
        return "animation:" + self.anim(stops, ease)

    def reveal_fill(self, t: float) -> str:
        """For <tspan>: `opacity` does not apply to tspans everywhere, `fill-opacity` does."""
        off = self.T - 0.6
        return self.custom([(0, "fill-opacity:0"), (t, "fill-opacity:0"), (t + .01, "fill-opacity:1"), (off, "fill-opacity:1"), (off + .4, "fill-opacity:0")])

    def appear(self, t: float, dur: float = 0.35, off_at: float | None = None, rise: float = 0) -> str:
        """hidden → visible at t; hidden again just before the loop restarts (or at off_at)."""
        off = off_at if off_at is not None else self.T - 0.6
        hid = "opacity:0" + (f";transform:translateY({rise}px)" if rise else "")
        vis = "opacity:1" + (";transform:translateY(0)" if rise else "")
        return self.custom([(0, hid), (t, hid), (t + dur, vis), (off, vis), (off + 0.4, hid)])

    def style(self) -> str:
        return "".join(self.css)


# ═══════════════════════════════════════════════════════════════════════════════
# 0) LOGO — wire-frame globe with four nodes (vector redraw of the FSV mark)
# ═══════════════════════════════════════════════════════════════════════════════

def _ellipse_point(cx, cy, rx, ry, rot_deg, t_deg):
    t, r = math.radians(t_deg), math.radians(rot_deg)
    x, y = rx * math.cos(t), ry * math.sin(t)
    return cx + x * math.cos(r) - y * math.sin(r), cy + x * math.sin(r) + y * math.cos(r)


def logo_defs(p: str) -> str:
    """Gradients for one logo instance; `p` prefixes ids so several logos can share a file."""
    return (f'<linearGradient id="{p}band" x1="0" y1="0" x2="1" y2="1">'
            f'<stop offset="0" stop-color="#ffffff"/><stop offset=".45" stop-color="#e4e4e9"/>'
            f'<stop offset=".7" stop-color="#a9a9b2"/><stop offset="1" stop-color="#f2f2f5"/></linearGradient>'
            f'<radialGradient id="{p}node" cx=".38" cy=".32" r=".75"><stop offset="0" stop-color="#ffffff"/>'
            f'<stop offset=".6" stop-color="#e2e2e7"/><stop offset="1" stop-color="#a4a4ad"/></radialGradient>')


def logo_group(p: str, cx: float, cy: float, R: float, edge: str = "#8d8d96") -> str:
    """The mark centred at (cx, cy) with outer radius R. `edge` is a thin outline that keeps the
    silver bands visible on white backgrounds too."""
    w = R * .085
    rings = [  # (rx, ry, rotation, dy) relative to R
        (1.0, 1.0, 0, 0),             # outer sphere
        (.52, .96, 8, -.02),          # meridian
        (.98, .32, -14, -.10),        # tilted equator (upper band)
        (.98, .36, 4, .16),           # lower band
    ]
    out = []
    for rx, ry, rot, dy in rings:
        e = (f'cx="{cx:.1f}" cy="{cy + dy*R:.1f}" rx="{rx*R:.1f}" ry="{ry*R:.1f}" '
             f'transform="rotate({rot} {cx:.1f} {cy + dy*R:.1f})" fill="none"')
        out.append(f'<ellipse {e} stroke="{edge}" stroke-opacity=".55" stroke-width="{w + 2.2:.1f}"/>'
                   f'<ellipse {e} stroke="url(#{p}band)" stroke-width="{w:.1f}"/>')
    # the axis is a thin rounded rect, not a <line>: a zero-width bounding box can't carry a gradient
    y0, h = cy - .95*R, 1.92*R
    out.append(f'<rect x="{cx - w/2 - 1.1:.1f}" y="{y0 - 1.1:.1f}" width="{w + 2.2:.1f}" height="{h + 2.2:.1f}" rx="{w/2 + 1.1:.1f}" fill="{edge}" fill-opacity=".55"/>'
               f'<rect x="{cx - w/2:.1f}" y="{y0:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{w/2:.1f}" fill="url(#{p}band)"/>')
    nodes = [_ellipse_point(cx, cy - .10*R, .98*R, .32*R, -14, -58),   # upper right, on the tilted band
             _ellipse_point(cx, cy - .10*R, .98*R, .32*R, -14, 140),   # left
             _ellipse_point(cx, cy + .16*R, .98*R, .36*R, 4, 52),      # lower right, on the lower band
             (cx, cy + .97*R)]                                         # south pole
    for x, y in nodes:
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{R*.085:.1f}" fill="url(#{p}node)" stroke="{edge}" stroke-opacity=".7" stroke-width="1.2"/>')
    return "<g>" + "".join(out) + "</g>"


def logo() -> str:
    W = 256
    body = logo_group("lg", 128, 126, 104)
    return svg(W, W, "FSV logo", "A wire-frame globe of silver bands with four nodes.", logo_defs("lg"), body)


# ═══════════════════════════════════════════════════════════════════════════════
# 1) HERO — radar sweep that "finds" things
# ═══════════════════════════════════════════════════════════════════════════════

def hero() -> str:
    W, H, cx, cy, R, T = 1200, 380, 925, 190, 135, 6.0
    blips = [  # clockwise angle from 12 o'clock, radius fraction, severity, label
        (38, .62, "high", "dangling CNAME"), (92, .88, "critical", "orphaned bucket"),
        (150, .55, "high", "SPF include → NXDOMAIN"), (208, .8, "critical", "XSS → session"),
        (262, .46, "medium", "source map"),
    ]
    css, blip_svg = [], []
    for i, (deg, rf, sev, label) in enumerate(blips):
        p = deg / 360 * 100
        x = cx + R * rf * math.sin(math.radians(deg)); y = cy - R * rf * math.cos(math.radians(deg))
        col = SEV[sev]
        css.append(f"@keyframes bo{i}{{0%,{p-.01:.2f}%{{opacity:.16}}{p:.2f}%{{opacity:1}}{min(p+30, 99.9):.2f}%{{opacity:.55}}100%{{opacity:.16}}}}"
                   f"@keyframes bs{i}{{0%,{p-.01:.2f}%{{transform:scale(1)}}{p:.2f}%{{transform:scale(2.3)}}{min(p+9, 99.9):.2f}%{{transform:scale(1)}}100%{{transform:scale(1)}}}}")
        left = deg > 180
        lx, anchor = (x - 24, "end") if left else (x + 24, "start")
        blip_svg.append(
            f'<g style="animation:bo{i} {T}s linear infinite;opacity:1">'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="5" fill="{col}" style="transform-box:fill-box;transform-origin:center;animation:bs{i} {T}s linear infinite"/>'
            f'<circle cx="{x:.1f}" cy="{y:.1f}" r="11" fill="none" stroke="{col}" stroke-opacity=".5"/>'
            f'<text x="{lx:.1f}" y="{y+4:.1f}" text-anchor="{anchor}" class="m" font-size="12" fill="{col}" style="fill:{col}">{esc(label)}</text></g>')
    css.append(f"@keyframes spin{{to{{transform:rotate(360deg)}}}}"
               f"@keyframes drift1{{to{{transform:translate(40px,28px)}}}}@keyframes drift2{{to{{transform:translate(-46px,-22px)}}}}"
               f"@keyframes ping{{0%{{transform:scale(1);opacity:.9}}100%{{transform:scale(14);opacity:0}}}}")
    rings = "".join(f'<circle cx="{cx}" cy="{cy}" r="{R*f:.1f}" fill="none" stroke="#fff" stroke-opacity=".09"/>' for f in (1, .66, .33))
    rays = "".join(f'<line x1="{cx}" y1="{cy}" x2="{cx + R*math.sin(math.radians(a)):.1f}" y2="{cy - R*math.cos(math.radians(a)):.1f}" stroke="#fff" stroke-opacity=".05"/>' for a in range(0, 360, 45))
    sx, sy = cx - R * math.sin(math.radians(60)), cy - R * math.cos(math.radians(60))
    defs = f"""
<radialGradient id="o1"><stop offset="0" stop-color="#e6e6ee" stop-opacity=".22"/><stop offset="1" stop-color="#e6e6ee" stop-opacity="0"/></radialGradient>
<radialGradient id="o2"><stop offset="0" stop-color="#b9b9c4" stop-opacity=".16"/><stop offset="1" stop-color="#b9b9c4" stop-opacity="0"/></radialGradient>
<radialGradient id="o3"><stop offset="0" stop-color="#ffffff" stop-opacity=".10"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></radialGradient>
<pattern id="dots" width="26" height="26" patternUnits="userSpaceOnUse"><circle cx="1.5" cy="1.5" r="1" fill="#fff" fill-opacity=".07"/></pattern>
<linearGradient id="hl" gradientUnits="userSpaceOnUse" x1="64" y1="0" x2="640" y2="0">
  <stop offset="0" stop-color="#8e8e98"/><stop offset=".45" stop-color="#ffffff"/><stop offset=".55" stop-color="#ffffff"/><stop offset="1" stop-color="#8e8e98"/>
  <animateTransform attributeName="gradientTransform" type="translate" from="-300 0" to="300 0" dur="6s" repeatCount="indefinite"/>
</linearGradient>
<linearGradient id="sw" gradientUnits="userSpaceOnUse" x1="{cx}" y1="{cy-R}" x2="{sx:.1f}" y2="{sy:.1f}">
  <stop offset="0" stop-color="#ffffff" stop-opacity=".55"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>
<filter id="blur" x="-60%" y="-60%" width="220%" height="220%"><feGaussianBlur stdDeviation="30"/></filter>
<clipPath id="disc"><circle cx="{cx}" cy="{cy}" r="{R}"/></clipPath>""" + logo_defs("hl_")
    body = f"""
<rect width="{W}" height="{H}" fill="url(#bgm)"/>
<rect width="{W}" height="{H}" fill="url(#brush)"/>
<rect width="{W}" height="{H}" fill="url(#dots)"/>
<g filter="url(#blur)">
  <circle cx="190" cy="40" r="190" fill="url(#o1)" style="animation:drift1 14s ease-in-out infinite alternate"/>
  <circle cx="1100" cy="340" r="200" fill="url(#o2)" style="animation:drift2 17s ease-in-out infinite alternate"/>
  <circle cx="640" cy="400" r="170" fill="url(#o3)" style="animation:drift1 19s ease-in-out infinite alternate"/>
</g>
<rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="22" fill="none" stroke="url(#rim)"/>

<rect x="64" y="58" width="68" height="68" rx="18" fill="url(#glass)" stroke="url(#rim)"/>
<path d="M82 58.8 H114" stroke="#fff" stroke-opacity=".5"/>
{logo_group("hl_", 98, 92, 25, edge="#3a3a42")}
<text x="150" y="84" font-size="15" class="b" letter-spacing="4" style="fill:url(#chrome)">FSV</text>
<text x="206" y="84" font-size="13" class="mut" letter-spacing="3">WEB SECURITY SCANNER  ·  MCP TOOLKIT</text>
<text x="150" y="108" font-size="13" class="m mut">v{SHORT_VERSION} · detection-only · local-first</text>

<text x="62" y="212" font-size="58" class="b" letter-spacing="-1.5" style="fill:url(#chrome)">Finds what</text>
<text x="62" y="276" font-size="58" class="b" letter-spacing="-1.5" style="fill:url(#hl)">checklists miss.</text>
<text x="64" y="324" font-size="16" class="m mut">dangling DNS · orphaned buckets · dead SPF includes · source maps · attack paths</text>

<g>
  <circle cx="{cx}" cy="{cy}" r="{R}" fill="url(#glass)"/>
  <circle cx="{cx}" cy="{cy}" r="{R}" fill="#060607" fill-opacity=".55"/>
  {rings}{rays}
  <g clip-path="url(#disc)">
    <g style="transform-origin:{cx}px {cy}px;animation:spin {T}s linear infinite">
      <path d="M{cx} {cy} L{cx} {cy-R} A{R} {R} 0 0 0 {sx:.1f} {sy:.1f} Z" fill="url(#sw)"/>
      <line x1="{cx}" y1="{cy}" x2="{cx}" y2="{cy-R}" stroke="#ffffff" stroke-width="2" stroke-opacity=".9"/>
    </g>
  </g>
  <circle cx="{cx}" cy="{cy}" r="{R}" fill="none" stroke="url(#rim)" stroke-width="1.5"/>
  <circle cx="{cx}" cy="{cy}" r="4" fill="none" stroke="#ffffff" stroke-width="1.5" vector-effect="non-scaling-stroke" style="transform-box:fill-box;transform-origin:center;animation:ping 3s ease-out infinite"/>
  <circle cx="{cx}" cy="{cy}" r="4" fill="#ffffff"/>
  {''.join(blip_svg)}
</g>
<text x="{cx}" y="{cy+R+34}" text-anchor="middle" font-size="12" class="m mut">never claims a resource · never tests a credential</text>"""
    return svg(W, H, "FSV — finds what checklists miss",
               "Animated radar sweep that lights up findings: dangling CNAME, orphaned bucket, SPF include that no longer exists, XSS leading to session theft, exposed source map.",
               defs, body, "".join(css))


# ═══════════════════════════════════════════════════════════════════════════════
# 2) TERMINAL — a real scan, replayed
# ═══════════════════════════════════════════════════════════════════════════════

def terminal(scan: dict) -> str:
    W, T = 960, 20.0
    L = Loop(T, "tm")
    LH, X0, Y0 = 24, 28, 86
    c = scan["counts"]
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    top = sorted(scan["findings"], key=lambda f: (order[f["severity"]], f["module"] != "correlation"))
    chosen, seen = [], set()
    for want in ("Hard-Coded", "Attack Path: XSS", "Orphaned", "Sensitive File", "End-of-Life", "Source Map", "Vulnerable JavaScript"):
        f = next((f for f in top if f["title"].startswith(want) and f["title"] not in seen), None)
        if f:
            chosen.append(f); seen.add(f["title"])
    cmd = "fsv scan http://127.0.0.1:8961 --authorize"
    fix_cmd = f"fsv fixes {scan['scan_id']} nginx"

    rows: list[str] = []
    y = Y0
    t = 0.5

    # command being typed: 2 characters at a time, as inline tspans so the font's own advance width
    # decides the spacing (no hard-coded column maths)
    def typed(prompt_y: float, text: str, start: float) -> float:
        chunks = [text[i:i + 2] for i in range(0, len(text), 2)]
        spans = "".join(f'<tspan style="{L.reveal_fill(start + i * 0.045)}">{esc(ch)}</tspan>' for i, ch in enumerate(chunks))
        rows.append(f'<text x="{X0}" y="{prompt_y}" class="m" font-size="15" xml:space="preserve" style="fill:{C["ok"]}">'
                    f'<tspan style="{L.reveal_fill(start)}">$ </tspan><tspan style="fill:{C["text"]}">{spans}</tspan></text>')
        return start + len(chunks) * 0.045

    t = typed(y, cmd, t) + 0.6
    y += LH

    def line(markup: str, at: float, dy: int = LH) -> None:
        nonlocal y
        rows.append(f'<g style="{L.appear(at, .3, rise=5)}">{markup.replace("{Y}", str(y))}</g>')
        y += dy

    line(f'<text x="{X0}" y="{{Y}}" class="m" font-size="14" style="fill:{C["mut"]}">▶ Scanning <tspan style="fill:{C["text"]};text-decoration:underline">{esc(scan["target"])}</tspan>  (balanced)</text>', t); t += .55
    line(f'<text x="{X0}" y="{{Y}}" class="m" font-size="14" style="fill:{C["mut"]}">{scan["urls_scanned"]} URLs · {NMOD} modules · {scan["requests"]} requests · {scan["duration_s"]}s</text>', t); t += .7
    line(f'<text x="{X0}" y="{{Y}}" class="m" font-size="14"><tspan style="fill:{C["crit"]};font-weight:700">Risk {esc(scan["grade"])} ({scan["risk_score"]}/100)</tspan>'
         f'<tspan style="fill:{C["crit"]}">   {c["critical"]} critical</tspan><tspan style="fill:{C["high"]}">  {c["high"]} high</tspan>'
         f'<tspan style="fill:{C["med"]}">  {c["medium"]} medium</tspan><tspan style="fill:{C["low"]}">  {c["low"]} low</tspan>'
         f'<tspan style="fill:{C["info"]}">  {c["info"]} info</tspan></text>', t, dy=LH + 6); t += .8
    for f in chosen:
        col = SEV[f["severity"]]
        title = (f["title"].replace("Hard-Coded Stripe live secret key in Client-Side Code", "Hard-coded Stripe live key in client-side JS")
                 .replace("Orphaned Cloud Storage Bucket Referenced:", "Orphaned bucket referenced:"))
        if f["module"] == "correlation":
            title = "⛓ " + title
        if len(title) > 70:
            title = title[:67] + "…"
        line(f'<text x="{X0}" y="{{Y}}" class="m" font-size="13.5" style="fill:{col};font-weight:700">{f["severity"].upper():<8}</text>'
             f'<text x="{X0 + 92}" y="{{Y}}" class="m" font-size="13.5">{esc(title)}</text>', t, dy=LH - 3); t += .62
    y += 12
    line(f'<rect x="{X0-10}" y="{{Y}}" width="{W-2*X0+20}" height="26" rx="8" fill="{C["ok"]}" fill-opacity=".1" stroke="{C["ok"]}" stroke-opacity=".4" transform="translate(0,-17)"/>'
         f'<text x="{X0}" y="{{Y}}" class="m" font-size="13.5" style="fill:{C["ok"]}">→ break the chain: mark `SESSIONID` HttpOnly (one line), then fix the XSS</text>', t, dy=LH + 12); t += 1.4
    t = typed(y, fix_cmd, t) + 0.5
    y += LH
    for txt in ('add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;',
                'add_header X-Content-Type-Options "nosniff" always;',
                'server_tokens off;'):
        line(f'<text x="{X0}" y="{{Y}}" class="m" font-size="13.5" style="fill:{C["accent"]}">{esc(txt)}</text>', t, dy=LH - 4); t += .5

    H = y + 30
    bar = (f'<rect x="0" y="0" width="{W}" height="{H}" rx="16" fill="url(#bgm)"/><rect x="0.5" y="0.5" width="{W-1}" height="{H-1}" rx="16" fill="none" stroke="url(#rim)"/>'
           f'<path d="M0.5 16.5 A16 16 0 0 1 16.5 0.5 H{W-16.5} A16 16 0 0 1 {W-.5} 16.5 V46 H0.5 Z" fill="#fff" fill-opacity=".05"/>'
           f'<circle cx="26" cy="23" r="6" fill="url(#chrome)" fill-opacity=".85"/><circle cx="46" cy="23" r="6" fill="#fff" fill-opacity=".28"/><circle cx="66" cy="23" r="6" fill="#fff" fill-opacity=".14"/>'
           f'<text x="{W/2}" y="28" text-anchor="middle" font-size="13" class="m faint">fsv — demo site scan (real output)</text>')
    blink = L.custom([(0, "opacity:0"), (t, "opacity:0"), (t+.01, "opacity:1"), (t+.6, "opacity:0"), (t+1.2, "opacity:1"), (t+1.8, "opacity:0"),
                      (t+2.4, "opacity:1"), (t+3.0, "opacity:0"), (T, "opacity:0")])
    cursor = (f'<text x="{X0}" y="{y}" class="m" font-size="15" xml:space="preserve" style="fill:{C["ok"]};{L.appear(t, .01)}">$ '
              f'<tspan style="fill:{C["ok"]};{blink}">█</tspan></text>')
    body = bar + "".join(rows) + cursor
    return svg(W, H, "FSV scanning a demo site", "A terminal replay of a real FSV scan: command, risk grade, the most important findings including an attack path, then generated nginx fixes.",
               "", body, L.style())


# ═══════════════════════════════════════════════════════════════════════════════
# 3) ATTACK PATH — two mediums, one critical story, one line to break it
# ═══════════════════════════════════════════════════════════════════════════════

def attack_path() -> str:
    W, H, T = 1000, 330, 10.0
    L = Loop(T, "ap")
    ny, nh, nw = 100, 118, 250
    xs = [30, 375, 720]
    cy_ = ny + nh / 2
    nodes = [
        ("Reflected XSS", "?q=<script>…", "HIGH", C["high"]),
        ("Session cookie", "no HttpOnly flag", "HIGH", C["high"]),
        ("Account takeover", "no password, no 2FA", "CRITICAL", C["crit"]),
    ]
    stroke_hot = [C["high"], C["high"], C["crit"]]
    t_arrive = [0.4, 1.6, 3.1]
    css = [f"@keyframes dash{{to{{stroke-dashoffset:-24}}}}@keyframes pulse{{0%,100%{{opacity:.35}}50%{{opacity:1}}}}"]
    nodes_svg = []
    for i, (title, sub, sev, col) in enumerate(nodes):
        x = xs[i]
        ta = t_arrive[i]
        broken = i == 2
        hot = L.custom([(0, "stroke:#fff;stroke-opacity:.14;fill-opacity:.05"), (ta, "stroke:#fff;stroke-opacity:.14;fill-opacity:.05"),
                        (ta + .3, f"stroke:{stroke_hot[i]};stroke-opacity:1;fill-opacity:.12"),
                        (5.0 if broken else 4.9, f"stroke:{stroke_hot[i]};stroke-opacity:1;fill-opacity:.12"),
                        (5.4, ("stroke:%s;stroke-opacity:.9;fill-opacity:.10" % C["ok"]) if broken else "stroke:#fff;stroke-opacity:.14;fill-opacity:.05"),
                        (T - .6, ("stroke:%s;stroke-opacity:.9;fill-opacity:.10" % C["ok"]) if broken else "stroke:#fff;stroke-opacity:.14;fill-opacity:.05"),
                        (T, "stroke:#fff;stroke-opacity:.14;fill-opacity:.05")])
        glyph = {0: f'<path d="M{x+36} {ny+34} l14 -14 l14 14 l-14 14 z M{x+40} {ny+60} h20" stroke="{col}" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round"/>',
                 1: f'<circle cx="{x+50}" cy="{ny+36}" r="15" stroke="{col}" stroke-width="3" fill="none"/><circle cx="{x+44}" cy="{ny+31}" r="2.6" fill="{col}"/><circle cx="{x+55}" cy="{ny+40}" r="2.6" fill="{col}"/><circle cx="{x+47}" cy="{ny+43}" r="2.6" fill="{col}"/>',
                 2: f'<circle cx="{x+50}" cy="{ny+30}" r="9" stroke="{col}" stroke-width="3" fill="none"/><path d="M{x+32} {ny+56} q18 -22 36 0" stroke="{col}" stroke-width="3" fill="none" stroke-linecap="round"/>'}[i]
        blocked = ""
        if broken:
            blocked = (f'<text x="{x+nw/2}" y="{ny+nh+26}" text-anchor="middle" font-size="15" class="b" style="fill:{C["ok"]};{L.appear(5.4, .4, rise=4)}">✓ chain broken — no takeover</text>'
                       f'<text x="{x+nw/2}" y="{ny+nh+26}" text-anchor="middle" font-size="15" class="b" style="fill:{C["crit"]};{L.custom([(0, "opacity:0"), (3.7, "opacity:0"), (4.0, "opacity:1"), (5.0, "opacity:1"), (5.3, "opacity:0"), (T, "opacity:0")])}">✗ one click = full compromise</text>')
        nodes_svg.append(
            f'<rect x="{x}" y="{ny}" width="{nw}" height="{nh}" rx="18" fill="#fff" style="{hot}" stroke="#fff" stroke-opacity=".14" stroke-width="1.6" fill-opacity=".05"/>'
            f'{glyph}<text x="{x+80}" y="{ny+42}" font-size="18.5" class="b">{esc(title)}</text>'
            f'<text x="{x+80}" y="{ny+68}" font-size="13" class="m mut">{esc(sub)}</text>'
            f'<rect x="{x+20}" y="{ny+nh-34}" width="{len(sev)*8.6+22:.0f}" height="22" rx="11" fill="{col}" fill-opacity=".15" stroke="{col}" stroke-opacity=".6"/>'
            f'<text x="{x+31}" y="{ny+nh-18.5}" font-size="12" class="b" style="fill:{col}" letter-spacing="1">{sev}</text>{blocked}')
    # links: a flowing dashed arrow; the second turns green when the fix lands
    links = []
    for i in (0, 1):
        x1, x2 = xs[i] + nw, xs[i + 1]
        flow = "dash .8s linear infinite"
        if i == 1:
            tint = L.anim([(0, f"stroke:{C['crit']}"), (4.7, f"stroke:{C['crit']}"), (5.1, f"stroke:{C['ok']}"),
                           (T - .6, f"stroke:{C['ok']}"), (T, f"stroke:{C['crit']}")])
            sty_line, sty_head = f"animation:{flow},{tint}", f"animation:{tint}"
        else:
            sty_line, sty_head = f"animation:{flow}", ""
        links.append(f'<line x1="{x1+6}" y1="{cy_}" x2="{x2-10}" y2="{cy_}" stroke="{C["crit"]}" stroke-width="3" stroke-dasharray="8 8" stroke-linecap="round" style="{sty_line}"/>'
                     f'<path d="M{x2-10} {cy_-8} l10 8 l-10 8" stroke="{C["crit"]}" stroke-width="3" fill="none" stroke-linecap="round" stroke-linejoin="round" style="{sty_head}"/>')
    # packets only travel ON the links (never over the cards' text); the second run is stopped by the fix
    def packet(x_start: float, length: float, t0: float, t1: float, stop_burst: bool = False) -> str:
        end_op = "opacity:0;transform:translateX(%.0fpx) scale(2.6)" % length if stop_burst else "opacity:0;transform:translateX(%.0fpx)" % length
        st = L.custom([(0, "opacity:0;transform:translateX(0)"), (t0, "opacity:0;transform:translateX(0)"), (t0 + .08, "opacity:1;transform:translateX(0)"),
                       (t1, f"opacity:1;transform:translateX({length:.0f}px)"), (t1 + (.3 if stop_burst else .08), end_op), (T, end_op)])
        return (f'<g style="{st};transform-box:fill-box;transform-origin:center"><circle cx="{x_start:.0f}" cy="{cy_}" r="6.5" fill="{C["crit"]}"/>'
                f'<circle cx="{x_start:.0f}" cy="{cy_}" r="13" fill="{C["crit"]}" fill-opacity=".25"/></g>')
    l1s, l2s = xs[0] + nw + 10, xs[1] + nw + 10
    llen = xs[1] - 14 - l1s
    fx = (xs[1] + nw + xs[2]) / 2
    packet = (packet(l1s, llen, 0.7, 1.5) + packet(l2s, llen, 2.3, 3.1)
              + packet(l1s, llen, 6.0, 6.8) + packet(l2s, fx - 14 - l2s, 7.3, 7.9, stop_burst=True))
    # the fix badge dropping on link 2
    fix = (f'<g style="{L.custom([(0, "opacity:0;transform:translateY(-26px)"), (4.5, "opacity:0;transform:translateY(-26px)"), (4.95, "opacity:1;transform:translateY(0)"), (T-.6, "opacity:1;transform:translateY(0)"), (T-.2, "opacity:0;transform:translateY(0)"), (T, "opacity:0;transform:translateY(-26px)")], "cubic-bezier(.3,1.4,.5,1)")}">'
           f'<rect x="{fx-45}" y="{cy_-58}" width="90" height="30" rx="15" fill="{C["ok"]}" fill-opacity=".2" stroke="{C["ok"]}"/>'
           f'<text x="{fx}" y="{cy_-38}" text-anchor="middle" font-size="13" class="m b" style="fill:{C["ok"]}">+HttpOnly</text></g>')
    hdr = (f'<text x="30" y="46" font-size="24" class="b">Two “medium” findings. One critical story.</text>'
           f'<text x="30" y="72" font-size="14" class="mut">FSV reads its own findings and names the chains that are worse together — and the cheapest link to cut.</text>')
    foot = (f'<text x="30" y="{H-24}" font-size="14" class="m faint">Break the chain: mark the cookie HttpOnly (one line) — then fix the XSS and add a CSP.</text>')
    body = (f'<rect width="{W}" height="{H}" rx="22" fill="url(#bgm)"/><rect width="{W}" height="{H}" rx="22" fill="url(#brush)"/><rect x=".5" y=".5" width="{W-1}" height="{H-1}" rx="22" fill="none" stroke="url(#rim)"/>'
            + hdr + "".join(links) + "".join(nodes_svg) + packet + fix + foot)
    return svg(W, H, "Attack path: XSS → session cookie → account takeover",
               "An animated chain: reflected XSS reads a session cookie that lacks HttpOnly, leading to account takeover; adding HttpOnly breaks the chain.",
               "", body, "".join(css) + L.style())


# ═══════════════════════════════════════════════════════════════════════════════
# 4) PIPELINE
# ═══════════════════════════════════════════════════════════════════════════════

def pipeline() -> str:
    W, H, T = 1000, 270, 7.2
    stages = [("Crawl", "same-origin", "cached · polite"), (f"{NMOD} modules", "site + per-URL", "passive / active"),
              ("Aggregate", "by fingerprint", "many → 1 issue"), ("Correlate", "attack paths", "links → story"),
              ("Triage", "per host", "FP · accepted"), ("Report", "5 formats", "+ fix packs")]
    n, bw, gap, x0, y0, bh = len(stages), 128, 34, 34, 96, 104
    css = ["@keyframes flow{to{stroke-dashoffset:-20}}"]
    parts = []
    for i, (name, l1, l2) in enumerate(stages):
        x = x0 + i * (bw + gap)
        glow = f"animation:lit{i} {T}s linear infinite"
        t0 = i * (T - 1.2) / n
        css.append(f"@keyframes lit{i}{{0%,{t0/T*100:.2f}%{{stroke-opacity:.14;fill-opacity:.05}}{(t0+.4)/T*100:.2f}%{{stroke-opacity:1;fill-opacity:.14}}{(t0+1.5)/T*100:.2f}%,100%{{stroke-opacity:.14;fill-opacity:.05}}}}")
        parts.append(f'<rect x="{x}" y="{y0}" width="{bw}" height="{bh}" rx="16" fill="#fff" fill-opacity=".05" stroke="#ffffff" stroke-opacity=".14" stroke-width="1.6" style="{glow}"/>'
                     f'<text x="{x+bw/2}" y="{y0+38}" text-anchor="middle" font-size="18" class="b">{esc(name)}</text>'
                     f'<text x="{x+bw/2}" y="{y0+64}" text-anchor="middle" font-size="12.5" class="m mut">{esc(l1)}</text>'
                     f'<text x="{x+bw/2}" y="{y0+84}" text-anchor="middle" font-size="12" class="m mut">{esc(l2)}</text>'
                     f'<text x="{x+14}" y="{y0-12}" font-size="13" class="m faint">{i+1}</text>')
        if i < n - 1:
            xa = x + bw + 5
            parts.append(f'<line x1="{xa}" y1="{y0+bh/2}" x2="{xa+gap-14}" y2="{y0+bh/2}" stroke="#ffffff" stroke-opacity=".7" stroke-width="2.4" stroke-dasharray="6 6" stroke-linecap="round" style="animation:flow .7s linear infinite"/>'
                         f'<path d="M{xa+gap-20} {y0+bh/2-6} l8 6 l-8 6" stroke="#ffffff" stroke-opacity=".8" stroke-width="2.4" fill="none" stroke-linecap="round" stroke-linejoin="round"/>')
    ends = ["CLI", "Dashboard", "MCP agents", "GitHub Action"]
    pills = "".join(f'<rect x="{34 + k*150}" y="{H-62}" width="136" height="32" rx="16" fill="#fff" fill-opacity=".05" stroke="#fff" stroke-opacity=".16"/>'
                    f'<text x="{34 + k*150 + 68}" y="{H-41}" text-anchor="middle" font-size="14" class="m">{esc(e)}</text>' for k, e in enumerate(ends))
    body = (f'<rect width="{W}" height="{H}" rx="22" fill="url(#bgm)"/><rect width="{W}" height="{H}" rx="22" fill="url(#brush)"/><rect x=".5" y=".5" width="{W-1}" height="{H-1}" rx="22" fill="none" stroke="url(#rim)"/>'
            f'<text x="34" y="46" font-size="22" class="b">One engine, four front doors</text>'
            f'<text x="34" y="70" font-size="14" class="mut">Address policy and proof of control live in the engine, so every front door gets them.</text>'
            + "".join(parts) + pills
            + f'<text x="{34 + 4*150 + 10}" y="{H-41}" font-size="13" class="m faint">← all share the same pipeline</text>')
    return svg(W, H, "FSV pipeline", f"Crawl, {NMOD} modules, aggregate, correlate, triage, report — shared by CLI, dashboard, MCP and the GitHub Action.",
               "", body, "".join(css))


# ═══════════════════════════════════════════════════════════════════════════════
# 5) DETECTION CARDS
# ═══════════════════════════════════════════════════════════════════════════════

def detections() -> str:
    W, T = 1080, 14.0
    cards = [
        ("Dangling DNS", "high", "HIGH", "blog.example.com → old-app.github.io", "✗ NXDOMAIN — anyone can claim the name", "chain"),
        ("Orphaned bucket", "critical", "CRITICAL", '<script src="//assets.s3…/app.js">', "NoSuchBucket → create it, own the page", "bucket"),
        ("Dead SPF include", "high", "HIGH", "v=spf1 include:old-vendor.example ~all", "old-vendor.example → NXDOMAIN", "mail"),
        ("Source map & secrets", "critical", "CRITICAL", "app.js.map  (sourcesContent embedded)", "key sk_l…************l2  (masked)", "map"),
        ("End-of-life software", "medium", "MEDIUM", "PHP/8.1.2 · jQuery 3.3.1 · Vue 2.6", "PHP 8.1 security support ended 2025-12-31", "clock"),
        ("Attack path", "critical", "CRITICAL", "XSS  +  session cookie without HttpOnly", "= account takeover with one click", "link"),
        ("Compromised CDN", "critical", "CRITICAL", '<script src="cdn.polyfill.io/v3/…">', "domain changed hands → served malware", "chip"),
        ("Debug mode in prod", "high", "HIGH", "GET /random-404 → Django DEBUG = True", "33 URL patterns + settings leak", "bug"),
    ]
    cw, ch, gx, gy, x0, y0 = 510, 140, 20, 20, 20, 20
    rows = (len(cards) + 1) // 2
    H = y0 * 2 + rows * ch + (rows - 1) * gy
    css = []
    L = Loop(T, "dc")
    parts, defs = [], ['<linearGradient id="beam" x1="0" x2="1"><stop offset="0" stop-color="#ffffff" stop-opacity="0"/><stop offset=".5" stop-color="#ffffff" stop-opacity=".35"/><stop offset="1" stop-color="#ffffff" stop-opacity="0"/></linearGradient>']
    icons = {
        "chain": lambda x, y, c: f'<path d="M{x-9} {y+4} a7 7 0 0 1 0 -10 l5 -5 a7 7 0 0 1 10 0 M{x+9} {y-4} a7 7 0 0 1 0 10 l-5 5 a7 7 0 0 1 -10 0" stroke="{c}" stroke-width="2.6" fill="none" stroke-linecap="round"/>',
        "bucket": lambda x, y, c: f'<path d="M{x-11} {y-8} h22 l-3 18 h-16 z" stroke="{c}" stroke-width="2.6" fill="none" stroke-linejoin="round"/><ellipse cx="{x}" cy="{y-8}" rx="11" ry="3.5" stroke="{c}" stroke-width="2.6" fill="none"/>',
        "mail": lambda x, y, c: f'<rect x="{x-12}" y="{y-8}" width="24" height="16" rx="3" stroke="{c}" stroke-width="2.6" fill="none"/><path d="M{x-12} {y-7} l12 9 l12 -9" stroke="{c}" stroke-width="2.6" fill="none" stroke-linejoin="round"/>',
        "map": lambda x, y, c: f'<path d="M{x-11} {y-9} l7 3 l8 -3 l7 3 v15 l-7 -3 l-8 3 l-7 -3 z M{x-4} {y-6} v15 M{x+4} {y-9} v15" stroke="{c}" stroke-width="2.4" fill="none" stroke-linejoin="round"/>',
        "clock": lambda x, y, c: f'<circle cx="{x}" cy="{y}" r="11" stroke="{c}" stroke-width="2.6" fill="none"/><path d="M{x} {y-6} v6 l5 3" stroke="{c}" stroke-width="2.6" fill="none" stroke-linecap="round"/>',
        "chip": lambda x, y, c: f'<rect x="{x-9}" y="{y-9}" width="18" height="18" rx="3" stroke="{c}" stroke-width="2.6" fill="none"/><path d="M{x-4} {y-13} v4 M{x+4} {y-13} v4 M{x-4} {y+9} v4 M{x+4} {y+9} v4 M{x-13} {y-4} h4 M{x-13} {y+4} h4 M{x+9} {y-4} h4 M{x+9} {y+4} h4" stroke="{c}" stroke-width="2.2"/>',
        "bug": lambda x, y, c: f'<ellipse cx="{x}" cy="{y+2}" rx="7" ry="10" stroke="{c}" stroke-width="2.6" fill="none"/><path d="M{x-7} {y} h-6 M{x+7} {y} h6 M{x-6} {y+7} l-5 4 M{x+6} {y+7} l5 4 M{x-5} {y-6} l-4 -5 M{x+5} {y-6} l4 -5" stroke="{c}" stroke-width="2.2" stroke-linecap="round"/>',
        "link": lambda x, y, c: f'<circle cx="{x-9}" cy="{y}" r="5" stroke="{c}" stroke-width="2.6" fill="none"/><circle cx="{x+9}" cy="{y}" r="5" stroke="{c}" stroke-width="2.6" fill="none"/><path d="M{x-4} {y} h8" stroke="{c}" stroke-width="2.6"/>',
    }
    for i, (title, sev, label, l1, l2, icon) in enumerate(cards):
        col, r, cc = SEV[sev], i // 2, i % 2
        x, y = x0 + cc * (cw + gx), y0 + r * (ch + gy)
        t0 = 0.3 + i * (T - 1.6) / len(cards)
        badge_w = len(label) * 9 + 26
        beam = L.custom([(0, "opacity:0;transform:translateX(-120px)"), (t0, "opacity:0;transform:translateX(-120px)"),
                         (t0 + .05, "opacity:1;transform:translateX(-120px)"), (t0 + 1.1, f"opacity:1;transform:translateX({cw}px)"),
                         (t0 + 1.15, f"opacity:0;transform:translateX({cw}px)"), (T, f"opacity:0;transform:translateX({cw}px)")], "ease-in-out")
        parts.append(
            f'<g transform="translate({x},{y})">'
            f'<rect width="{cw}" height="{ch}" rx="18" fill="url(#glass)" stroke="url(#rim)"/><path d="M18 .8 H{cw-18}" stroke="#fff" stroke-opacity=".35"/>'
            f'<clipPath id="cl{i}"><rect width="{cw}" height="{ch}" rx="18"/></clipPath>'
            f'<g clip-path="url(#cl{i})"><rect y="0" width="120" height="{ch}" fill="url(#beam)" style="{beam}"/></g>'
            f'<circle cx="46" cy="44" r="24" fill="{col}" fill-opacity=".13" stroke="{col}" stroke-opacity=".5"/>{icons[icon](46, 44, col)}'
            f'<text x="86" y="52" font-size="20" class="b">{esc(title)}</text>'
            f'<text x="24" y="92" font-size="14.5" class="m mut" xml:space="preserve">{esc(l1)}</text>'
            f'<text x="24" y="118" font-size="14.5" class="m" style="fill:{col}">{esc(l2)}</text>'
            f'<g style="{L.custom([(0, "opacity:0;transform:scale(.7)"), (t0 + .5, "opacity:0;transform:scale(.7)"), (t0 + .8, "opacity:1;transform:scale(1.08)"), (t0 + 1.0, "opacity:1;transform:scale(1)"), (T - .7, "opacity:1;transform:scale(1)"), (T - .3, "opacity:0;transform:scale(1)"), (T, "opacity:0;transform:scale(.7)")], "ease-out")};transform-box:fill-box;transform-origin:center">'
            f'<rect x="{cw-badge_w-22}" y="22" width="{badge_w}" height="26" rx="13" fill="{col}" fill-opacity=".16" stroke="{col}"/>'
            f'<text x="{cw-badge_w/2-22}" y="40" text-anchor="middle" font-size="12.5" class="b" letter-spacing="1" style="fill:{col}">{label}</text></g>'
            f'</g>')
    body = f'<rect width="{W}" height="{H}" rx="22" fill="url(#bgm)"/><rect width="{W}" height="{H}" rx="22" fill="url(#brush)"/><rect x=".5" y=".5" width="{W-1}" height="{H-1}" rx="22" fill="none" stroke="url(#rim)"/>' + "".join(parts)
    return svg(W, H, "What FSV finds that checklists miss",
               "Eight detection cards: dangling DNS, orphaned bucket, dead SPF include, source map and secrets, end-of-life software, attack path, compromised CDN, debug mode in production.",
               "".join(defs), body, "".join(css) + L.style())


def main() -> None:
    os.makedirs(ASSETS, exist_ok=True)
    scan = json.load(open(os.path.join(ASSETS, "demo-scan.json"), encoding="utf-8"))
    for name, content in (("logo", logo()), ("hero", hero()), ("terminal", terminal(scan)), ("attack-path", attack_path()),
                          ("pipeline", pipeline()), ("detections", detections())):
        path = os.path.join(ASSETS, f"{name}.svg")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
        if name == "logo":   # the dashboard serves the same mark (favicon + header)
            with open(os.path.join(HERE, "..", "fsv", "web", "static", "logo.svg"), "w", encoding="utf-8") as fh:
                fh.write(content)
        print(f"{name}.svg  {len(content)/1024:.1f} KB")


if __name__ == "__main__":
    main()
