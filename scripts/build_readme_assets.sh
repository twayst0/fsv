#!/usr/bin/env bash
# Rebuilds everything under docs/assets/:
#   animated SVGs  — python scripts/make_readme_assets.py            (always)
#   screenshots    — needs Playwright + ImageMagick + a demo scan     (pass --screenshots)
#
#   scripts/build_readme_assets.sh                 # SVGs only
#   scripts/build_readme_assets.sh --screenshots   # + dashboard.webp / findings.webp from a live demo run
set -euo pipefail
cd "$(dirname "$0")/.."
python scripts/make_readme_assets.py

if [[ "${1:-}" == "--screenshots" ]]; then
  tmp="$(mktemp -d)"; trap 'kill $(jobs -p) 2>/dev/null || true; rm -rf "$tmp"' EXIT
  export FSV_DB="$tmp/readme.db"
  python examples/demo_site.py >/dev/null & sleep 1.5
  fsv scan http://127.0.0.1:8961 --authorize --quiet --rate 100 >/dev/null || true
  FSV_PORT=7795 fsv-web >/dev/null 2>&1 & sleep 3
  OUT="$tmp" node scripts/screenshots.cjs
  for f in dashboard findings; do
    convert "$tmp/$f.png" -strip -quality 90 -define webp:method=6 "docs/assets/$f.webp"
  done
  ls -la docs/assets/*.webp
fi
