#!/usr/bin/env bash
# FSV installer
set -e

echo "┌──────────────────────────────────────┐"
echo "│  FSV — Web Vulnerability Scanner       │"
echo "│  authorized testing only               │"
echo "└──────────────────────────────────────┘"
echo

if ! command -v python3 >/dev/null 2>&1; then
  echo "✗ Python 3.10+ is required."
  exit 1
fi

PYV=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
echo "• Python $PYV detected"

echo "• Creating virtual environment (.venv)…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate

echo "• Upgrading pip…"
pip install --upgrade pip >/dev/null

echo "• Installing FSV + dependencies…"
pip install -e .

echo
echo "✓ Installed. Activate with:  source .venv/bin/activate"
echo
echo "Quick start:"
echo "  fsv web                                  # dashboard at http://127.0.0.1:7474"
echo "  fsv scan example.com --authorize         # CLI scan"
echo "  fsv mcp                                  # run MCP server (stdio)"
echo
