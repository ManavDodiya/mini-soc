#!/usr/bin/env bash
# ─────────────────────────────────────────────────
#  Mini SOC Platform — Quick Start Script
# ─────────────────────────────────────────────────
set -e

echo ""
echo "╔══════════════════════════════════════════════╗"
echo "║      Mini SOC Platform — Setup & Launch      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Check Python
if ! command -v python3 &>/dev/null; then
  echo "❌  Python 3 not found. Install from https://python.org"
  exit 1
fi

echo "✅  Python $(python3 --version)"

# Create virtualenv if missing
if [ ! -d ".venv" ]; then
  echo "📦  Creating virtual environment..."
  python3 -m venv .venv
fi

# Activate
source .venv/bin/activate
echo "🔧  Virtual environment active"

# Install dependencies
echo "📥  Installing dependencies (this takes ~60s first time)..."
pip install -q -r requirements.txt

echo ""
echo "🚀  Starting Mini SOC Platform..."
echo "🌐  Open your browser → http://127.0.0.1:5000"
echo "     Press Ctrl+C to stop."
echo ""

python3 app.py
