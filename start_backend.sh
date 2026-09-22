#!/usr/bin/env bash
# Run from the PLEXUS root directory.
#
# v3.0.0: the backend NEVER runs as root anymore. Raw packet capture needs
# CAP_NET_RAW, which is granted once (not per-run) via:
#     sudo setcap cap_net_raw+ep .venv/bin/python3
# On macOS (no setcap), live capture still needs root — run this script
# with sudo only on macOS, and only if you need live capture.
set -e

# Always resolve to the project root regardless of where the script is called from
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

if [ ! -d ".venv" ]; then
  echo "Creating virtual environment…"
  python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -r backend/requirements.txt

echo ""
echo "Starting PLEXUS backend on http://127.0.0.1:8000"
echo "API docs: http://127.0.0.1:8000/api/docs"
echo ""

PYTHON_BIN="$ROOT/.venv/bin/python3"

if [ "$(id -u)" -eq 0 ]; then
  echo "WARNING: running as root is unnecessary and unsafe."
  echo "         Drop to a normal user and use instead:"
  echo "             sudo setcap cap_net_raw+ep \"$PYTHON_BIN\"   (one-time)"
  echo ""
elif command -v getcap >/dev/null 2>&1; then
  # Linux: offer the one-time capability grant for raw sockets.
  if ! getcap "$PYTHON_BIN" 2>/dev/null | grep -q cap_net_raw; then
    echo "Note: live packet capture needs the CAP_NET_RAW capability."
    echo "One-time setup (then root is never needed again):"
    echo "    sudo setcap cap_net_raw+ep \"$PYTHON_BIN\""
    echo ""
    echo "Without it, the API, PCAP analysis and dashboard still work —"
    echo "only live interface capture will fail to start."
    echo ""
  fi
fi

# uvicorn must be launched from the project root so that
# 'backend' is a resolvable top-level package.
exec "$ROOT/.venv/bin/uvicorn" backend.main:app --host 127.0.0.1 --port 8000
