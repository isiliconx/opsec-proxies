#!/usr/bin/env bash
# resiproxy — setup, verify, and run. Linux / macOS / Windows(WSL,Git Bash,MSYS).
set -euo pipefail
cd "$(dirname "$0")"

PY="${PY:-python3}"
command -v "$PY" >/dev/null 2>&1 || { echo "need python3 on PATH"; exit 1; }
"$PY" -c 'import sys; assert sys.version_info>=(3,10), "need python 3.10+"'

echo "== install =="
"$PY" -m pip install -r requirements.txt 2>/dev/null || pip3 install -r requirements.txt 2>/dev/null || \
  echo "  (aiohttp already present or pip unavailable — continuing)"

echo "== compile check =="
"$PY" -m compileall -q tooling recon enum vuln exploit egress ui run.py >/dev/null && echo "  all modules compile"

echo "== setup =="
"$PY" run.py setup

echo
echo "== full pipeline (harvest -> enum -> test -> pool.txt) =="
"$PY" run.py pipeline "$@" || true

echo
echo "next:"
echo "  $PY run.py serve --grade B      # rotating SOCKS5 :2080 + HTTP :2081"
echo "  $PY run.py chrome               # route A: Chrome only"
echo "  sudo $PY run.py tunnel --dry-run # route B: whole machine (plan only)"
echo "  sudo $PY run.py tunnel           # route B: whole machine (for real)"
echo "  $PY run.py ui                   # control panel on 127.0.0.1:8770"
