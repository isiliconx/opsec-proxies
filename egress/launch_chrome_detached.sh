#!/usr/bin/env bash
# Start Chrome windows fully detached from the calling shell.
#
# Why: launch_chrome.sh used `exec`, so the chrome process WAS the shell's
# child. When the parent session's terminal went away, chrome took the pooled
# window with it — and took the environment-launched Storo window too, since
# both were in the same session group. This version uses setsid to put each
# chrome in its own session, so nothing that happens to the caller can signal
# it, and it exits immediately instead of holding the shell open.
#
#   launch_chrome_detached.sh <profile-dir> <proxy-or-empty> [url ...]
set -u

PROFILE="${1:?profile dir}"
PROXY="${2:-}"
shift 2 || true
URLS=("$@")

COMMON=(
  --no-first-run
  --no-default-browser-check
  --password-store=basic
  --disable-component-update
  --disable-background-networking
  --disable-sync
  --dns-prefetch-disable
  --disable-features=Translate
)

if [ -n "$PROXY" ]; then
  COMMON+=(--proxy-server="$PROXY")
  echo "[resi] proxy -> $PROXY"
fi
echo "[resi] profile -> $PROFILE"

mkdir -p "$PROFILE"
[ ${#URLS[@]} -eq 0 ] && URLS=(about:blank)

setsid google-chrome \
  --user-data-dir="$PROFILE" \
  "${COMMON[@]}" \
  --window-size=1280,900 \
  --window-position=60,60 \
  --new-window \
  "${URLS[@]}" \
  </dev/null >/dev/null 2>&1 &

disown 2>/dev/null || true
echo "[resi] launched detached"
exit 0
