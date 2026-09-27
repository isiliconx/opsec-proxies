#!/usr/bin/env bash
# Second, isolated Chrome through the resiproxy rotating listener.
# The existing desktop Chrome window is NOT touched: different --user-data-dir,
# so different process tree, different session, nothing to restore.
set -euo pipefail
cd "$(dirname "$0")/.."

PROXY_HOST="${RESI_HOST:-127.0.0.1}"
PROXY_PORT="${RESI_PORT:-2081}"
PROFILE="${RESI_PROFILE:-$PWD/data/chrome-pool-profile}"
URLS=("$@")
[ ${#URLS[@]} -eq 0 ] && URLS=(
  "https://ipinfo.io"
  "https://whatismyipaddress.com"
  "https://browserleaks.com/ip"
)

mkdir -p "$PROFILE"

echo "[resi] chrome -> http://${PROXY_HOST}:${PROXY_PORT}   profile=${PROFILE}"
echo "[resi] urls: ${URLS[*]}"

exec google-chrome \
  --user-data-dir="$PROFILE" \
  --proxy-server="http://${PROXY_HOST}:${PROXY_PORT}" \
  --no-first-run \
  --no-default-browser-check \
  --password-store=basic \
  --dns-prefetch-disable \
  --disable-background-networking \
  --disable-component-update \
  --disable-sync \
  --disable-features=Translate \
  --window-size=1280,900 \
  --window-position=140,90 \
  --new-window \
  "${URLS[@]}"
