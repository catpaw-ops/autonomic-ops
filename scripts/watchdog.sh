#!/bin/sh
# Optional external watchdog: if the heartbeat is older than the budget, restart
# the unit. The in-process watchdog already handles self-overrun; this covers a
# frozen process or a stuck kernel wait that the internal thread cannot report.
set -eu
PREFIX="${AUTONOMIC_PREFIX:-/opt/autonomic-ops}"
HEARTBEAT="$PREFIX/run/heartbeat.json"
MAX_AGE="${AUTONOMIC_HEARTBEAT_MAX_AGE:-90}"
while true; do
  sleep 20
  if [ ! -f "$HEARTBEAT" ]; then continue; fi
  NOW=$(date +%s)
  MTIME=$(stat -c %Y "$HEARTBEAT" 2>/dev/null || echo "$NOW")
  AGE=$((NOW - MTIME))
  if [ "$AGE" -gt "$MAX_AGE" ]; then
    logger -t autonomic-watchdog "heartbeat stale (${AGE}s), restarting autonomic-ops"
    systemctl restart autonomic-ops || true
  fi
done
