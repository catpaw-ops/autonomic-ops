#!/usr/bin/env bash
# Remove AutonomicOps. Data/logs are kept unless --purge is given.
set -euo pipefail
PREFIX="/opt/autonomic-ops"
PURGE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --purge) PURGE=1; shift ;;
    -h|--help) echo "usage: uninstall.sh [--prefix DIR] [--purge]"; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done
if [ -d /run/systemd/system ] && systemctl list-unit-files autonomic-ops.service >/dev/null 2>&1; then
  systemctl disable --now autonomic-ops.service 2>/dev/null || true
  rm -f /etc/systemd/system/autonomic-ops.service
  systemctl daemon-reload || true
fi
if [ -x "$PREFIX/bin/autonomic-ops" ]; then
  "$PREFIX/bin/autonomic-ops" service stop 2>/dev/null || true
fi
if [ "$PURGE" -eq 1 ]; then
  rm -rf "$PREFIX"
  echo "removed $PREFIX (data and logs purged)"
else
  rm -rf "$PREFIX/lib" "$PREFIX/bin" "$PREFIX/config" "$PREFIX/plugins" "$PREFIX/scripts" "$PREFIX/systemd"
  echo "removed program files; kept $PREFIX/data and $PREFIX/logs"
fi
