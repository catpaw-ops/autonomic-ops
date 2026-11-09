#!/usr/bin/env bash
# =============================================================================
# AutonomicOps installer
#
#   bash scripts/install.sh --prefix /opt/autonomic-ops
#   bash scripts/install.sh --prefix /opt/autonomic-ops --non-interactive
#   bash scripts/install.sh --prefix /tmp/fake --non-interactive --no-service --simulate
#
# Contract (relied on by the remote bootstrap):
#   produces <prefix>/lib/autonomic/main.py
#            <prefix>/bin/autonomic-ops
#            <prefix>/config/rules/default_rules.yaml
# =============================================================================
set -euo pipefail

PREFIX="/opt/autonomic-ops"
CONFIG_SRC=""
NON_INTERACTIVE=0
NO_SERVICE=0
SIMULATE=0
FORCE=0
BOOTSTRAP_TOKEN=""
PYTHON_BIN="${AUTONOMIC_PYTHON:-python3}"

usage() {
  cat <<'USAGE'
Options:
  --prefix DIR          install root (default /opt/autonomic-ops)
  --config FILE         config template to install as <prefix>/config/config.yaml
  --non-interactive     never prompt (required for remote bootstrap)
  --no-service          do not install/start the systemd unit
  --simulate            local fake-root install (implies --no-service)
  --bootstrap-token T   write the one-time authorization token into the config
  --force               overwrite an existing config.yaml
  -h, --help            this text
USAGE
}

while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2 ;;
    --config) CONFIG_SRC="$2"; shift 2 ;;
    --non-interactive) NON_INTERACTIVE=1; shift ;;
    --no-service) NO_SERVICE=1; shift ;;
    --simulate) SIMULATE=1; NO_SERVICE=1; shift ;;
    --bootstrap-token) BOOTSTRAP_TOKEN="$2"; shift 2 ;;
    --force) FORCE=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

# The prefix is interpolated into sed expressions and shell wrappers below.
# Reject characters that would break those expressions before creating anything.
case "$PREFIX" in
  *[[:space:]]*|*"#"*|*"&"*)
    echo "installer: --prefix must not contain whitespace, '#' or '&'" >&2
    exit 2 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PREFIX="$(mkdir -p "$PREFIX" && cd "$PREFIX" && pwd)"

if [ ! -d "$ROOT/src/autonomic" ]; then
  echo "installer: source tree not found at $ROOT/src/autonomic" >&2
  exit 1
fi

if ! "$PYTHON_BIN" -c 'import sys; sys.exit(0 if sys.version_info >= (3,9) else 1)'; then
  echo "installer: Python 3.9+ required (found $("$PYTHON_BIN" -V 2>&1))" >&2
  exit 1
fi

say() { printf '[install] %s\n' "$*"; }

copy_file() {
  src="$1"; dst="$2"
  if [ -e "$dst" ] && [ "$src" -ef "$dst" ]; then return 0; fi
  cp -f "$src" "$dst"
}

say "prefix=$PREFIX simulate=$SIMULATE"

# ---------------------------------------------------------------- directories
mkdir -p "$PREFIX"/{lib/autonomic,bin,config/rules,plugins/builtin,plugins/examples,data,logs,run,scripts,systemd,docs}
chmod 750 "$PREFIX"/{data,logs,run} 2>/dev/null || true

# ------------------------------------------------------------------- payload
for f in "$ROOT"/src/autonomic/*.py; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/lib/autonomic/$(basename "$f")"; done
say "library  -> $PREFIX/lib/autonomic ($(find "$PREFIX/lib/autonomic" -maxdepth 1 -name '*.py' | wc -l | tr -d ' ') modules)"

if [ -d "$ROOT/plugins/builtin" ]; then
  for f in "$ROOT"/plugins/builtin/*.py; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/plugins/builtin/$(basename "$f")"; done
fi
if [ -d "$ROOT/plugins/examples" ]; then
  for f in "$ROOT"/plugins/examples/*.py; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/plugins/examples/$(basename "$f")"; done
fi
if [ -d "$ROOT/config/rules" ]; then
  for f in "$ROOT"/config/rules/*.yaml; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/config/rules/$(basename "$f")"; done
fi
if [ -d "$ROOT/systemd" ]; then
  for f in "$ROOT"/systemd/*; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/systemd/$(basename "$f")"; done
fi
for f in build_manifest.py selftest.sh watchdog.sh install.sh uninstall.sh; do
  if [ -f "$ROOT/scripts/$f" ]; then copy_file "$ROOT/scripts/$f" "$PREFIX/scripts/$f"; fi
done
chmod +x "$PREFIX"/scripts/*.sh 2>/dev/null || true
if [ -f "$ROOT/README.md" ]; then copy_file "$ROOT/README.md" "$PREFIX/README.md"; fi
if [ -f "$ROOT/LICENSE" ]; then copy_file "$ROOT/LICENSE" "$PREFIX/LICENSE"; fi
if [ -f "$ROOT/DISCLAIMER.md" ]; then copy_file "$ROOT/DISCLAIMER.md" "$PREFIX/DISCLAIMER.md"; fi
if [ -d "$ROOT/docs" ]; then for f in "$ROOT"/docs/*.md; do [ -f "$f" ] || continue; copy_file "$f" "$PREFIX/docs/$(basename "$f")"; done; fi

# -------------------------------------------------------------------- config
TARGET_CONFIG="$PREFIX/config/config.yaml"
if [ -f "$TARGET_CONFIG" ] && [ "$FORCE" -eq 0 ]; then
  say "config exists, keeping it (use --force to replace): $TARGET_CONFIG"
else
  if [ -n "$CONFIG_SRC" ] && [ -f "$CONFIG_SRC" ]; then
    cp -f "$CONFIG_SRC" "$TARGET_CONFIG"
  else
    cp -f "$ROOT/config/config.example.yaml" "$TARGET_CONFIG"
  fi
  # Re-home every default path when installing to a non-default prefix:
  # plugins.dirs and bootstrap.install_root live in this template too, and
  # leaving them at /opt would silently break plugins and remote deployment.
  if [ "$PREFIX" != "/opt/autonomic-ops" ]; then
    sed -i "s#/opt/autonomic-ops#$PREFIX#g" "$TARGET_CONFIG"
    sed -i "s#^  prefix:.*#  prefix: $PREFIX#" "$TARGET_CONFIG"
    sed -i "s#^  data_dir:.*#  data_dir: $PREFIX/data#" "$TARGET_CONFIG"
    sed -i "s#^  log_dir:.*#  log_dir: $PREFIX/logs#" "$TARGET_CONFIG"
    sed -i "s#^  run_dir:.*#  run_dir: $PREFIX/run#" "$TARGET_CONFIG"
  fi
  say "config   -> $TARGET_CONFIG"
fi
chmod 600 "$TARGET_CONFIG" 2>/dev/null || true

if [ -n "$BOOTSTRAP_TOKEN" ]; then
  # token is hex/base64-ish; escape the delimiter only
  ESCAPED_TOKEN=$(printf '%s' "$BOOTSTRAP_TOKEN" | sed 's/[&#]/\\&/g')
  sed -i "s#^  authorization_token:.*#  authorization_token: \"$ESCAPED_TOKEN\"#" "$TARGET_CONFIG" || true
  say "bootstrap token written (one-time authorization)"
fi
if [ -f "$ROOT/config/config.example.yaml" ]; then
  copy_file "$ROOT/config/config.example.yaml" "$PREFIX/config/config.example.yaml"
fi

# -------------------------------------------------------------------- wrappers
cat > "$PREFIX/bin/autonomic-ops" <<EOF
#!/bin/sh
# AutonomicOps control CLI (read-only by design except explicit approve/rollback)
PREFIX="$PREFIX"
export PYTHONPATH="\$PREFIX/lib\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\${AUTONOMIC_PYTHON:-$PYTHON_BIN}" -m autonomic.cli --config "\${AUTONOMIC_CONFIG:-$TARGET_CONFIG}" "\$@"
EOF
chmod 755 "$PREFIX/bin/autonomic-ops"

cat > "$PREFIX/bin/autonomic-ops-daemon" <<EOF
#!/bin/sh
# Long-lived supervisor. Never attach this to an interactive terminal; it is
# started by systemd (or the pidfile supervisor) and logs to files only.
PREFIX="$PREFIX"
export PYTHONPATH="\$PREFIX/lib\${PYTHONPATH:+:\$PYTHONPATH}"
exec "\${AUTONOMIC_PYTHON:-$PYTHON_BIN}" -m autonomic.main --config "\${AUTONOMIC_CONFIG:-$TARGET_CONFIG}" "\$@"
EOF
chmod 755 "$PREFIX/bin/autonomic-ops-daemon"
say "binaries -> $PREFIX/bin/{autonomic-ops,autonomic-ops-daemon}"

# ------------------------------------------------------------ core integrity
PYTHONPATH="$PREFIX/lib" "$PYTHON_BIN" "$PREFIX/scripts/build_manifest.py" -c "$TARGET_CONFIG" \
  || say "warning: core manifest build failed; run scripts/build_manifest.py later"

# ------------------------------------------------------------------- service
if [ "$NO_SERVICE" -eq 1 ]; then
  say "service installation skipped (--no-service)"
else
  UNIT_SRC="$PREFIX/systemd/autonomic-ops.service"
  UNIT_DST="/etc/systemd/system/autonomic-ops.service"
  if [ ! -f "$UNIT_SRC" ]; then
    say "warning: systemd unit template missing"
  elif [ -d /run/systemd/system ] && [ -w /etc/systemd/system ]; then
    sed "s#/opt/autonomic-ops#$PREFIX#g" "$UNIT_SRC" > "$UNIT_DST"
    systemctl daemon-reload
    systemctl enable autonomic-ops.service >/dev/null 2>&1 || true
    if [ "$NON_INTERACTIVE" -eq 1 ]; then
      systemctl restart autonomic-ops.service
    else
      systemctl restart autonomic-ops.service || true
    fi
    say "systemd unit installed and started: autonomic-ops.service"
    # Optional external watchdog unit: install the unit file so it can be
    # enabled on demand, but do NOT enable it by default (second-layer supervisor).
    WATCHDOG_SRC="$PREFIX/systemd/autonomic-ops-watchdog.service"
    if [ -f "$WATCHDOG_SRC" ]; then
      sed "s#/opt/autonomic-ops#$PREFIX#g" "$WATCHDOG_SRC" > "/etc/systemd/system/autonomic-ops-watchdog.service"
      systemctl daemon-reload
      say "watchdog unit installed (enable with: systemctl enable --now autonomic-ops-watchdog.service)"
    fi
  else
    say "systemd unavailable; starting pidfile supervisor"
    "$PREFIX/bin/autonomic-ops" service start || true
  fi
fi

# -------------------------------------------------------------------- verify
if [ -x "$PREFIX/bin/autonomic-ops" ]; then
  if "$PREFIX/bin/autonomic-ops" --version >/dev/null 2>&1; then
    say "CLI verified: $("$PREFIX/bin/autonomic-ops" --version)"
  else
    say "warning: CLI did not run; check python path"
  fi
fi
say "done. status: $PREFIX/bin/autonomic-ops status"
say "logs:   $PREFIX/logs/runtime.log  |  audit: $PREFIX/logs/audit.log"
