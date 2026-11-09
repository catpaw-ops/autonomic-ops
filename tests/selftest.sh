#!/usr/bin/env bash
# =============================================================================
# AutonomicOps end-to-end self-test.
#
# It boots a real daemon against config/config.selftest.yaml (all paths under
# /tmp/autonomic-selftest), drives it only through the public CLI, and asserts
# the behaviours the product promises:
#
#   1  background launch / pidfile / control socket
#   2  log channel separation
#   3  task submission
#   4  queueing when the pool is full
#   5  preemption + cancellation + requeue
#   6  SSH brute-force detection -> auto ban (degraded recorder backend)
#   7  disk cleanup with snapshot -> byte-exact rollback
#   8  codegen preview/apply + forbidden path denial
#   9  plugin hot load without restart
#  10  audit hash chain verification
#  11  IPC token authentication
#  12  remote bootstrap simulate
#  13  installer layout contract
#  14  clean shutdown
#
# Exit code 0 only if every assertion passes.
# =============================================================================
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CONFIG="$ROOT/config/config.selftest.yaml"
BASE="/tmp/autonomic-selftest"
PY="${AUTONOMIC_PYTHON:-python3}"
export PYTHONPATH="$ROOT/src${PYTHONPATH:+:$PYTHONPATH}"

# Safety guard: rm -rf below must only ever touch our dedicated temp root.
case "$BASE" in
  /tmp/autonomic-selftest) ;;
  *) echo "refusing to run with unexpected BASE=$BASE" >&2; exit 2 ;;
esac

PASS=0
FAIL=0
declare -a FAILURES=()
DAEMON_PID=""

green() { printf '\033[32m%s\033[0m\n' "$*"; }
red()   { printf '\033[31m%s\033[0m\n' "$*"; }
ok()    { PASS=$((PASS+1)); green "[PASS] $1"; }
bad()   { FAIL=$((FAIL+1)); FAILURES+=("$1: $2"); red "[FAIL] $1 -- $2"; }

check() { local name="$1" detail="${2:-}"; shift 2; if "$@" >/dev/null 2>&1; then ok "$name"; else bad "$name" "$detail"; fi; }
expect() { local name="$1" expected="$2" actual="$3"; if [ "$expected" = "$actual" ]; then ok "$name"; else bad "$name" "expected=$expected actual=$actual"; fi; }

cli() { "$PY" -m autonomic.cli -c "$CONFIG" "$@"; }

cleanup() {
  if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
    cli stop >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.3; done
    kill -9 "$DAEMON_PID" 2>/dev/null || true
  fi
  pkill -f "http.server 65001" 2>/dev/null || true
}
trap cleanup EXIT

echo "=================================================================="
echo " AutonomicOps self-test"
echo " root:   $ROOT"
echo " config: $CONFIG"
echo " python: $($PY -V 2>&1)"
echo " date:   $(date -Is)"
echo "=================================================================="

# --------------------------------------------------------------- prerequisites
for tool in "$PY" jq curl tar; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "missing required tool: $tool" >&2
    exit 2
  fi
done

# The self-test config deliberately references only paths under BASE. Mirror the
# repository's builtin plugins and default rules there so the test is portable
# and never depends on where the repository was cloned.
SELFTEST_TOKEN="$("$PY" -c 'import secrets; print(secrets.token_hex(16))')"
export AUTONOMIC_SELFTEST_TOKEN="$SELFTEST_TOKEN"

# The self-test watches one healthy process to exercise the detector's
# "alive" branch. Its name is host-specific: PID 1 is dumb-init in some
# containers, systemd on bare metal, something else elsewhere. Inject the
# real comm so a mismatch cannot be misreported as process.absent and spawn
# an automatic restart that races the preemption assertions below.
PID1_COMM="$(ps -p 1 -o comm= 2>/dev/null | tr -d '[:space:]')"
export AUTONOMIC_SELFTEST_PROC_MATCH="${PID1_COMM:-dumb-init}"
echo "watched healthy process: ${AUTONOMIC_SELFTEST_PROC_MATCH} (PID 1 comm)"

pkill -f "http.server 65001" 2>/dev/null || true
rm -rf "$BASE"
mkdir -p "$BASE"/{plugins/builtin,plugins/user,rules,cleanup,codegen}
cp -R "$ROOT"/plugins/builtin/. "$BASE/plugins/builtin/"
cp -R "$ROOT"/config/rules/. "$BASE/rules/"
: > "$BASE/auth.log"
printf 'OLD-DATA\n' > "$BASE/cleanup/old1.log"
touch -d '3 hours ago' "$BASE/cleanup/old1.log"
printf 'NEW-DATA\n' > "$BASE/cleanup/new.log"
for i in $(seq 1 12); do echo "2026-11-04T12:00:00 ERROR selftest synthetic error $i" >> "$BASE/app.log"; done

echo
echo "--- build core manifest ---"
if ! "$PY" "$ROOT/scripts/build_manifest.py" -c "$CONFIG"; then
  bad "manifest" "build_manifest.py failed"
fi

# ---------------------------------------------------------------- 1. launch
echo
echo "--- [1] background launch ---"
"$PY" -m autonomic.main -c "$CONFIG" --foreground >"$BASE/daemon-stdout.log" 2>&1 &
DAEMON_PID=$!
for _ in $(seq 1 60); do [ -S "$BASE/run/agent.sock" ] && break; sleep 0.5; done
check "control socket exists" "no socket after 30s" test -S "$BASE/run/agent.sock"
check "pidfile exists" "no pidfile" test -f "$BASE/run/agent.pid"
check "daemon process alive" "pid $DAEMON_PID not alive" kill -0 "$DAEMON_PID"
STATUS_JSON="$(cli --json status)"
expect "daemon reports running" "running" "$(echo "$STATUS_JSON" | jq -r .state)"
expect "worker pool size = 2" "2" "$(echo "$STATUS_JSON" | jq -r '.queue.workers.size')"

# ------------------------------------------------------------------ 2. logs
echo
echo "--- [2] log channels ---"
check "runtime.log written" "empty" test -s "$BASE/logs/runtime.log"
check "audit.log written" "empty" test -s "$BASE/logs/audit.log"
check "error.log exists" "missing" test -f "$BASE/logs/error.log"
check "task/decision/security channels exist" "missing" test -f "$BASE/logs/decision.log"
check "no terminal output captured" "daemon printed to stdout" test ! -s "$BASE/daemon-stdout.log"

# --------------------------------------------------------------- 3. submit
echo
echo "--- [3] task submission ---"
SUB_JSON="$(cli submit --kind shell --command "cat /proc/loadavg" --priority 40 --title selftest-loadavg)"
SUB_ID="$(echo "$SUB_JSON" | jq -r .task.id)"
expect "submit accepted" "queue" "$(echo "$SUB_JSON" | jq -r .decision.kind)"
for _ in $(seq 1 40); do [ "$(cli task "$SUB_ID" | jq -r .task.state)" = "succeeded" ] && break; sleep 0.5; done
expect "shell task succeeded" "succeeded" "$(cli task "$SUB_ID" | jq -r .task.state)"

# ---------------------------------------------------------- 4. queueing
echo
echo "--- [4] queueing under load ---"
cli workers 1 >/dev/null
SLOW_JSON="$(cli submit --kind shell --command "sleep 10" --priority 20 --title selftest-slow)"
SLOW_ID="$(echo "$SLOW_JSON" | jq -r .task.id)"
for _ in $(seq 1 20); do [ "$(cli task "$SLOW_ID" | jq -r .task.state)" = "running" ] && break; sleep 0.3; done
Q_JSON="$(cli submit --kind shell --command "date" --priority 30 --title selftest-queued)"
expect "second task queued while worker busy" "queue" "$(echo "$Q_JSON" | jq -r .decision.kind)"
expect "queue position reported" "1" "$(echo "$Q_JSON" | jq -r .decision.queue_position)"

# ---------------------------------------------------------- 5. preemption
echo
echo "--- [5] preemption / cancellation / requeue ---"
# Make the race explicit: the urgent request must find the slow task still
# running. If an automatic action already claimed the worker, say so instead
# of failing later with an opaque "expected=preempt actual=queue".
for _ in $(seq 1 30); do
  [ "$(cli task "$SLOW_ID" | jq -r .task.state)" = "running" ] && break
  sleep 0.2
done
SLOW_BEFORE="$(cli task "$SLOW_ID" | jq -r .task.state)"
echo "slow task state before urgent chat: $SLOW_BEFORE"
PRE_JSON="$(cli --json chat "紧急：诊断当前负载")"
expect "emergency chat preempts" "preempt" "$(echo "$PRE_JSON" | jq -r .decision.kind)"
expect "preemption victim is the slow task" "$SLOW_ID" "$(echo "$PRE_JSON" | jq -r '.decision.compared_with // empty')"
for _ in $(seq 1 40); do grep -q "requeue preempted task=$SLOW_ID" "$BASE/logs/runtime.log" && break; sleep 0.5; done
check "victim cancelled and requeued" "no requeue log line" grep -q "requeue preempted task=$SLOW_ID" "$BASE/logs/runtime.log"
for _ in $(seq 1 40); do [ "$(cli task "$SLOW_ID" | jq -r .task.state)" = "succeeded" ] && break; sleep 0.5; done
expect "preempted task eventually re-ran" "succeeded" "$(cli task "$SLOW_ID" | jq -r .task.state)"
cli workers 2 >/dev/null

# ------------------------------------------------------- 6. SSH detection
echo
echo "--- [6] SSH brute-force detection -> ban ---"
for i in $(seq 1 6); do
  echo "Nov  4 16:00:00 selftest sshd[999]: Failed password for invalid user admin from 45.77.12.34 port 22 ssh2" >> "$BASE/auth.log"
done
for _ in $(seq 1 24); do [ "$(cli bans | jq -r '.bans | length')" -gt 0 ] && break; sleep 1; done
BAN_JSON="$(cli bans)"
expect "ban recorded for source IP" "45.77.12.34" "$(echo "$BAN_JSON" | jq -r '.bans[0].ip // empty')"
expect "degraded backend marked simulated" "true" "$(echo "$BAN_JSON" | jq -r '.bans[0].simulated')"
expect "backend is recorder (no privilege)" "recorder" "$(echo "$BAN_JSON" | jq -r .backend)"
check "firewall intent trail written" "missing" test -s "$BASE/data/security/firewall-intents.jsonl"

# ------------------------------------------------------- 7. cleanup + rollback
echo
echo "--- [7] disk cleanup -> snapshot -> rollback ---"
cli chat "清理磁盘" >/dev/null
for _ in $(seq 1 30); do [ "$(cli snapshots --limit 5 | jq -r '.snapshots | length')" -gt 0 ] && break; sleep 0.5; done
SNAP_ID="$(cli snapshots --limit 5 | jq -r '.snapshots[0].id // empty')"
check "snapshot created by cleanup" "no snapshot" test -n "$SNAP_ID"
check "old file removed" "old file still present" test ! -f "$BASE/cleanup/old1.log"
check "fresh file preserved" "fresh file was deleted" test -f "$BASE/cleanup/new.log"
cli rollback "$SNAP_ID" >/dev/null
check "rollback restored file" "file missing after rollback" test -f "$BASE/cleanup/old1.log"
expect "rollback content byte-exact" "OLD-DATA" "$(cat "$BASE/cleanup/old1.log")"

# ------------------------------------------------------------- 8. codegen
echo
echo "--- [8] code generation / validation / policy ---"
CODEGEN_JSON="$(cli codegen apply --target "$BASE/codegen/demo.service" --purpose systemd_unit \
  --requirements "30s heartbeat demo" --approved)"
expect "codegen applied" "applied" "$(echo "$CODEGEN_JSON" | jq -r .status)"
check "generated file exists" "missing" test -s "$BASE/codegen/demo.service"
check "codegen created rollback point" "none" test -n "$(echo "$CODEGEN_JSON" | jq -r '.rollback_point // empty')"
BAD_JSON="$(cli codegen apply --target /etc/passwd --purpose config_fragment --requirements x --approved 2>/dev/null || true)"
expect "forbidden path rejected" "rejected" "$(echo "$BAD_JSON" | jq -r .status)"
check "forbidden path untouched" "should not exist" test ! -f "$BASE/etc/passwd"

# ------------------------------------------------------------- 9. plugins
echo
echo "--- [9] plugin hot load ---"
cp "$ROOT/plugins/examples/hello_watch.py" "$BASE/plugins/user/"
for _ in $(seq 1 20); do cli plugins list | jq -e '.plugins[] | select(.name=="hello_watch")' >/dev/null 2>&1 && break; sleep 0.5; done
PLUGINS_JSON="$(cli plugins list)"
check "hello_watch loaded without restart" "not loaded" bash -c "printf '%s' '$PLUGINS_JSON' | jq -e '.plugins[] | select(.name==\"hello_watch\")'"
expect "plugin registered its runtime rule" "16" "$(cli rules list | jq -r '.stats.count')"
for _ in $(seq 1 20); do grep -q "hello.marker" "$BASE/data/notifications.jsonl" 2>/dev/null && break; sleep 0.5; done
check "plugin detector fired through the rule engine" "no notification" grep -q "hello.marker" "$BASE/data/notifications.jsonl"

# --------------------------------------------------------------- 10. audit
echo
echo "--- [10] audit chain ---"
AUDIT_JSON="$(cli audit verify)"
expect "audit hash chain valid" "true" "$(echo "$AUDIT_JSON" | jq -r .ok)"
CHECKED="$(echo "$AUDIT_JSON" | jq -r .checked)"
check "audit records checked > 10" "too few records" test "$CHECKED" -gt 10
BAN_AUDIT="$(cli audit query --action-filter firewall.ban_ip)"
check "ban is audited with actor=auto" "missing" bash -c "printf '%s' '$BAN_AUDIT' | jq -e '.records[] | select(.actor==\"auto\")'"

# ---------------------------------------------------------------- 11. IPC
echo
echo "--- [11] IPC authentication ---"
IPC_RESULT="$("$PY" - "$BASE/run/agent.sock" <<'PY'
import json, socket, sys
path = sys.argv[1]
s = socket.socket(socket.AF_UNIX); s.settimeout(3); s.connect(path)
s.sendall((json.dumps({"cmd": "status", "token": ""}) + "\n").encode())
print(s.makefile().readline().strip())
PY
)"
expect "missing token rejected" "ipc.unauthorized" "$(echo "$IPC_RESULT" | jq -r .error.code)"

# ------------------------------------------------------------- 12. deploy
echo
echo "--- [12] remote bootstrap (simulate) ---"
DEPLOY_JSON="$(cli deploy --host 127.0.0.1 --token "$SELFTEST_TOKEN" --simulate)"
expect "simulated deployment ok" "true" "$(echo "$DEPLOY_JSON" | jq -r .ok)"
check "simulated install layout verified" "missing files" bash -c "test -x '$BASE/simulated/opt/autonomic-ops/bin/autonomic-ops'"
check "simulated rules installed" "missing" test -f "$BASE/simulated/opt/autonomic-ops/config/rules/default_rules.yaml"

# ------------------------------------------------------------ 13. installer
echo
echo "--- [13] installer contract ---"
INSTALL_LOG="$(bash "$ROOT/scripts/install.sh" --prefix "$BASE/install-prefix" --non-interactive --no-service --simulate 2>&1)"
expect "installer exit ok" "0" "$?"
check "installer produced main.py" "missing" test -f "$BASE/install-prefix/lib/autonomic/main.py"
check "installer produced CLI" "missing" test -x "$BASE/install-prefix/bin/autonomic-ops"
check "installer produced default rules" "missing" test -f "$BASE/install-prefix/config/rules/default_rules.yaml"
check "installed CLI runs" "version failed" "$BASE/install-prefix/bin/autonomic-ops" --version
printf '%s\n' "$INSTALL_LOG" | grep -q "done." || bad "installer summary" "missing done line"

# ------------------------------------------------------------- 14. shutdown
echo
echo "--- [14] clean shutdown ---"
cli stop >/dev/null
for _ in $(seq 1 40); do kill -0 "$DAEMON_PID" 2>/dev/null || break; sleep 0.3; done
check "daemon exited" "still alive" bash -c "! kill -0 $DAEMON_PID 2>/dev/null"
check "pidfile removed" "pidfile left behind" test ! -f "$BASE/run/agent.pid"
check "shutdown audited" "missing" grep -q "daemon.stop" "$BASE/logs/audit.log"
DAEMON_PID=""

# ------------------------------------------------------------------ summary
echo
echo "=================================================================="
echo " RESULT: PASS=$PASS FAIL=$FAIL"
if [ "$FAIL" -gt 0 ]; then
  for f in "${FAILURES[@]}"; do red "  - $f"; done
  echo "=================================================================="
  exit 1
fi
green " ALL CHECKS PASSED"
echo " artifacts: $BASE  (logs: $BASE/logs, snapshots: $BASE/backups)"
echo "=================================================================="
exit 0
