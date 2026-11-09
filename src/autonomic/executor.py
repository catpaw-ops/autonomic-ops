"""Action execution + coordinator.

Flow for every automatic remediation:

    detect -> rule -> action.request -> policy.decide
                                          |            |
                                       allowed      not allowed
                                          |            |
                                     scheduler      pending store
                                          |         (CLI approval)
                                      worker
                                          |
                              snapshot -> handler -> verify -> audit

Handlers return ``ActionResult`` and are individually responsible for taking
a snapshot before mutating files. The executor adds a second policy check
(defence in depth), a per-action timeout, restart storm protection and the
audit record.
"""

from __future__ import annotations

import gzip
import json
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from . import util
from .config import Config
from .errors import PolicyDenied
from .models import ActionRequest, ActionResult, Finding, Priority, Task, TaskKind
from .policy import PendingStore, PolicyEngine

# action -> handler name is 1:1; the mapping lives in ActionExecutor.register
HandlerFn = Callable[[ActionRequest, "ExecContext"], ActionResult]


class ExecContext:
    def __init__(self, config: Config, backup, sandbox, firewall, security, policy: PolicyEngine,
                 logger: Optional[logging.Logger] = None, dry_run: bool = False, plugins=None, audit=None):
        self.config = config
        self.backup = backup
        self.sandbox = sandbox
        self.firewall = firewall
        self.security = security
        self.policy = policy
        self.log = logger or logging.getLogger("autonomic")
        self.dry_run = dry_run
        self.plugins = plugins
        self.audit = audit
        self.daemon = None  # injected late (for metrics snapshot)


class ActionExecutor:
    def __init__(self, config: Config, ctx: ExecContext, logger: Optional[logging.Logger] = None):
        self.config = config
        self.ctx = ctx
        self._log = logger or logging.getLogger("autonomic")
        self._handlers: dict[str, HandlerFn] = {}
        self._restarts: dict[str, list[float]] = {}
        self._lock = threading.Lock()
        self.max_restarts_per_hour = int(config.get("remediation.max_restarts_per_hour", 5) or 5)
        self._register_builtins()

    def register(self, action: str, handler: HandlerFn) -> None:
        with self._lock:
            self._handlers[action] = handler

    def unregister(self, action: str) -> None:
        with self._lock:
            self._handlers.pop(action, None)

    def actions(self) -> list[str]:
        with self._lock:
            return sorted(self._handlers)

    # ------------------------------------------------------------- dispatch
    def execute(self, request: ActionRequest, approved_by: Optional[str] = None,
                timeout: float = 120.0) -> ActionResult:
        started = time.time()
        decision = self.ctx.policy.decide(request, approved_by=approved_by)
        if not decision.allowed:
            detail = f"policy denied: {decision.reason}"
            if self.ctx.audit:
                self.ctx.audit.record(
                    actor=request.source, trigger=request.rule_id or request.id, action=request.action,
                    target=request.target, params=request.params, result=detail,
                    extra={"decision": decision.to_dict()},
                )
            return ActionResult(False, request.action, detail=detail, skipped=True, duration=time.time() - started)

        with self._lock:
            handler = self._handlers.get(request.action)
        if handler is None:
            return ActionResult(False, request.action, detail=f"no handler registered for '{request.action}'",
                                skipped=True, duration=time.time() - started)

        self._log.info("execute action=%s target=%s risk=%s approved_by=%s dry_run=%s",
                       request.action, request.target, decision.risk, approved_by or "-",
                       self.ctx.dry_run or request.dry_run)
        try:
            result = handler(request, self.ctx)
        except PolicyDenied as exc:
            result = ActionResult(False, request.action, detail=f"policy: {exc.message}", skipped=True)
        except Exception as exc:  # noqa: BLE001 - handler isolation
            self._log.error("action %s failed: %s", request.action, exc, exc_info=True)
            result = ActionResult(False, request.action, detail=f"{type(exc).__name__}: {exc}")
        result.duration = time.time() - started
        if self.ctx.audit:
            self.ctx.audit.record(
                actor=request.source, trigger=request.rule_id or request.id, action=request.action,
                target=request.target, params=request.params,
                result=("OK: " if result.ok else "FAILED: ") + result.detail,
                files_changed=result.changed_files, rollback_point=result.rollback_point,
                extra={
                    "approved_by": approved_by,
                    "dry_run": self.ctx.dry_run or request.dry_run,
                    "verified": result.verified,
                    "simulated": result.skipped,
                    "finding_id": request.finding_id,
                    "request_id": request.id,
                },
            )
        return result

    # ------------------------------------------------------------- builtins
    def _register_builtins(self) -> None:
        self.register("noop", _h_noop)
        self.register("notify", _h_notify)
        self.register("diagnostic", _h_diagnostic)
        self.register("process.restart", _h_process_restart)
        self.register("service.restart", _h_process_restart)
        self.register("disk.cleanup", _h_disk_cleanup)
        self.register("cache.cleanup", _h_cache_cleanup)
        self.register("log.rotate", _h_log_rotate)
        self.register("firewall.ban_ip", _h_ban_ip)
        self.register("firewall.unban_ip", _h_unban_ip)
        self.register("file.delete", _h_file_delete)
        self.register("shell.exec", _h_shell)
        self.register("plugin.install", _h_plugin_install)
        self.register("plugin.action", _h_plugin_action)
        self.register("code.patch", _h_code_patch)
        self.register("system.config.modify", _h_system_config)
        self.register("service.enable", _h_service_toggle)
        self.register("service.disable", _h_service_toggle)
        self.register("log.archive", _h_log_archive)
        self.register("notify.webhook", _h_webhook)

    def stats(self) -> dict:
        return {"actions": self.actions(), "max_restarts_per_hour": self.max_restarts_per_hour}


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

_RESTART_LOCK = threading.Lock()

def _resolve_process_spec(config: Config, name: str, params: dict) -> dict:
    spec = dict(config.get(f"remediation.processes.{name}", {}) or {})
    for key in ("unit", "command", "health_port", "health_host", "health_path", "pidfile", "match"):
        if params.get(key) not in (None, ""):
            spec[key] = params[key]
    spec.setdefault("name", name)
    return spec


def _process_alive(spec: dict) -> bool:
    name = str(spec.get("name", ""))
    pattern = str(spec.get("match") or name)
    pidfile = spec.get("pidfile")
    if pidfile:
        try:
            pid = int(util.read_text(str(pidfile)).strip())
            if os.path.exists(f"/proc/{pid}"):
                return True
        except (ValueError, OSError):
            pass
    if not pattern:
        return False
    for pid_dir in os.listdir("/proc"):
        if not pid_dir.isdigit():
            continue
        try:
            comm = util.read_text(f"/proc/{pid_dir}/comm").strip()
            cmdline = util.read_text(f"/proc/{pid_dir}/cmdline", max_bytes=8192).replace("\x00", " ")
        except OSError:
            continue
        try:
            if re.search(pattern, comm, re.I) or re.search(pattern, cmdline, re.I):
                return True
        except re.error:
            if pattern == comm:
                return True
    return False


def _port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=1.5):
            return True
    except (OSError, ValueError):
        return False


def _unit_active(unit: str) -> bool:
    try:
        proc = subprocess.run(["systemctl", "is-active", unit], capture_output=True, text=True,
                              timeout=8, check=False)
        return (proc.stdout or "").strip() == "active"
    except (subprocess.TimeoutExpired, OSError):
        return False


def _verify_service(spec: dict) -> tuple[bool, str]:
    checks = []
    unit = str(spec.get("unit") or "")
    if unit and _systemd_online():
        checks.append((f"unit {unit}", _unit_active(unit)))
    if spec.get("health_port"):
        host = str(spec.get("health_host", "127.0.0.1"))
        port = int(spec["health_port"])
        checks.append((f"port {host}:{port}", _port_open(host, port)))
    # Fall back to process-name matching only when there is no unit to verify.
    if not unit and spec.get("name"):
        checks.append((f"process {spec['name']}", _process_alive(spec)))
    if not checks:
        return True, "no verification target configured (restart accepted without health check)"
    for label, ok in checks:
        if not ok:
            return False, f"post-restart verification failed: {label} not healthy"
    return True, "verified: " + ", ".join(label for label, _ in checks)


def _systemd_online() -> bool:
    return os.path.isdir("/run/systemd/system")


# ---------------------------------------------------------------------------
# handlers
# ---------------------------------------------------------------------------

def _h_service_toggle(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    """Enable or disable a systemd unit. Gated by the approval list."""
    unit = req.target or str(req.params.get("unit") or req.params.get("service") or "")
    if not unit:
        return ActionResult(False, req.action, detail="no unit supplied")
    verb = "enable" if req.action == "service.enable" else "disable"
    if not _systemd_online():
        return ActionResult(False, req.action, detail="systemd is not available", skipped=True)
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would systemctl {verb} {unit}", skipped=True)
    try:
        proc = subprocess.run(["systemctl", verb, unit], capture_output=True, text=True,
                              timeout=30, check=False)
    except (subprocess.TimeoutExpired, OSError) as exc:
        return ActionResult(False, req.action, detail=f"systemctl {verb} {unit} error: {exc}")
    output = (proc.stdout + proc.stderr).strip()
    if proc.returncode != 0:
        return ActionResult(False, req.action,
                            detail=f"systemctl {verb} {unit} failed rc={proc.returncode}: {output[:400]}")
    state = ""
    try:
        chk = subprocess.run(["systemctl", "is-enabled", unit], capture_output=True, text=True,
                             timeout=10, check=False)
        state = (chk.stdout or "").strip()
    except (subprocess.TimeoutExpired, OSError):
        pass
    ok = (state == "enabled") if verb == "enable" else (state in ("disabled", "masked"))
    return ActionResult(ok, req.action,
                        detail=f"systemctl {verb} {unit} -> is-enabled={state or 'unknown'}", verified=ok)


def _h_log_archive(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    """Gzip *.log files older than a threshold; the active log is left alone."""
    log_dir = str(req.params.get("log_dir") or ctx.config.get("agent.log_dir"))
    min_age_hours = util.parse_int(req.params.get("min_age_hours"), 168, 1, 24 * 365)
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action,
                            detail=f"DRY-RUN: would gzip *.log older than {min_age_hours}h in {log_dir}",
                            skipped=True)
    cutoff = util.now() - min_age_hours * 3600
    archived = []
    try:
        names = os.listdir(log_dir)
    except OSError as exc:
        return ActionResult(False, req.action, detail=f"cannot read log dir {log_dir}: {exc}")
    for name in names:
        path = os.path.join(log_dir, name)
        if not os.path.isfile(path) or not name.endswith(".log"):
            continue
        try:
            if os.path.getmtime(path) > cutoff:
                continue
        except OSError:
            continue
        target = path + ".gz"
        try:
            with open(path, "rb") as src, gzip.open(target, "wb") as dst:
                shutil.copyfileobj(src, dst)
            os.unlink(path)
            archived.append(target)
        except OSError as exc:
            ctx.log.warning("log archive failed for %s: %s", path, exc)
    return ActionResult(True, req.action, detail=f"archived {len(archived)} log file(s)",
                        changed_files=archived)


def _post_json(url: str, payload: dict, timeout: float = 10) -> tuple:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    try:
        request = urllib.request.Request(url, data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(request, timeout=timeout) as resp:
            return True, "HTTP %s" % resp.status
    except (urllib.error.URLError, OSError) as exc:
        return False, str(exc)


def _h_webhook(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    """POST a JSON event to a configured webhook (Slack/DingTalk/Feishu/...)."""
    url = str(req.params.get("url") or ctx.config.get("notify.webhook_url") or "")
    if not url:
        return ActionResult(False, req.action,
                            detail="no webhook url configured (notify.webhook_url)", skipped=True)
    payload = {"action": req.action, "target": req.target, "params": req.params, "ts": util.iso()}
    ok, info = _post_json(url, payload, float(req.params.get("timeout", 10)))
    return ActionResult(ok, req.action, detail=f"webhook POST -> {info}")


def _h_noop(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    return ActionResult(True, req.action, detail="noop acknowledged", verified=True)


def _h_notify(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    message = str(req.params.get("message") or req.reason or req.target)
    path = os.path.join(ctx.config.get("agent.data_dir"), "notifications.jsonl")
    util.ensure_dir(os.path.dirname(path), 0o750)
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(util.json_dumps({"ts": util.iso(), "target": req.target, "message": message,
                                  "source": req.source, "request_id": req.id}) + "\n")
    ctx.log.info("notification target=%s message=%s", req.target, util.redact(message)[:200])
    detail = f"notification recorded for {req.target}"
    url = str(ctx.config.get("notify.webhook_url") or "")
    if url:
        ok, info = _post_json(url, {"action": "notify", "target": req.target, "message": message,
                                    "source": req.source, "ts": util.iso()})
        detail += "; webhook " + ("ok " + info if ok else "failed: " + info[:120])
    return ActionResult(True, req.action, detail=detail, verified=True)


def _h_diagnostic(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    latest = {}
    if ctx.daemon is not None:
        latest = getattr(ctx.daemon, "latest_metrics", None) or {}
    summary = {
        "cpu": latest.get("cpu"), "load": latest.get("load"), "memory": latest.get("memory"),
        "disks": latest.get("disks"), "top_connections": (latest.get("connections") or {}).get("per_ip", [])[:5],
    }
    detail = "diagnostic snapshot: " + util.json_dumps(summary)[:1200]
    return ActionResult(True, req.action, detail=detail, verified=True, output=util.json_dumps(summary, pretty=True))


def _h_process_restart(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    name = req.target or str(req.params.get("service") or req.params.get("name") or "")
    if not name:
        return ActionResult(False, req.action, detail="no target service name supplied")
    spec = _resolve_process_spec(ctx.config, name, req.params)

    # restart storm guard: per-target budget per rolling hour
    now = util.now()
    with _RESTART_LOCK:
        registries = getattr(ctx, "restart_registry", None)
        if registries is None:
            registries = {}
            setattr(ctx, "restart_registry", registries)
        history = [t for t in registries.get(name, []) if now - t < 3600]
        limit = int(ctx.config.get("remediation.max_restarts_per_hour", 5) or 5)
        if len(history) >= limit:
            return ActionResult(False, req.action,
                                detail=f"restart storm guard: {name} already restarted {len(history)} times in 1h",
                                skipped=True)
        registries[name] = history + [now]

    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would restart '{name}' via "
                                                     f"{spec.get('unit') or spec.get('command') or 'unknown'}",
                            verified=False, skipped=True)

    unit = str(spec.get("unit") or "")
    command = str(spec.get("command") or "")
    output = ""
    if unit and _systemd_online():
        try:
            proc = subprocess.run(["systemctl", "restart", unit], capture_output=True, text=True,
                                  timeout=float(req.params.get("timeout", 60)), check=False)
            output = (proc.stdout + proc.stderr).strip()
            if proc.returncode != 0:
                return ActionResult(False, req.action, detail=f"systemctl restart {unit} failed rc={proc.returncode}: {output[:400]}")
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ActionResult(False, req.action, detail=f"systemctl restart {unit} error: {exc}")
    elif command:
        recipe_check = ctx.policy.check_restart_command(command)
        if not recipe_check.allowed:
            return ActionResult(False, req.action,
                                detail=f"restart recipe rejected by policy: {recipe_check.reason}",
                                skipped=True)
        try:
            proc = subprocess.run(["sh", "-c", command], capture_output=True, text=True, timeout=60,
                                  check=False, env={"PATH": "/usr/local/bin:/usr/bin:/bin",
                                                    "HOME": "/tmp"})
            output = (proc.stdout + proc.stderr).strip()
            if proc.returncode != 0:
                return ActionResult(False, req.action, detail=f"restart command failed rc={proc.returncode}: {output[:400]}")
        except (subprocess.TimeoutExpired, OSError) as exc:
            return ActionResult(False, req.action, detail=f"restart command error: {exc}")
    else:
        return ActionResult(False, req.action,
                            detail=f"no restart recipe for '{name}'. Add remediation.processes.{name} "
                                   f"(unit/command) or pass params.command; refusing to guess.")

    time.sleep(float(req.params.get("verify_delay", 2.0)))
    ok, verify_detail = _verify_service(spec)
    return ActionResult(ok, req.action,
                        detail=f"restarted '{name}'; {verify_detail}" + (f"; output={output[:300]}" if output else ""),
                        verified=ok)


def _collect_cleanup_candidates(ctx: ExecContext, roots: list[str], min_age_hours: int,
                                max_files: int) -> tuple[list[dict], int]:
    cutoff = util.now() - min_age_hours * 3600
    candidates: list[dict] = []
    scanned = 0
    for root in roots:
        if not ctx.policy.in_cleanup_scope(root):
            ctx.log.warning("cleanup root rejected (outside policy.cleanup_paths): %s", root)
            continue
        if not os.path.isdir(root):
            continue
        for base, dirs, names in os.walk(root):
            # never follow symlinked directories
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(base, d))]
            for name in names:
                if len(candidates) >= max_files:
                    return candidates, scanned
                path = os.path.join(base, name)
                scanned += 1
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if not os.path.isfile(path) or os.path.islink(path):
                    continue
                if st.st_mtime > cutoff or st.st_size <= 0:
                    continue
                candidates.append({"path": path, "size": st.st_size, "mtime": st.st_mtime})
    return candidates, scanned


def _do_cleanup(req: ActionRequest, ctx: ExecContext, roots: Optional[list[str]] = None,
                label: str = "disk-cleanup") -> ActionResult:
    cfg_roots = list(roots or req.params.get("paths") or ctx.config.get("policy.cleanup_paths", []) or [])
    min_age = util.parse_int(req.params.get("min_age_hours"), int(ctx.config.get("policy.cleanup_min_age_hours", 48)), 1, 8760)
    max_files = util.parse_int(req.params.get("max_files"), int(ctx.config.get("policy.cleanup_max_files", 500)), 1, 5000)
    max_bytes = util.parse_int(req.params.get("max_bytes"), int(ctx.config.get("policy.cleanup_max_bytes", 2 * 1024 ** 3)),
                               1, 50 * 1024 ** 3)

    candidates, scanned = _collect_cleanup_candidates(ctx, cfg_roots, min_age, max_files)
    selected: list[dict] = []
    total = 0
    for item in candidates:
        if total + item["size"] > max_bytes:
            continue
        selected.append(item)
        total += item["size"]

    if not selected:
        return ActionResult(True, req.action, detail=f"nothing to clean (scanned={scanned}, roots={cfg_roots})",
                            verified=True)

    if ctx.dry_run or req.dry_run:
        preview = [f"{c['path']} ({util.human_bytes(c['size'])})" for c in selected[:10]]
        return ActionResult(True, req.action,
                            detail=f"DRY-RUN: would remove {len(selected)} files ({util.human_bytes(total)}). "
                                   f"First: {preview}", skipped=True, verified=False)

    # Disk/cache cleanup exists to free space, often precisely when the disk is
    # already full -- so copying file contents into the backup store is both
    # wasteful and frequently impossible. Take a metadata-only rollback record
    # (no payload copied) and then unlink the files directly. Deletion must not
    # depend on the snapshot copy succeeding.
    snap = {"id": "none", "complete": False}
    try:
        snap = ctx.backup.snapshot([c["path"] for c in selected], label=label,
                                   meta={"request_id": req.id, "reason": req.reason},
                                   metadata_only=True, remove_originals=False)
    except Exception as exc:  # noqa: BLE001 - best effort; deletion proceeds regardless
        ctx.log.warning("cleanup snapshot failed, continuing with deletion: %s", exc)

    removed = []
    failed = []
    for item in selected:
        try:
            if os.path.exists(item["path"]):
                os.unlink(item["path"])
            removed.append(item["path"])
        except OSError as exc:
            failed.append(item["path"])
            ctx.log.warning("cleanup failed to remove %s: %s", item["path"], exc)

    return ActionResult(
        True, req.action,
        detail=f"removed {len(removed)} files ({util.human_bytes(total)}) from {cfg_roots}; "
               f"snapshot={snap['id']} complete={snap['complete']} failed={len(failed)}",
        changed_files=removed[:80],
        rollback_point=snap["id"],
        verified=len(failed) == 0,
    )


def _h_disk_cleanup(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    return _do_cleanup(req, ctx)


def _h_cache_cleanup(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    cache_roots = [p for p in (ctx.config.get("policy.cleanup_paths", []) or []) if "cache" in str(p) or "tmp" in str(p)]
    return _do_cleanup(req, ctx, roots=cache_roots or ["/tmp"], label="cache-cleanup")


def _h_log_rotate(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    log_dir = str(req.params.get("log_dir") or ctx.config.get("agent.log_dir"))
    max_bytes = util.parse_int(req.params.get("max_bytes"), int(ctx.config.get("agent.log_max_bytes", 10 * 1024 * 1024)),
                               1024, 1024 ** 3)
    keep = util.parse_int(req.params.get("backups"), int(ctx.config.get("agent.log_backups", 5)), 1, 50)
    rotated = []
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would rotate logs in {log_dir}", skipped=True)
    for name in os.listdir(log_dir):
        path = os.path.join(log_dir, name)
        if not os.path.isfile(path) or not name.endswith(".log"):
            continue
        try:
            if os.path.getsize(path) < max_bytes:
                continue
        except OSError:
            continue
        stamp = util.utc_stamp()
        target = f"{path}.{stamp}"
        try:
            shutil.copy2(path, target)
            open(path, "w").close()
            rotated.append(target)
        except OSError as exc:
            ctx.log.warning("log rotate failed for %s: %s", path, exc)
    for name in os.listdir(log_dir):
        path = os.path.join(log_dir, name)
        if ".log." in name:
            siblings = sorted([os.path.join(log_dir, n) for n in os.listdir(log_dir)
                               if n.startswith(name.split(".log.")[0] + ".log.")])
            for stale in siblings[:-keep]:
                try:
                    os.unlink(stale)
                except OSError:
                    pass
    return ActionResult(True, req.action, detail=f"rotated {len(rotated)} log files in {log_dir}",
                        changed_files=rotated, verified=True)


def _h_ban_ip(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    ip = str(req.target or req.params.get("ip") or "")
    if not ip:
        return ActionResult(False, req.action, detail="no IP supplied")
    if req.source == "auto" and not ctx.config.get("security.auto_ban", False):
        return ActionResult(False, req.action, skipped=True,
                            detail="security.auto_ban=false; ban proposal requires approval")
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would ban {ip} on backend {ctx.firewall.backend}",
                            skipped=True, verified=False)
    result = ctx.firewall.ban(ip, reason=req.reason, duration=util.parse_int(req.params.get("duration"), 0) or None)
    if not result.get("ok"):
        return ActionResult(False, req.action, detail=f"ban failed: {result.get('error')}")
    return ActionResult(True, req.action,
                        detail=f"banned {ip} backend={result.get('backend')} simulated={result.get('simulated')} "
                               f"verified={result.get('verified')} expires_in={result.get('expires_in')}s",
                        rollback_point=f"unban:{ip}", verified=bool(result.get("verified")),
                        output=util.json_dumps(result, pretty=True))


def _h_unban_ip(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    ip = str(req.target or req.params.get("ip") or "")
    if not ip:
        return ActionResult(False, req.action, detail="no IP supplied")
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would unban {ip}", skipped=True)
    result = ctx.firewall.unban(ip, reason="action rollback")
    return ActionResult(bool(result.get("ok")), req.action, detail=f"unban {ip}: {result}", verified=bool(result.get("ok")))


def _h_file_delete(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    path = str(req.target or req.params.get("path") or "")
    if not path:
        return ActionResult(False, req.action, detail="no path supplied")
    if ctx.policy.is_forbidden_path(path):
        return ActionResult(False, req.action, detail=f"refusing to delete forbidden path {path}", skipped=True)
    if not os.path.exists(path):
        return ActionResult(True, req.action, detail=f"{path} does not exist", verified=True)
    if os.path.isdir(path):
        return ActionResult(False, req.action, detail="directory deletion is not automated; use a plugin with explicit approval")
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would delete {path}", skipped=True)
    snap = ctx.backup.snapshot([path], label="file-delete", meta={"request_id": req.id}, remove_originals=True)
    return ActionResult(True, req.action, detail=f"deleted {path}; snapshot={snap['id']}",
                        changed_files=[path], rollback_point=snap["id"], verified=snap["complete"])


def _h_shell(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    command = str(req.params.get("command") or req.target or "")
    check = ctx.policy.check_shell(command)
    if not check.allowed:
        return ActionResult(False, req.action, detail=f"shell policy: {check.reason}", skipped=True)
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would run: {command}", skipped=True)
    result = ctx.sandbox.run(["sh", "-c", command], timeout=util.parse_int(req.params.get("timeout"), 30),
                             allow_network=False, max_output=200_000)
    return ActionResult(result.ok, req.action,
                        detail=f"rc={result.rc} in {result.duration:.2f}s" + (f" stderr={result.stderr[:300]}" if result.stderr else ""),
                        verified=result.ok, output=result.stdout)


def _h_plugin_install(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    if ctx.plugins is None:
        return ActionResult(False, req.action, detail="plugin manager unavailable")
    path = str(req.params.get("path") or req.target or "")
    result = ctx.plugins.install(path)
    return ActionResult(bool(result.get("ok")), req.action, detail=util.json_dumps(result)[:800],
                        verified=bool(result.get("ok")))


def _h_plugin_action(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    if ctx.plugins is None:
        return ActionResult(False, req.action, detail="plugin manager unavailable")
    action_name = str(req.params.get("action") or req.target or "")
    finding = req.params.get("finding") or {}
    ok, detail = ctx.plugins.invoke_action(action_name, finding, req.params)
    return ActionResult(bool(ok), req.action, detail=str(detail)[:1000], verified=bool(ok))


def _h_code_patch(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    codegen = getattr(ctx, "codegen", None)
    if codegen is None:
        return ActionResult(False, req.action, detail="codegen module unavailable")
    spec = dict(req.params.get("spec") or {})
    spec.setdefault("target_path", req.target)
    result = codegen.generate_and_apply(spec, approved=True, actor="action-executor")
    return ActionResult(bool(result.get("ok")), req.action, detail=str(result.get("detail"))[:1000],
                        changed_files=result.get("changed_files", []),
                        rollback_point=result.get("rollback_point"), verified=bool(result.get("verified")))


def _h_system_config(req: ActionRequest, ctx: ExecContext) -> ActionResult:
    path = str(req.params.get("path") or req.target or "")
    content = str(req.params.get("content") or "")
    if not path or not content:
        return ActionResult(False, req.action, detail="system.config.modify requires path and content")
    if ctx.policy.is_forbidden_path(path):
        return ActionResult(False, req.action, detail=f"forbidden path {path}", skipped=True)
    if ctx.dry_run or req.dry_run:
        return ActionResult(True, req.action, detail=f"DRY-RUN: would write {len(content)} bytes to {path}", skipped=True)
    snap = ctx.backup.snapshot([path], label="config-modify", meta={"request_id": req.id})
    util.atomic_write(path, content)
    verified = util.sha256_file(path) == util.sha256_text(content)
    return ActionResult(True, req.action, detail=f"wrote {path}", changed_files=[path],
                        rollback_point=snap["id"], verified=verified)


# ---------------------------------------------------------------------------


class ActionCoordinator:
    """Translates action requests into scheduled tasks, or into proposals."""

    def __init__(self, config: Config, bus, scheduler, executor: ActionExecutor, policy: PolicyEngine,
                 pending: PendingStore, audit, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self.scheduler = scheduler
        self.executor = executor
        self.policy = policy
        self.pending = pending
        self.audit = audit
        self._log = logger or logging.getLogger("autonomic")
        self.submitted = 0
        self.queued_for_approval = 0
        self.rejected = 0
        bus.subscribe("action.request", self._on_request, name="action-coordinator")

    def _on_request(self, topic: str, event: dict) -> None:
        raw = event.get("request") or {}
        try:
            request = ActionRequest(
                action=raw["action"], target=raw.get("target", ""), params=raw.get("params", {}),
                risk=raw.get("risk", ""), source=raw.get("source", "auto"), reason=raw.get("reason", ""),
                rule_id=raw.get("rule_id"), finding_id=raw.get("finding_id"), id=raw.get("id") or util.new_id("a_"),
            )
        except (KeyError, TypeError) as exc:
            self._log.error("malformed action.request dropped: %s", exc)
            return
        self.handle(request)

    def handle(self, request: ActionRequest, approved_by: Optional[str] = None) -> dict:
        decision = self.policy.decide(request, approved_by=approved_by)
        self.audit.record(
            actor=request.source, trigger=request.rule_id or request.id, action="policy.decide",
            target=request.target, params={"action": request.action},
            result=f"{'allow' if decision.allowed else 'hold'}: {decision.reason}",
            extra={"risk": decision.risk, "rule_hit": decision.rule_hit, "request": request.to_dict()},
        )
        if decision.allowed:
            priority = Priority.CRITICAL if decision.risk in ("high", "critical") else Priority.SECURITY
            task = Task(
                kind=TaskKind.ACTION.value,
                payload={"request": request.to_dict(), "approved_by": approved_by},
                priority=int(priority), source=request.source,
                title=f"{request.action}:{request.target or '-'}",
                timeout=min(300, float(self.config.get("scheduler.default_task_timeout", 120))),
                preemptible=False,          # never leave a mutation half-done
                rule_id=request.rule_id, finding_id=request.finding_id,
            )
            decision_result = self.scheduler.submit(task)
            self.submitted += 1
            self.bus.publish("action.submitted", {"request": request.to_dict(), "task_id": task.id,
                                                  "decision": decision_result.to_dict()
                                                  if hasattr(decision_result, "to_dict") else decision_result})
            return {"status": "submitted", "task_id": task.id, "decision": decision.to_dict()}

        if decision.needs_approval:
            existing = self.pending.find_similar(request.action, request.target)
            if existing:
                self.bus.publish("action.pending", {"request": request.to_dict(), "decision": decision.to_dict()})
                self._log.warning("duplicate approval request ignored: existing id=%s action=%s target=%s",
                                  existing, request.action, request.target)
                return {"status": "pending_approval", "request_id": existing, "decision": decision.to_dict()}
            self.pending.add(request, decision)
            self.queued_for_approval += 1
            self.bus.publish("action.pending", {"request": request.to_dict(), "decision": decision.to_dict()})
            self._log.warning("action held for approval id=%s action=%s target=%s reason=%s",
                              request.id, request.action, request.target, decision.reason)
            return {"status": "pending_approval", "request_id": request.id, "decision": decision.to_dict()}

        self.rejected += 1
        self._log.warning("action hard-denied action=%s target=%s reason=%s", request.action, request.target,
                          decision.reason)
        return {"status": "denied", "request_id": request.id, "decision": decision.to_dict()}

    def approve(self, request_id: str, actor: str = "cli") -> dict:
        record = self.pending.pop(request_id)
        if not record:
            return {"ok": False, "error": f"pending request not found: {request_id}"}
        raw = record.get("request", {})
        request = ActionRequest(
            action=raw.get("action", ""), target=raw.get("target", ""), params=raw.get("params", {}),
            risk=raw.get("risk", ""), source="user", reason=raw.get("reason", ""),
            rule_id=raw.get("rule_id"), finding_id=raw.get("finding_id"), id=raw.get("id", request_id),
        )
        self.audit.record(actor=actor, trigger="cli.approve", action="approve", target=request.target,
                          params={"request_id": request_id, "action": request.action},
                          result="approved for execution")
        result = self.handle(request, approved_by=actor)
        return {"ok": result.get("status") == "submitted", **result}

    def reject(self, request_id: str, actor: str = "cli", reason: str = "") -> dict:
        record = self.pending.pop(request_id)
        if not record:
            return {"ok": True, "already_absent": True}
        self.audit.record(actor=actor, trigger="cli.reject", action="reject", target=request_id,
                          params={"action": record.get("request", {}).get("action")}, result=reason or "rejected")
        return {"ok": True, "request_id": request_id, "reason": reason}

    def stats(self) -> dict:
        return {"submitted": self.submitted, "pending_approval": self.queued_for_approval,
                "rejected": self.rejected, "pending_count": self.pending.count()}
