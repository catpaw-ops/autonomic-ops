"""Daemon assembly and supervision.

This module owns the process lifecycle and wires every subsystem together. It
is the only place that knows the full object graph; every other module receives
its dependencies through the constructor.

Startup order matters:
    logs -> audit -> bus -> policy/backup/sandbox -> detection -> rules ->
    security -> codegen -> executor -> scheduler -> plugins -> coordinator ->
    chat -> IPC -> watchdog

Shutdown is the reverse, with the scheduler drained before the audit log closes.
"""

from __future__ import annotations

import logging
import os
import signal
import threading
import time
from typing import Optional

from . import util
from .audit import AuditLog
from .backup import BackupManager
from .bootstrap import Deployer
from .bus import Bus
from .chat import ChatService
from .codegen import CodeGenerator
from .config import Config, load_config
from .detect import DetectorEngine
from .errors import AutonomicError, ConfigError
from .executor import ActionCoordinator, ActionExecutor, ExecContext
from .ipc import IPCServer
from . import util
from .logs import LogManager
from .metrics import MetricsSampler
from .models import ActionRequest, Priority, Task, TaskKind
from .plugins import PluginManager
from .policy import CoreIntegrity, PendingStore, PolicyEngine
from .rules import RuleEngine
from .sandbox import Sandbox
from .scheduler import Scheduler
from .security import Firewall, SecurityEngine
from .selfcheck import run as run_doctor
from .version import VERSION, version_string
from .watchdog import Watchdog

SKIP_TASK_AUDIT_KINDS = {TaskKind.DIAGNOSTIC.value, TaskKind.CHAT.value}


def _pid_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


class Daemon:
    def __init__(self, config: Config, console: bool = False):
        self.config = config
        self.config_path = config.path
        self.console = console
        self.logs = LogManager(config, console=console)
        self.logs.configure()
        self._log = self.logs.get("autonomic")
        self._task_log = self.logs.get("autonomic.task")
        self._started_at = util.now()
        self._stop_event = threading.Event()
        self._exit_code = 0
        self._shutdown_reason = ""
        self._ipc: Optional[IPCServer] = None
        self._boot_id = util.new_id("boot_")

        # core infrastructure
        self.audit = AuditLog(config, self._log)
        self.bus = Bus(max_queue=int(config.get("scheduler.queue_max", 200)) * 10, threads=2, logger=self._log)
        self.policy = PolicyEngine(config, self._log)
        self.pending = PendingStore(config.get("agent.data_dir"))
        self.sandbox = Sandbox(config, self._log)
        self.backup = BackupManager(config, self._log)
        self.core_integrity = self.policy.core

        # observation + reasoning
        self.metrics = MetricsSampler(config, self.bus, self.logs.get("autonomic.metrics"))
        self.detectors = DetectorEngine(config, self.bus, self.logs.get("autonomic.metrics"))
        self.rules = RuleEngine(config, self.bus, self._log)
        self.rules.load(config.get("rules.path"))
        self.firewall = Firewall(config, self.logs.get("autonomic.security"))
        self.security = SecurityEngine(config, self.firewall, self.logs.get("autonomic.security"))
        self.codegen = CodeGenerator(config, self.sandbox, self.backup, self.policy,
                                     self.audit, self.logs.get("autonomic.codegen"))
        self.codegen.publish = self.bus.publish

        # execution
        self.exec_ctx = ExecContext(config, self.backup, self.sandbox, self.firewall, self.security,
                                    self.policy, self._log, dry_run=self.policy.dry_run, audit=self.audit)
        self.exec_ctx.codegen = self.codegen
        self.exec_ctx.daemon = self
        self.executor = ActionExecutor(config, self.exec_ctx, self._log)
        self.scheduler = Scheduler(config, self.bus, self._run_task, audit=self.audit, logger=self._task_log)

        # extension layer
        self.plugins = PluginManager(config, self.bus, self.detectors, self.executor, self.policy,
                                     self.sandbox, self.backup, self.audit, rule_engine=self.rules,
                                     metrics_provider=lambda: self.latest_metrics,
                                     logger=self.logs.get("autonomic.plugin"))
        self.exec_ctx.plugins = self.plugins
        self.coordinator = ActionCoordinator(config, self.bus, self.scheduler, self.executor, self.policy,
                                             self.pending, self.audit, self._log)
        self.coordinator.policy = self.policy

        # human + remote interfaces
        self.chat = ChatService(config, self.scheduler, self.coordinator, self.codegen, self.plugins,
                                self.metrics, status_provider=self.status, rollback_fn=self.rollback,
                                deploy_fn=self.deploy_plan, audit=self.audit, logger=self.logs.get("autonomic.chat"))
        self.deployer = Deployer(config, self.audit, self._log)
        self.watchdog = Watchdog(config, self, self._log)

        self._wire_bus()
        self._last_security_audit = 0.0
        self._last_rules_check = 0.0
        self._rules_signature = self._compute_rules_signature()
        self.latest_metrics: dict = {}
        self._pidfile = config.get("agent.pidfile")
        util.ensure_dir(os.path.dirname(self._pidfile), 0o750)

    # ------------------------------------------------------------- wiring
    def _wire_bus(self) -> None:
        self.bus.subscribe("metrics.sample", self._on_sample, name="detector-feed")
        self.bus.subscribe("detect.finding", self._on_finding, name="rule-feed")
        self.bus.subscribe("task.finished", self._on_task_event, name="task-observer")
        self.bus.subscribe("task.preempt", self._on_task_event, name="preempt-observer")
        self.bus.subscribe("task.needs_review", self._on_needs_review, name="review-observer")
        self.bus.subscribe("security.alert", self._on_security_alert, name="security-observer")
        self.bus.subscribe("plugin.changed", self._on_plugin_changed, name="plugin-observer")

    def _on_sample(self, topic: str, event: dict) -> None:
        sample = event.get("sample") or {}
        self.latest_metrics = sample
        self.detectors.on_sample(sample)
        for finding in self.plugins.run_detectors(sample):
            self.detectors.plugin_finding(finding)
        self.exec_ctx.daemon = self
        self.exec_ctx.dry_run = self.policy.dry_run

    def _on_finding(self, topic: str, event: dict) -> None:
        finding = event.get("finding_obj")
        if finding is None:
            return
        for request in self.rules.on_finding(finding):
            self.bus.publish("action.request", {"request": request.to_dict()})

    def _on_task_event(self, topic: str, event: dict) -> None:
        task = event.get("task") or {}
        if topic == "task.preempt":
            self._task_log.warning("preempt task=%s victim=%s", task.get("id"),
                                   (event.get("victim") or {}).get("id"))

    def _on_needs_review(self, topic: str, event: dict) -> None:
        task = event.get("task") or {}
        self.audit.record(actor="system", trigger="crash-recovery", action="task.needs_review",
                          target=str(task.get("id")), params={"title": task.get("title")},
                          result=str(event.get("reason")))
        self._log.warning("task needs review after restart id=%s title=%s", task.get("id"), task.get("title"))

    def _on_security_alert(self, topic: str, event: dict) -> None:
        self._log.warning("security alert kind=%s detail=%s", event.get("kind"), event.get("detail"))

    def _on_plugin_changed(self, topic: str, event: dict) -> None:
        self._log.info("plugin set changed added=%s changed=%s removed=%s",
                       event.get("added"), event.get("changed"), event.get("removed"))

    # -------------------------------------------------------------- runner
    def _run_task(self, task: Task) -> dict:
        if task.cancel_event.is_set():
            return {"ok": False, "detail": "cancelled before execution"}
        self._task_log.info("execute task id=%s kind=%s source=%s", task.id, task.kind, task.source)
        if task.kind == TaskKind.SHELL.value:
            return self._task_shell(task)
        if task.kind == TaskKind.DIAGNOSTIC.value:
            return self._task_diagnostic(task)
        if task.kind == TaskKind.ACTION.value:
            return self._task_action(task)
        if task.kind == TaskKind.CODEGEN.value:
            return self._task_codegen(task)
        if task.kind == TaskKind.PLUGIN.value:
            name = str(task.payload.get("action") or "")
            finding = task.payload.get("finding") or {}
            ok, detail = self.plugins.invoke_action(name, finding, task.payload)
            return {"ok": ok, "detail": detail}
        if task.kind == TaskKind.DEPLOY.value:
            return self.deployer.deploy(task.payload.get("target") or {}, provided_token="", apply=True)
        if task.kind == TaskKind.NOOP.value:
            return {"ok": True, "detail": "noop"}
        return {"ok": False, "detail": f"unsupported task kind: {task.kind}"}

    def _task_shell(self, task: Task) -> dict:
        command = str(task.payload.get("command") or "")
        check = self.policy.check_shell(command)
        if not check.allowed:
            return {"ok": False, "detail": f"shell policy denied: {check.reason}"}
        result = self.sandbox.run(["sh", "-c", command], timeout=task.timeout, cpu_seconds=task.cpu_seconds,
                                 memory_mb=task.memory_mb, allow_network=False, cancel_event=task.cancel_event)
        self.audit.record(actor=task.source, trigger="task.shell", action="shell.exec", target=command[:200],
                          params={"task_id": task.id}, result=("OK" if result.ok else "FAILED") + f": rc={result.rc}",
                          extra={"duration": round(result.duration, 2), "notes": result.notes})
        return {"ok": result.ok, "cancelled": result.cancelled,
                "detail": ("cancelled: " if result.cancelled else f"rc={result.rc}: ") +
                          (result.stdout or result.stderr)[:600],
                "data": result.to_dict()}

    def _task_diagnostic(self, task: Task) -> dict:
        sample = self.latest_metrics or {}
        diagnostics = {
            "reason": task.payload.get("reason"),
            "message": task.payload.get("message"),
            "host": self.config.get("agent.node_id"),
            "uptime_seconds": round(util.now() - self._started_at),
            "load": sample.get("load"),
            "cpu": sample.get("cpu"),
            "memory": sample.get("memory"),
            "disks": sample.get("disks"),
            "ports": sample.get("ports"),
            "processes": sample.get("processes"),
            "connections": (sample.get("connections") or {}).get("per_ip", [])[:5],
            "queue": self.scheduler.stats().get("counters"),
            "pending_approval": self.pending.count(),
            "core_integrity": self.core_integrity.verify(),
            "plugins": len(self.plugins.list()),
            "firewall_backend": self.firewall.backend,
        }
        self._task_log.info("diagnostic completed task=%s", task.id)
        return {"ok": True, "detail": f"diagnostic collected for {self.config.get('agent.node_id')}",
                "data": diagnostics}

    def _task_action(self, task: Task) -> dict:
        raw = task.payload.get("request") or {}
        try:
            request = ActionRequest(
                action=raw.get("action", ""), target=raw.get("target", ""),
                params=raw.get("params") or {}, risk=raw.get("risk", ""),
                source=raw.get("source", "auto"), reason=raw.get("reason", ""),
                rule_id=raw.get("rule_id"), finding_id=raw.get("finding_id"),
                id=raw.get("id") or util.new_id("a_"),
            )
        except (TypeError, ValueError) as exc:
            return {"ok": False, "detail": f"malformed action payload: {exc}"}
        result = self.executor.execute(request, approved_by=task.payload.get("approved_by"), timeout=task.timeout)
        return {"ok": result.ok, "detail": result.detail, "data": result.to_dict()}

    def _task_codegen(self, task: Task) -> dict:
        spec = dict(task.payload.get("spec") or {})
        approved = bool(task.payload.get("approved"))
        result = self.codegen.generate_and_apply(spec, approved=approved, actor=task.source)
        return {"ok": bool(result.get("ok")), "detail": str(result.get("detail") or result.get("status")),
                "data": {"status": result.get("status"), "rollback_point": result.get("rollback_point"),
                         "validation": result.get("validation")}}

    # ------------------------------------------------------------- lifecycle
    def _write_pidfile(self) -> None:
        existing = self._read_pidfile()
        if existing and existing != os.getpid() and _pid_alive(existing):
            raise ConfigError(f"another daemon is already running with pid {existing}")
        util.atomic_write(self._pidfile, f"{os.getpid()}\n", mode=0o644)

    def _read_pidfile(self) -> Optional[int]:
        try:
            return int(util.read_text(self._pidfile).strip())
        except (ValueError, OSError):
            return None

    def _remove_pidfile(self) -> None:
        try:
            if self._read_pidfile() == os.getpid():
                os.unlink(self._pidfile)
        except OSError:
            pass

    def start(self) -> None:
        self._write_pidfile()
        self._log.info("starting %s pid=%d config=%s", version_string(), os.getpid(), self.config_path)
        self.audit.record(actor="system", trigger="daemon.start", action="daemon.start",
                          target=self.config.get("agent.node_id"),
                          params={"version": VERSION, "pid": os.getpid(), "config": self.config_path},
                          result="started")
        self.core_integrity.verify()
        self.bus.start()
        self.scheduler.recover()
        self.scheduler.start()
        self.metrics.start()
        self.plugins.scan(notify=False)
        self.plugins.start_watcher()
        self.watchdog.start()
        self._ipc = IPCServer(self.config, self.handle_ipc, self._log)
        self._ipc.start()
        self._run_security_audit(force=True)
        self.audit.record(actor="system", trigger="daemon.ready", action="daemon.ready",
                          target=self.config.get("agent.node_id"), params={"workers": len(self.scheduler.pool.workers)},
                          result="ready")
        self._log.info("daemon ready socket=%s workers=%d plugins=%d rules=%d",
                       self.config.get("agent.socket"), len(self.scheduler.pool.workers),
                       len(self.plugins.list()), len(self.rules.rules))

    def run(self) -> int:
        try:
            self.start()
        except Exception as exc:  # noqa: BLE001
            self._log.critical("startup failed: %s", exc, exc_info=True)
            self._shutdown(exit_code=1)
            return 1
        signal.signal(signal.SIGTERM, self._signal)
        signal.signal(signal.SIGINT, self._signal)
        if hasattr(signal, "SIGHUP"):
            signal.signal(signal.SIGHUP, self._signal)
        last_sweep = 0.0
        while not self._stop_event.wait(1.0):
            now = util.now()
            try:
                if now - last_sweep >= 60:
                    last_sweep = now
                    self.firewall.sweep()
                    self.pending.expire()
                if now - self._last_security_audit >= 600:
                    self._run_security_audit()
                self._maybe_reload_rules()
            except Exception as exc:  # noqa: BLE001
                self._log.error("maintenance tick failed: %s", exc, exc_info=True)
        self._shutdown(self._exit_code)
        return self._exit_code

    def _signal(self, signum, frame) -> None:
        if signum == getattr(signal, "SIGHUP", None):
            try:
                result = self.reload_config()
                self._log.info("SIGHUP config reload: %s", util.json_dumps(result)[:300])
            except Exception as exc:  # noqa: BLE001
                self._log.error("SIGHUP reload failed: %s", exc)
            return
        self._shutdown_reason = f"signal {signum}"
        self._log.info("received signal %s, shutting down", signum)
        self._stop_event.set()

    def _run_security_audit(self, force: bool = False) -> None:
        self._last_security_audit = util.now()
        findings = self.security.audit()
        for finding in findings:
            self.detectors.plugin_finding(finding)

    def _compute_rules_signature(self) -> tuple:
        path = self.config.get("rules.path")
        signature = []
        if os.path.isdir(path):
            for name in sorted(os.listdir(path)):
                if name.endswith((".yaml", ".yml")):
                    full = os.path.join(path, name)
                    try:
                        signature.append((name, int(os.path.getmtime(full)), os.path.getsize(full)))
                    except OSError:
                        continue
        return tuple(signature)

    def _maybe_reload_rules(self) -> None:
        now = util.now()
        interval = float(self.config.get("rules.reload_interval", 30))
        if now - self._last_rules_check < interval:
            return
        self._last_rules_check = now
        signature = self._compute_rules_signature()
        if signature != self._rules_signature:
            count = self.rules.reload()
            self._rules_signature = signature
            self._log.info("rules hot reloaded count=%d", count)
            self.audit.record(actor="system", trigger="rules.reload", action="rules.reload",
                              target=str(self.config.get("rules.path")), params={},
                              result=f"reloaded {count} rules")

    def _shutdown(self, exit_code: int = 0) -> None:
        if getattr(self, "_shutting_down", False):
            return
        self._shutting_down = True
        self._exit_code = exit_code
        self._log.info("shutdown begin reason=%s exit_code=%s", self._shutdown_reason or "normal", exit_code)
        try:
            self.audit.record(actor="system", trigger="daemon.stop", action="daemon.stop",
                              target=self.config.get("agent.node_id"),
                              params={"reason": self._shutdown_reason, "exit_code": exit_code,
                                      "uptime": round(util.now() - self._started_at)},
                              result="stopping")
        except Exception:  # noqa: BLE001
            pass
        if self._ipc:
            self._ipc.stop()
        self.watchdog.stop()
        self.plugins.stop()
        self.metrics.stop()
        self.scheduler.stop()
        try:
            self.bus.stop()
        except Exception:  # noqa: BLE001
            pass
        self.backup.prune()
        self._remove_pidfile()
        self._log.info("shutdown complete")
        self.logs.close()

    def emergency_exit(self, code: int, reason: str = "watchdog") -> None:
        self._shutdown_reason = f"watchdog: {reason}"
        self._exit_code = code
        try:
            self.audit.record(actor="watchdog", trigger="watchdog.restart", action="daemon.restart",
                              target=self.config.get("agent.node_id"), params={"reason": reason},
                              result=f"graceful exit with code {code} for supervisor restart")
        except Exception:  # noqa: BLE001
            pass
        self._stop_event.set()

    # ---------------------------------------------------------------- status
    def status(self) -> dict:
        sample = self.latest_metrics or {}
        return {
            "state": "running" if not self._stop_event.is_set() else "stopping",
            "version": VERSION,
            "boot_id": self._boot_id,
            "pid": os.getpid(),
            "node_id": self.config.get("agent.node_id"),
            "config": self.config_path,
            "uptime_seconds": round(util.now() - self._started_at),
            "queue": self.scheduler.stats(),
            "pending_approval": self.pending.count(),
            "metrics": {
                "ts": sample.get("ts_iso"),
                "cpu_percent": (sample.get("cpu") or {}).get("percent"),
                "load1": (sample.get("load") or {}).get("load1"),
                "mem_percent": (sample.get("memory") or {}).get("percent"),
                "disks": sample.get("disks"),
                "ports_down": [p.get("name") for p in sample.get("ports", []) if not p.get("open")],
                "connections": (sample.get("connections") or {}).get("established"),
                "ssh_failures": (sample.get("ssh") or {}).get("failed_total"),
            },
            "security": {**self.security.stats(), "bans": self.firewall.list_bans()},
            "policy": self.policy.describe(),
            "audit": self.audit.stats(),
            "backup": self.backup.stats(),
            "plugins": {"loaded": len(self.plugins.list()), "dirs": self.plugins.dirs,
                        "errors": self.plugins.errors[-3:]},
            "rules": self.rules.stats(),
            "bus": self.bus.stats(),
            "ipc": self._ipc.stats() if self._ipc else {},
            "watchdog": self.watchdog.status(),
            "sandbox": self.sandbox.capabilities(),
            "firewall_backend": self.firewall.backend,
        }

    # ------------------------------------------------------------- operations
    def rollback(self, snapshot_id: str) -> dict:
        if not snapshot_id:
            raise AutonomicError("snapshot id is required", code="backup.missing_id")
        result = self.backup.restore(snapshot_id, actor="user")
        self.audit.record(actor="user", trigger="cli.rollback", action="rollback", target=snapshot_id,
                          params={}, result=util.json_dumps(result)[:1200],
                          extra={"pre_rollback_snapshot": result.get("pre_rollback_snapshot")})
        return result

    def deploy_plan(self, target: dict) -> dict:
        return self.deployer.plan(target)

    def reload_config(self) -> dict:
        new = load_config(self.config_path)
        old_data = self.config.data
        self.config.data = new.data
        # dynamic subset that can be applied without rebuilding subsystems
        self.exec_ctx.dry_run = bool(self.config.get("policy.dry_run", False))
        self.scheduler.queue_max = int(self.config.get("scheduler.queue_max", 200))
        self.scheduler.aging_rate = float(self.config.get("scheduler.aging_rate", 0.25))
        self.scheduler.aging_cap = float(self.config.get("scheduler.aging_cap", 25))
        self.scheduler.preemption = bool(self.config.get("scheduler.preemption", True))
        self.metrics.interval = float(self.config.get("metrics.interval", 10))
        self.metrics.collector.config = self.config
        self.detectors.config = self.config
        self.rules.config = self.config
        self.chat.config = self.config
        self.chat.max_message = int(self.config.get("chat.max_message_bytes", 16384))
        self.codegen.config = self.config
        self.plugins.config = self.config
        self.watchdog.config = self.config
        new_policy = PolicyEngine(self.config, self._log)
        for attr in ("auto_remediate", "dry_run", "max_auto_risk", "whitelist", "approval_required",
                     "forbidden_paths", "cleanup_paths", "critical_always_approval", "shell_allowlist",
                     "shell_forbidden", "limiter", "core"):
            setattr(self.policy, attr, getattr(new_policy, attr))
        logging.getLogger("autonomic").setLevel(
            getattr(logging, str(self.config.get("agent.log_level", "INFO")).upper(), logging.INFO))
        self.core_integrity = self.policy.core
        self.audit.record(actor="user", trigger="cli.reload", action="config.reload", target=self.config_path,
                          params={}, result="config hot reloaded (dynamic subset)")
        return {"ok": True, "reloaded": True,
                "restart_required": ["firewall backend changes", "socket path changes", "worker count changes "
                                     "are applied via `workers set`"]}

    def handle_ipc(self, cmd: str, args: dict) -> dict:
        handlers = {
            "ping": lambda a: {"pong": True, "ts": util.iso(), "version": VERSION},
            "status": lambda a: self.status(),
            "metrics": lambda a: {"latest": self.latest_metrics, "stats": self.metrics.stats()},
            "tasks": lambda a: {"tasks": self.scheduler.task_list(bool(a.get("all")), util.parse_int(a.get("limit"), 50))},
            "task.get": lambda a: self._find_task(str(a.get("id") or "")),
            "task.cancel": lambda a: self.scheduler.cancel(str(a.get("id") or ""), str(a.get("reason") or "cli cancel")),
            "task.submit": self._ipc_submit,
            "chat": lambda a: self.chat.handle(str(a.get("message") or ""), actor=str(a.get("actor") or "cli")),
            "chat.history": lambda a: {"history": self.chat.history(util.parse_int(a.get("limit"), 20))},
            "logs": lambda a: {"channel": a.get("channel"), "lines": self._logs(a)},
            "pending": lambda a: {"pending": self.pending.list(util.parse_int(a.get("limit"), 50)),
                                  "count": self.pending.count()},
            "approve": lambda a: self.coordinator.approve(str(a.get("id") or ""), actor=str(a.get("actor") or "cli")),
            "reject": lambda a: self.coordinator.reject(str(a.get("id") or ""), actor=str(a.get("actor") or "cli"),
                                                        reason=str(a.get("reason") or "")),
            "rollback": lambda a: self.rollback(str(a.get("snapshot") or "")),
            "snapshots": lambda a: {"snapshots": self.backup.list(util.parse_int(a.get("limit"), 20)),
                                    "stats": self.backup.stats()},
            "plugins": self._ipc_plugins,
            "rules": self._ipc_rules,
            "bans": lambda a: {"backend": self.firewall.backend, "bans": self.firewall.list_bans(),
                               "simulated": self.firewall.simulated},
            "unban": lambda a: self.firewall.unban(str(a.get("ip") or ""), reason="cli"),
            "audit": self._ipc_audit,
            "workers": lambda a: self.scheduler.set_workers(util.parse_int(a.get("size"), 4, 1, 64)),
            "config": self._ipc_config,
            "codegen": self._ipc_codegen,
            "doctor": lambda a: run_doctor(self.config_path, self.config),
            "deploy": self._ipc_deploy,
            "version": lambda a: {"version": VERSION, "banner": version_string()},
            "stop": self._ipc_stop,
        }
        if cmd not in handlers:
            raise AutonomicError(f"unknown command: {cmd}", code="ipc.unknown_command", cmd=cmd)
        return handlers[cmd](args)

    def _ipc_submit(self, args: dict) -> dict:
        kind = str(args.get("kind") or TaskKind.SHELL.value)
        payload = dict(args.get("payload") or {})
        if args.get("command"):
            payload["command"] = str(args["command"])
        task = Task(kind=kind, payload=payload, priority=util.parse_int(args.get("priority"), 50, 1, 99),
                    source=str(args.get("source") or "user"), title=str(args.get("title") or f"{kind} task"),
                    timeout=util.parse_int(args.get("timeout"), 120, 1, 1800),
                    preemptible=util.parse_bool(args.get("preemptible", True), True))
        decision = self.scheduler.submit(task)
        return {"task": task.to_dict(), "decision": decision.to_dict()}

    def _find_task(self, task_id: str) -> dict:
        for task in self.scheduler.task_list(include_terminal=True, limit=200):
            if task.get("id") == task_id:
                return {"task": task}
        raise AutonomicError(f"task not found: {task_id}", code="task.not_found")

    def _logs(self, args: dict) -> list:
        channel = str(args.get("channel") or "runtime")
        if channel not in ("runtime", "error", "task", "decision", "security", "plugin", "metrics",
                           "codegen", "chat", "backup", "audit"):
            raise AutonomicError(f"unknown log channel: {channel}", code="logs.unknown_channel")
        lines = util.parse_int(args.get("lines"), 40, 1, 2000)
        if channel == "audit":
            return self.audit.tail(lines)
        return self.logs.tail(channel, lines)

    def _ipc_plugins(self, args: dict) -> dict:
        action = str(args.get("action") or "list")
        if action == "list":
            return {"plugins": self.plugins.list(), "stats": self.plugins.stats()}
        if action == "reload":
            return self.plugins.scan(notify=True)
        if action == "install":
            return self.plugins.install(str(args.get("path") or ""))
        if action == "unload":
            return {"ok": self.plugins.unload(str(args.get("name") or ""), reason="cli")}
        raise AutonomicError(f"unknown plugins action: {action}", code="plugins.bad_action")

    def _ipc_rules(self, args: dict) -> dict:
        action = str(args.get("action") or "list")
        if action == "list":
            return {"rules": [r.to_dict() for r in self.rules.rules], "stats": self.rules.stats()}
        if action == "reload":
            count = self.rules.reload()
            self._rules_signature = self._compute_rules_signature()
            return {"ok": True, "count": count, "stats": self.rules.stats()}
        raise AutonomicError(f"unknown rules action: {action}", code="rules.bad_action")

    def _ipc_audit(self, args: dict) -> dict:
        action = str(args.get("action") or "tail")
        if action == "verify":
            return self.audit.verify()
        if action == "tail":
            return {"records": self.audit.tail(util.parse_int(args.get("lines"), 50))}
        if action == "query":
            return {"records": self.audit.query(util.parse_int(args.get("limit"), 100),
                                                actor=str(args.get("actor") or ""),
                                                action=str(args.get("filter_action") or ""))}
        raise AutonomicError(f"unknown audit action: {action}", code="audit.bad_action")

    def _ipc_config(self, args: dict) -> dict:
        action = str(args.get("action") or "get")
        if action == "get":
            return {"config": self.config.public_dict(), "path": self.config_path}
        if action == "reload":
            return self.reload_config()
        if action == "validate":
            errors = self.config.validate()
            return {"ok": not errors, "errors": errors}
        raise AutonomicError(f"unknown config action: {action}", code="config.bad_action")

    def _ipc_codegen(self, args: dict) -> dict:
        action = str(args.get("action") or "preview")
        spec = dict(args.get("spec") or {})
        if action == "preview":
            return self.codegen.preview(spec)
        if action == "apply":
            return self.codegen.generate_and_apply(spec, approved=bool(args.get("approved", True)), actor="cli")
        raise AutonomicError(f"unknown codegen action: {action}", code="codegen.bad_action")

    def _ipc_deploy(self, args: dict) -> dict:
        target = dict(args.get("target") or {})
        if args.get("host"):
            target["host"] = args.get("host")
        result = self.deployer.deploy(target, provided_token=str(args.get("token") or ""),
                                      simulate=bool(args.get("simulate")),
                                      apply=bool(args.get("apply")))
        return result

    def _ipc_stop(self, args: dict) -> dict:
        self._shutdown_reason = "cli stop"
        threading.Timer(0.3, self._stop_event.set).start()
        return {"ok": True, "message": "shutdown scheduled"}
