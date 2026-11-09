"""Dynamic plugin system with hot reload and fault isolation.

Contract (see docs/PLUGIN_DEV.md):

    PLUGIN = {
        "name": "cert_expiry", "version": "1.0.0", "description": "...",
        "permissions": {"exec": False, "network": False},
    }

    def setup(ctx):            # optional, called once
        ctx.register_detector("cert_expiry", detect, interval=3600)
        ctx.register_action("cert_expiry.notify", handle)
        ctx.register_rule({...})   # optional declarative rule

    def detect(ctx, sample):   # -> list[dict] | list[Finding]
        ...

Plugins never get a raw file handle, raw subprocess or the network by default.
They get a context object whose capabilities are gated by their declared
permissions, and every plugin-originated action still goes through the same
policy gate as built-in ones.

Hot reload never restarts the daemon: changed file -> unload old module ->
import new -> re-register detectors/actions/rules. A plugin that raises five
times in a row is disabled automatically and reported via CLI.
"""

from __future__ import annotations

import glob
import importlib.util
import logging
import os
import re
import shutil
import sys
import threading
import time
import types
from typing import Any, Callable, Optional

from . import util
from .config import Config
from .models import Finding

_REQUIRED = ("name", "version")
_FORBIDDEN_PLUGIN_PATTERNS = [
    (r"os\.system\s*\(", "os.system bypasses the plugin sandbox"),
    (r"\beval\s*\(", "eval of dynamic code"),
    (r"\bexec\s*\(", "exec of dynamic code"),
    (r"__import__\s*\(", "dynamic import"),
    (r"ctypes\.", "native memory access"),
    (r"socket\.socket\s*\(", "direct socket; use ctx.http_get with permission"),
    (r"subprocess\.\w+", "direct subprocess; use ctx.run_command with permission"),
]


class PluginContext:
    """Capability-scoped facade handed to each plugin."""

    def __init__(self, manager: "PluginManager", name: str, permissions: dict, module: types.ModuleType):
        self._manager = manager
        self.name = name
        self.permissions = permissions or {}
        self.module = module
        self.logger = logging.getLogger(f"autonomic.plugin.{name}")
        self.config = manager.config
        self.bus = manager.bus
        self.audit = manager.audit
        self.sandbox = manager.sandbox
        self.backup = manager.backup
        self.policy = manager.policy
        self._detectors: list[str] = []
        self._actions: list[str] = []
        self._subscriptions: list = []
        self._rules: list[str] = []
        self._unloaded = False

    # ------------------------------------------------------------ read-only
    def latest_metrics(self) -> dict:
        return self._manager.latest_metrics() or {}

    def read_text(self, path: str, max_bytes: int = 262144) -> str:
        allowed_prefixes = ("/proc/", "/sys/", "/var/log/", "/etc/", "/tmp/")
        real = os.path.realpath(path)
        if not real.startswith(allowed_prefixes):
            raise PermissionError(f"plugin read outside allowed prefixes: {real}")
        return util.read_text(real, max_bytes=max_bytes)

    # ---------------------------------------------------------- registration
    def register_detector(self, name: str, fn: Callable, interval: float = 0) -> str:
        key = f"plugin:{self.name}:{name}"
        self._manager.register_detector(self.name, key, fn, interval)
        self._detectors.append(key)
        return key

    def register_action(self, name: str, fn: Callable) -> str:
        key = f"{self.name}.{name}" if not name.startswith(f"{self.name}.") else name
        self._manager.register_action(self.name, key, fn)
        self._actions.append(key)
        return key

    def register_rule(self, rule: dict) -> Optional[str]:
        return self._manager.register_rule(self.name, rule)

    def subscribe(self, pattern: str, handler: Callable) -> None:
        sub = self.bus.subscribe(pattern, handler, name=f"plugin:{self.name}:{handler.__name__}")
        self._subscriptions.append(sub)

    def emit_finding(self, kind: str, target: str, value: Any = None, severity: str = "medium",
                     message: str = "", evidence: Optional[dict] = None) -> None:
        finding = Finding(kind=kind, target=target, value=value, severity=severity,
                          detector=f"plugin:{self.name}", message=message, evidence=evidence or {})
        self._manager.emit_finding(finding)

    # ------------------------------------------------------------- execution
    def run_command(self, argv: list, timeout: float = 10, allow_network: bool = False) -> dict:
        if not self.permissions.get("exec"):
            raise PermissionError("plugin has no 'exec' permission")
        if allow_network and not self.permissions.get("network"):
            raise PermissionError("plugin has no 'network' permission")
        result = self.sandbox.run(argv, timeout=timeout, allow_network=allow_network)
        return result.to_dict()

    def log(self, level: str, message: str) -> None:
        getattr(self.logger, level.lower(), self.logger.info)(util.redact(str(message))[:2000])

    def _cleanup(self) -> None:
        self._unloaded = True
        for key in self._detectors:
            self._manager.unregister_detector(key)
        for key in self._actions:
            self._manager.unregister_action(key)
        for key in self._rules:
            self._manager.unregister_rule(key)
        for sub in self._subscriptions:
            try:
                self.bus.unsubscribe(sub)
            except Exception:  # noqa: BLE001
                pass
        self._subscriptions = []


class PluginManager:
    def __init__(self, config: Config, bus, detector_engine, executor, policy, sandbox, backup, audit,
                 rule_engine=None, metrics_provider=None, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self.detectors = detector_engine
        self.executor = executor
        self.policy = policy
        self.sandbox = sandbox
        self.backup = backup
        self.audit = audit
        self.rules = rule_engine
        self._metrics_provider = metrics_provider
        self._log = logger or logging.getLogger("autonomic.plugin")
        self.dirs = [d for d in (config.get("plugins.dirs", []) or []) if d]
        install_dir = os.path.join(config.get("agent.data_dir"), "plugins")
        if install_dir not in self.dirs:
            self.dirs.append(install_dir)
        util.ensure_dir(install_dir, 0o750)
        self.max_bytes = int(config.get("plugins.max_plugin_bytes", 512 * 1024))
        self.error_threshold = int(config.get("plugins.error_disable_threshold", 5))
        self._lock = threading.RLock()
        self._plugins: dict[str, dict] = {}
        self._detector_fns: dict[str, tuple] = {}
        self._action_fns: dict[str, tuple] = {}
        self._runtime_rules: dict[str, Any] = {}
        self._stop = threading.Event()
        self._watch_thread: Optional[threading.Thread] = None
        self._last_scan: dict[str, tuple] = {}
        self._rejected: dict[str, tuple] = {}
        self.errors: list[dict] = []
        self._load_state()

    # ---------------------------------------------------------------- state
    def _load_state(self) -> None:
        path = self.config.get("plugins.state_file")
        data = util.json_loads(util.read_text(path), {}) or {}
        self._state = data if isinstance(data, dict) else {}

    def _save_state(self) -> None:
        path = self.config.get("plugins.state_file")
        payload = {"updated_at": util.iso(), "plugins": {
            name: {"path": rec.get("path"), "hash": rec.get("hash"), "version": rec.get("version"),
                   "enabled": rec.get("enabled", True), "errors": rec.get("errors", 0)}
            for name, rec in self._plugins.items()
        }}
        util.atomic_write(path, util.json_dumps(payload, pretty=True), mode=0o600)

    # ------------------------------------------------------------- discovery
    def scan(self, notify: bool = True) -> dict:
        with self._lock:
            discovered: dict[str, tuple[str, tuple]] = {}
            for directory in self.dirs:
                if not os.path.isdir(directory):
                    continue
                for path in sorted(glob.glob(os.path.join(directory, "*.py"))):
                    if os.path.basename(path).startswith("_"):
                        continue
                    try:
                        stat = os.stat(path)
                        signature = (int(stat.st_mtime), stat.st_size)
                    except OSError:
                        continue
                    discovered[os.path.abspath(path)] = (path, signature)

            loaded_paths = {os.path.abspath(rec["path"]) for rec in self._plugins.values()}
            added = changed = removed = 0
            for abs_path, (path, signature) in discovered.items():
                if abs_path not in loaded_paths:
                    if self._rejected.get(abs_path) == signature:
                        continue
                    if self._load_plugin(path):
                        added += 1
                        self._rejected.pop(abs_path, None)
                    else:
                        self._rejected[abs_path] = signature
                    continue
                name, rec = self._plugin_by_path(abs_path)
                if rec and rec.get("signature") != signature:
                    if self._reload_plugin(name):
                        changed += 1
            for name, rec in list(self._plugins.items()):
                if os.path.abspath(rec["path"]) not in discovered:
                    self.unload(name, reason="file removed")
                    removed += 1
            self._save_state()
            if notify and (added or changed or removed):
                self.bus.publish("plugin.changed", {"added": added, "changed": changed, "removed": removed,
                                                    "plugins": self.list()})
            return {"added": added, "changed": changed, "removed": removed, "loaded": len(self._plugins)}

    def _plugin_by_path(self, abs_path: str) -> tuple[Optional[str], Optional[dict]]:
        for name, rec in self._plugins.items():
            if os.path.abspath(rec["path"]) == abs_path:
                return name, rec
        return None, None

    # ---------------------------------------------------------------- loader
    def _validate_source(self, path: str, text: str) -> tuple[bool, str]:
        if len(text.encode("utf-8")) > self.max_bytes:
            return False, f"plugin exceeds {self.max_bytes} bytes"
        for pattern, reason in _FORBIDDEN_PLUGIN_PATTERNS:
            if re.search(pattern, text):
                return False, f"forbidden construct: {reason}"
        return True, "ok"

    def _import(self, path: str) -> types.ModuleType:
        name = f"autonomic_plugin_{util.sha256_text(os.path.abspath(path))[:10]}_{int(time.time() * 1000) % 100000}"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError(f"cannot create import spec for {path}")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.modules[name] = module
        return module

    def _load_plugin(self, path: str) -> bool:
        text = util.read_text(path)
        ok, reason = self._validate_source(path, text)
        if not ok:
            self._log.error("plugin rejected path=%s reason=%s", path, reason)
            self.errors.append({"path": path, "reason": reason, "ts": util.iso()})
            return False
        try:
            module = self._import(path)
            meta = getattr(module, "PLUGIN", None)
            if not isinstance(meta, dict):
                raise ValueError("missing PLUGIN metadata dict")
            for key in _REQUIRED:
                if not meta.get(key):
                    raise ValueError(f"PLUGIN.{key} is required")
            name = str(meta["name"])
            if not re.match(r"[a-zA-Z_][a-zA-Z0-9_\-]*", name):
                raise ValueError(f"invalid plugin name: {name}")
            if name in self._plugins:
                raise ValueError(f"duplicate plugin name: {name}")
            registry = self._state.get("plugins", {}).get(name, {})
            if registry.get("enabled") is False:
                self._log.warning("plugin %s is administratively disabled; not loading", name)
                return False
            permissions = dict(meta.get("permissions") or {})
            ctx = PluginContext(self, name, permissions, module)
            setup = getattr(module, "setup", None)
            if callable(setup):
                setup(ctx)
            sig = self._signature(path)
            with self._lock:
                self._plugins[name] = {
                    "name": name, "version": str(meta.get("version")), "description": str(meta.get("description", "")),
                    "path": os.path.abspath(path), "module": module, "ctx": ctx, "meta": meta,
                    "permissions": permissions, "signature": sig, "hash": util.sha256_file(path),
                    "enabled": True, "errors": 0, "loaded_at": util.iso(), "detectors": list(ctx._detectors),
                    "actions": list(ctx._actions),
                }
            self.audit.record(actor="system", trigger="plugin.load", action="plugin.load", target=name,
                              params={"path": path, "version": meta.get("version"),
                                      "permissions": permissions}, result="loaded")
            self._log.info("plugin loaded name=%s version=%s path=%s detectors=%d actions=%d",
                           name, meta.get("version"), path, len(ctx._detectors), len(ctx._actions))
            return True
        except Exception as exc:  # noqa: BLE001 - a bad plugin must not kill the daemon
            self._log.error("plugin load failed path=%s: %s", path, exc, exc_info=True)
            self.errors.append({"path": path, "reason": util.redact(str(exc)), "ts": util.iso()})
            self.audit.record(actor="system", trigger="plugin.load", action="plugin.load", target=os.path.basename(path),
                              params={}, result=f"FAILED: {exc}")
            return False

    def _signature(self, path: str) -> tuple:
        stat = os.stat(path)
        return (int(stat.st_mtime), stat.st_size)

    def unload(self, name: str, reason: str = "manual") -> bool:
        with self._lock:
            rec = self._plugins.pop(name, None)
        if not rec:
            return False
        try:
            teardown = getattr(rec["module"], "teardown", None)
            if callable(teardown):
                teardown(rec["ctx"])
        except Exception as exc:  # noqa: BLE001
            self._log.warning("plugin teardown %s failed: %s", name, exc)
        rec["ctx"]._cleanup()
        self.audit.record(actor="system", trigger="plugin.unload", action="plugin.unload", target=name,
                          params={"reason": reason}, result="unloaded")
        self._log.info("plugin unloaded name=%s reason=%s", name, reason)
        return True

    def _reload_plugin(self, name: str) -> bool:
        rec = self._plugins.get(name)
        if not rec:
            return False
        path = rec["path"]
        self._log.info("hot reload plugin=%s path=%s", name, path)
        self.unload(name, reason="hot reload")
        return self._load_plugin(path)

    # ------------------------------------------------------------ registries
    def register_detector(self, plugin: str, key: str, fn: Callable, interval: float = 0) -> None:
        with self._lock:
            self._detector_fns[key] = (plugin, fn, float(interval or 0), 0.0)

    def unregister_detector(self, key: str) -> None:
        with self._lock:
            self._detector_fns.pop(key, None)

    def register_action(self, plugin: str, key: str, fn: Callable) -> None:
        with self._lock:
            self._action_fns[key] = (plugin, fn)

    def unregister_action(self, key: str) -> None:
        with self._lock:
            self._action_fns.pop(key, None)

    def register_rule(self, plugin: str, rule: dict) -> Optional[str]:
        if self.rules is None:
            return None
        try:
            rule_id = self.rules.add_runtime_rule(rule, source=f"plugin:{plugin}")
            if rule_id:
                self._runtime_rules[rule_id] = plugin
            return rule_id
        except Exception as exc:  # noqa: BLE001
            self._log.error("plugin %s rule registration failed: %s", plugin, exc)
            return None

    def unregister_rule(self, rule_id: str) -> None:
        if self.rules is not None:
            self.rules.remove_runtime_rule(rule_id)
        self._runtime_rules.pop(rule_id, None)

    def invoke_action(self, action_name: str, finding: dict, params: dict) -> tuple[bool, str]:
        with self._lock:
            entry = self._action_fns.get(action_name)
        if not entry:
            return False, f"plugin action not found: {action_name}"
        plugin, fn = entry
        rec = self._plugins.get(plugin)
        if not rec or not rec.get("enabled", True):
            return False, f"plugin {plugin} is disabled"
        try:
            result = fn(rec["ctx"], finding or {}, params or {})
            if isinstance(result, tuple):
                ok, detail = result[0], result[1]
            elif isinstance(result, dict):
                ok, detail = bool(result.get("ok")), str(result.get("detail", ""))
            else:
                ok, detail = bool(result), ""
            if not ok:
                self._record_error(plugin, str(detail))
            return bool(ok), str(detail)
        except Exception as exc:  # noqa: BLE001
            self._record_error(plugin, str(exc))
            return False, f"{type(exc).__name__}: {exc}"

    def _record_error(self, plugin: str, message: str) -> None:
        rec = self._plugins.get(plugin)
        if not rec:
            return
        rec["errors"] = rec.get("errors", 0) + 1
        self.errors.append({"plugin": plugin, "error": util.redact(message)[:400], "ts": util.iso()})
        self.errors = self.errors[-30:]
        self._log.error("plugin error name=%s count=%d: %s", plugin, rec["errors"], message)
        if rec["errors"] >= self.error_threshold and rec.get("enabled", True):
            rec["enabled"] = False
            self._log.error("plugin %s disabled after %d consecutive errors", plugin, rec["errors"])
            self.audit.record(actor="system", trigger="plugin.auto_disable", action="plugin.disable", target=plugin,
                              params={"errors": rec["errors"]}, result="disabled")

    # ------------------------------------------------------------- detectors
    def run_detectors(self, sample: dict) -> list[Finding]:
        now = util.now()
        findings: list[Finding] = []
        with self._lock:
            entries = list(self._detector_fns.items())
        for key, (plugin, fn, interval, last_run) in entries:
            rec = self._plugins.get(plugin)
            if rec and not rec.get("enabled", True):
                continue
            if interval and now - last_run < interval:
                continue
            with self._lock:
                self._detector_fns[key] = (plugin, fn, interval, now)
            try:
                produced = fn(rec["ctx"] if rec else None, sample) or []
                for item in produced:
                    if isinstance(item, Finding):
                        findings.append(item)
                    elif isinstance(item, dict):
                        findings.append(Finding(
                            kind=str(item.get("kind")), target=str(item.get("target")),
                            value=item.get("value"), severity=str(item.get("severity", "medium")),
                            detector=f"plugin:{plugin}", message=str(item.get("message", "")),
                            evidence=item.get("evidence") or {},
                        ))
            except Exception as exc:  # noqa: BLE001
                self._record_error(plugin, f"detector {key}: {exc}")
        return findings

    def emit_finding(self, finding: Finding) -> None:
        self.detectors.plugin_finding(finding)

    def latest_metrics(self) -> dict:
        return self._metrics_provider() if self._metrics_provider else {}

    # ---------------------------------------------------------------- install
    def install(self, source: str) -> dict:
        if not self.config.get("plugins.allow_install", True):
            return {"ok": False, "detail": "plugins.allow_install=false"}
        if not source or not os.path.isfile(source):
            return {"ok": False, "detail": f"plugin source not found: {source}"}
        text = util.read_text(source)
        ok, reason = self._validate_source(source, text)
        if not ok:
            return {"ok": False, "detail": reason}
        try:
            module_meta = re.search(r"PLUGIN\s*=\s*\{", text)
            if not module_meta:
                return {"ok": False, "detail": "missing PLUGIN metadata"}
        except re.error:
            pass
        target_dir = self.dirs[-1]
        target = os.path.join(target_dir, os.path.basename(source))
        existed = os.path.exists(target)
        snapshot = self.backup.snapshot([target], label="plugin-install", meta={"source": source})
        with open(source, "rb") as src_fh, open(target + ".tmp", "wb") as dst_fh:
            dst_fh.write(src_fh.read())
        os.chmod(target + ".tmp", 0o644)
        os.replace(target + ".tmp", target)
        self.audit.record(actor="user", trigger="plugin.install", action="plugin.install", target=target,
                          params={"source": source, "overwrite": existed},
                          result="installed", rollback_point=snapshot["id"] if snapshot else None,
                          files_changed=[target])
        loaded = self.scan(notify=True)
        return {"ok": True, "target": target, "overwrote": existed, "scan": loaded,
                "rollback_point": snapshot["id"] if snapshot else None}

    # -------------------------------------------------------------- watchers
    def start_watcher(self) -> None:
        if not self.config.get("plugins.hot_reload", True):
            return
        if self._watch_thread and self._watch_thread.is_alive():
            return
        self._stop.clear()
        self._watch_thread = threading.Thread(target=self._watch_loop, name="plugin-watcher", daemon=True)
        self._watch_thread.start()

    def _watch_loop(self) -> None:
        interval = float(self.config.get("plugins.scan_interval", 5))
        while not self._stop.wait(interval):
            try:
                self.scan()
            except Exception as exc:  # noqa: BLE001
                self._log.error("plugin scan failed: %s", exc, exc_info=True)

    def stop(self) -> None:
        self._stop.set()
        if self._watch_thread:
            self._watch_thread.join(timeout=3)
        for name in list(self._plugins):
            self.unload(name, reason="daemon shutdown")

    def list(self) -> list[dict]:
        with self._lock:
            return [
                {"name": rec["name"], "version": rec["version"], "description": rec["description"],
                 "path": rec["path"], "enabled": rec["enabled"], "errors": rec["errors"],
                 "loaded_at": rec["loaded_at"], "detectors": rec["detectors"], "actions": rec["actions"],
                 "permissions": rec["permissions"]}
                for rec in sorted(self._plugins.values(), key=lambda r: r["name"])
            ]

    def stats(self) -> dict:
        return {"dirs": self.dirs, "loaded": len(self._plugins), "plugins": self.list(),
                "detector_hooks": len(self._detector_fns), "action_hooks": len(self._action_fns),
                "runtime_rules": len(self._runtime_rules), "errors": self.errors[-10:]}
