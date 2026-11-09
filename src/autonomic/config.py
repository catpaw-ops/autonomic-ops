"""Configuration loading, defaults, validation and hot-reload support.

The config is a nested mapping. Every subsystem reads it through ``Config.get``
with a dotted path so a typo produces one clear error at startup instead of an
AttributeError deep inside a worker thread.
"""

from __future__ import annotations

import copy
import os
import re
from typing import Any, Optional

from . import util, yamlmini
from .errors import ConfigError

try:  # pragma: no cover - exercised only when PyYAML exists
    import yaml as _pyyaml
except Exception:  # pragma: no cover
    _pyyaml = None

_ENV_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}")


DEFAULTS: dict = {
    "agent": {
        "name": "autonomic-ops",
        "node_id": "",
        "prefix": "/opt/autonomic-ops",
        "data_dir": "/var/lib/autonomic-ops",
        "log_dir": "/var/log/autonomic-ops",
        "run_dir": "/run/autonomic-ops",
        "socket": "",
        "pidfile": "",
        "log_level": "INFO",
        "log_max_bytes": 10 * 1024 * 1024,
        "log_backups": 5,
        "task_journal": True,
        "status_refresh": 5,
        "shutdown_grace": 10,
        "require_root_for_privileged": True,
        "allow_private_deploy": False,
    },
    "scheduler": {
        "workers": 4,
        "max_workers": 16,
        "tick_interval": 0.5,
        "queue_max": 200,
        "default_task_timeout": 120,
        "max_task_timeout": 1800,
        "default_cpu_seconds": 300,
        "default_memory_mb": 512,
        "aging_rate": 0.25,
        "aging_cap": 25,
        "preemption": True,
        "preempt_threshold": 15,
        "preempt_requeue_limit": 2,
        "dedupe_window": 30,
        "journal_max_entries": 500,
        "max_actions_per_minute": 30,
    },
    "policy": {
        "auto_remediate": True,
        "dry_run": False,
        "max_auto_risk": "medium",
        "critical_always_approval": True,
        "whitelist": [
            "process.restart",
            "service.restart",
            "disk.cleanup",
            "log.rotate",
            "plugin.action",
            "cache.cleanup",
        ],
        "approval_required": [
            "firewall.ban_ip",
            "file.delete",
            "system.config.modify",
            "service.enable",
            "service.disable",
            "sudo.modify",
            "plugin.install",
            "code.patch",
            "package.install",
            "shell.exec",
        ],
        "forbidden_paths": [
            "/boot",
            "/dev",
            "/proc",
            "/sys",
            "/etc/sudoers",
            "/etc/sudoers.d",
            "/etc/passwd",
            "/etc/shadow",
            "/etc/ssh/sshd_config",
            "/etc/systemd/system",
            "/usr/lib/systemd",
            "/lib/systemd",
        ],
        "cleanup_paths": ["/tmp", "/var/tmp", "/var/log", "/var/cache"],
        "cleanup_min_age_hours": 48,
        "cleanup_max_files": 500,
        "cleanup_max_bytes": 2 * 1024 * 1024 * 1024,
        "core_self_modify": False,
        "allow_unsigned_plugins": True,
        "shell_allowlist": [
            "uptime", "df ", "free", "date", "whoami", "id", "hostname",
            "systemctl status", "journalctl -n", "ss -", "du ", "ls ",
            "cat /proc/loadavg", "python3 -V", "uname",
        ],
        "shell_forbidden_patterns": [
            r"rm\s+-rf\s+/", r"mkfs", r"dd\s+if=", r":\(\)\s*\{", r"shutdown",
            r"reboot", r"iptables\s+-F", r"chmod\s+777\s+/etc", r"\bsudo\b",
            r"curl\s*[^|]*\|\s*(sh|bash)", r"base64\s+-d.*\|\s*(sh|bash)",
            r">\s*/dev/sd", r"\/etc\/sudoers",
        ],
    },
    "metrics": {
        "enabled": True,
        "interval": 10,
        "disk_paths": ["/", "/var", "/tmp"],
        "watch_ports": [
            {"host": "127.0.0.1", "port": 22, "name": "ssh", "critical": False},
        ],
        "watch_processes": [],
        "watch_units": [],
        "load_warn": 4.0,
        "load_critical": 8.0,
        "mem_warn_percent": 85,
        "mem_critical_percent": 95,
        "disk_warn_percent": 80,
        "disk_critical_percent": 92,
        "traffic_warn_mbps": 100,
        "conn_per_ip_threshold": 100,
        "ssh_log_paths": ["/var/log/auth.log", "/var/log/secure"],
        "ssh_fail_threshold": 5,
        "ssh_fail_window": 600,
        "auth_log_max_bytes": 4 * 1024 * 1024,
        "sustained_samples": 3,
        "top_n": 10,
    },
    "security": {
        "ids_enabled": True,
        "auto_ban": False,
        "ban_requires_approval": True,
        "firewall_backend": "auto",     # auto | nft | iptables | recorder
        "ban_duration": 3600,
        "max_bans_per_hour": 50,
        "protect_private_ips": True,
        "config_audit": True,
        "ssh_config_path": "/etc/ssh/sshd_config",
        "expose_check_ports": [22, 3306, 6379, 27017],
    },
    "backup": {
        "enabled": True,
        "dir": "",
        "max_snapshots": 300,
        "retention_days": 7,
        "max_file_bytes": 50 * 1024 * 1024,
        "max_total_bytes": 512 * 1024 * 1024,
        "auto_rollback_on_failure": True,
    },
    "audit": {
        "enabled": True,
        "file": "",
        "max_bytes": 32 * 1024 * 1024,
        "backups": 5,
        "chain": True,
    },
    "plugins": {
        "enabled": True,
        "dirs": [],
        "hot_reload": True,
        "scan_interval": 5,
        "error_disable_threshold": 5,
        "allow_install": True,
        "max_plugin_bytes": 512 * 1024,
        "state_file": "",
    },
    "chat": {
        "enabled": True,
        "default_priority": 70,
        "max_message_bytes": 16384,
        "history_limit": 200,
        "session_file": "",
    },
    "codegen": {
        "enabled": True,
        "max_artifact_bytes": 256 * 1024,
        "sandbox_run": True,
        "sandbox_timeout": 10,
        "sandbox_cpu_seconds": 10,
        "sandbox_memory_mb": 256,
        "allow_network_in_sandbox": False,
        "templates_dir": "",
        "require_approval_for_system_files": True,
        "core_manifest": "",
    },
    "bootstrap": {
        "enabled": True,
        "authorization_token": "",
        "install_root": "/opt/autonomic-ops",
        "ssh_user": "root",
        "ssh_port": 22,
        "connect_timeout": 15,
        "command_timeout": 180,
        "allow_private": False,
        "strict_host_key": True,
        "simulate_root": "",
        "package_excludes": ["data", "logs", ".git", "__pycache__", "*.pyc"],
    },
    "rules": {
        "path": "",
        "reload_interval": 30,
    },
    "remediation": {
        "processes": {},
        "max_restarts_per_hour": 5,
        "default_verify_delay": 2.0,
    },
    "watchdog": {
        "enabled": True,
        "interval": 10,
        "heartbeat_timeout": 45,
        "max_rss_mb": 1024,
        "max_fd": 4096,
        "restart_exit_code": 99,
        "core_integrity_interval": 60,
    },
}


def deep_merge(base: dict, override: dict) -> dict:
    result = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = copy.deepcopy(value)
    return result


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            name, default = match.group(1), match.group(2)
            return os.environ.get(name, default if default is not None else "")

        return _ENV_RE.sub(repl, value)
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    return value


def parse_yaml(text: str) -> Any:
    if _pyyaml is not None:
        try:
            return _pyyaml.safe_load(text) or {}
        except Exception as exc:  # noqa: BLE001 - convert to our error type
            raise ConfigError(f"YAML parse failed: {exc}") from exc
    try:
        return yamlmini.safe_load(text)
    except YamlSubsetError as exc:  # type: ignore[name-defined]
        raise ConfigError(str(exc)) from exc


class Config:
    def __init__(self, data: dict, path: str = "", raw_text: str = ""):
        self.data = data
        self.path = path
        self.raw_text = raw_text
        self._mtime = 0.0
        if path and os.path.exists(path):
            self._mtime = os.path.getmtime(path)

    # ------------------------------------------------------------------ read
    def get(self, dotted: str, default: Any = None) -> Any:
        node: Any = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    def require(self, dotted: str) -> Any:
        value = self.get(dotted, None)
        if value is None:
            raise ConfigError(f"missing required config key: {dotted}")
        return value

    def section(self, name: str) -> dict:
        value = self.get(name, {}) or {}
        if not isinstance(value, dict):
            raise ConfigError(f"config section '{name}' must be a mapping")
        return value

    def as_dict(self) -> dict:
        return copy.deepcopy(self.data)

    def public_dict(self) -> dict:
        """Config with secrets stripped - safe for CLI/IPC display."""
        def scrub(node: Any) -> Any:
            if isinstance(node, dict):
                return {
                    k: ("***" if str(k).lower() in ("api_key", "password", "token", "authorization_token", "secret") and node[k] else scrub(v))
                    for k, v in node.items()
                }
            if isinstance(node, list):
                return [scrub(v) for v in node]
            return node

        return scrub(self.data)

    # --------------------------------------------------------------- resolve
    def resolve_paths(self) -> None:
        prefix = self.get("agent.prefix", "/opt/autonomic-ops")
        data_dir = self.get("agent.data_dir", "/var/lib/autonomic-ops")
        log_dir = self.get("agent.log_dir", "/var/log/autonomic-ops")
        run_dir = self.get("agent.run_dir", "/run/autonomic-ops")

        def expand(p: str) -> str:
            if not p:
                return p
            p = os.path.expanduser(os.path.expandvars(str(p)))
            if not os.path.isabs(p):
                p = os.path.join(prefix, p)
            return p

        self.data["agent"]["prefix"] = expand(prefix)
        self.data["agent"]["data_dir"] = expand(data_dir)
        self.data["agent"]["log_dir"] = expand(log_dir)
        self.data["agent"]["run_dir"] = expand(run_dir)
        self.data["agent"]["socket"] = expand(self.get("agent.socket", "") or os.path.join(run_dir, "agent.sock"))
        self.data["agent"]["pidfile"] = expand(self.get("agent.pidfile", "") or os.path.join(run_dir, "agent.pid"))
        self.data["backup"]["dir"] = expand(self.get("backup.dir", "") or os.path.join(data_dir, "backups"))
        self.data["audit"]["file"] = expand(self.get("audit.file", "") or os.path.join(log_dir, "audit.log"))
        self.data["plugins"]["state_file"] = expand(
            self.get("plugins.state_file", "") or os.path.join(data_dir, "plugins-state.json")
        )
        self.data["chat"]["session_file"] = expand(
            self.get("chat.session_file", "") or os.path.join(data_dir, "chat-sessions.jsonl")
        )
        self.data["codegen"]["templates_dir"] = expand(
            self.get("codegen.templates_dir", "") or os.path.join(prefix, "templates")
        )
        self.data["rules"]["path"] = expand(
            self.get("rules.path", "") or os.path.join(prefix, "config", "rules")
        )
        self.data["codegen"]["core_manifest"] = expand(
            self.get("codegen.core_manifest", "") or os.path.join(data_dir, "core-manifest.json")
        )
        self.data["bootstrap"]["simulate_root"] = expand(
            self.get("bootstrap.simulate_root", "") or os.path.join(data_dir, "simulated-remote")
        )
        if not self.data["agent"]["node_id"]:
            import socket
            self.data["agent"]["node_id"] = socket.gethostname() or "node"

        plugin_dirs = self.get("plugins.dirs", []) or []
        resolved = []
        for d in plugin_dirs:
            resolved.append(expand(d))
        self.data["plugins"]["dirs"] = resolved

    # -------------------------------------------------------------- validate
    def validate(self) -> list[str]:
        errors: list[str] = []
        ag = self.section("agent")
        if not str(ag.get("name", "")).strip():
            errors.append("agent.name must not be empty")
        if not os.path.isabs(str(ag.get("data_dir", ""))):
            errors.append("agent.data_dir must be an absolute path")
        workers = self.get("scheduler.workers", 4)
        if not isinstance(workers, int) or not 1 <= workers <= 64:
            errors.append("scheduler.workers must be an integer in [1, 64]")
        if self.get("scheduler.queue_max", 200) < 10:
            errors.append("scheduler.queue_max must be >= 10")
        for key in ("default_task_timeout", "max_task_timeout", "tick_interval"):
            val = self.get(f"scheduler.{key}", 0)
            if not isinstance(val, (int, float)) or val <= 0:
                errors.append(f"scheduler.{key} must be > 0")
        if self.get("scheduler.max_task_timeout", 1800) < self.get("scheduler.default_task_timeout", 120):
            errors.append("scheduler.max_task_timeout must be >= default_task_timeout")
        if self.get("policy.max_auto_risk") not in ("low", "medium", "high", "critical"):
            errors.append("policy.max_auto_risk must be one of: low, medium, high, critical")
        if self.get("security.firewall_backend") not in ("auto", "nft", "iptables", "recorder"):
            errors.append("security.firewall_backend must be one of: auto, nft, iptables, recorder")
        if self.get("backup.retention_days", 7) < 1:
            errors.append("backup.retention_days must be >= 1")
        if self.get("metrics.interval", 10) < 1:
            errors.append("metrics.interval must be >= 1 second")
        for key in ("load_warn", "load_critical", "disk_warn_percent", "disk_critical_percent"):
            val = self.get(f"metrics.{key}")
            if not isinstance(val, (int, float)):
                errors.append(f"metrics.{key} must be numeric")
        if self.get("metrics.disk_warn_percent", 80) >= self.get("metrics.disk_critical_percent", 92):
            errors.append("metrics.disk_warn_percent must be < disk_critical_percent")
        if self.get("scheduler.max_workers", 16) < self.get("scheduler.workers", 4):
            errors.append("scheduler.max_workers must be >= workers")
        for p in self.get("policy.forbidden_paths", []):
            if not str(p).startswith("/"):
                errors.append(f"policy.forbidden_paths entry not absolute: {p}")
        return errors

    def check_dirs(self) -> list[str]:
        errors = []
        for label, path in (
            ("data_dir", self.get("agent.data_dir")),
            ("log_dir", self.get("agent.log_dir")),
            ("run_dir", self.get("agent.run_dir")),
            ("backup_dir", self.get("backup.dir")),
        ):
            if not path:
                continue
            if os.path.exists(path):
                if not util.writable(path):
                    errors.append(f"{label} is not writable: {path}")
                continue
            probe = os.path.dirname(path) or "."
            while probe and not os.path.exists(probe):
                probe = os.path.dirname(probe) or "."
            if not util.writable(probe):
                errors.append(f"{label} cannot be created (nearest parent {probe} not writable): {path}")
        return errors

    # --------------------------------------------------------------- reload
    def changed_on_disk(self) -> bool:
        if not self.path or not os.path.exists(self.path):
            return False
        return os.path.getmtime(self.path) > self._mtime + 0.001

    def reload(self) -> "Config":
        return load_config(self.path)


def load_config(path: str, overrides: Optional[dict] = None) -> Config:
    if not path:
        raise ConfigError("config path is required")
    if not os.path.exists(path):
        raise ConfigError(f"config file not found: {path}")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = fh.read()
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc

    parsed = parse_yaml(raw)
    if not isinstance(parsed, dict):
        raise ConfigError("config root must be a mapping")

    data = deep_merge(DEFAULTS, _expand_env(parsed))
    if overrides:
        data = deep_merge(data, _expand_env(overrides))

    config = Config(data, path=path, raw_text=raw)
    config.resolve_paths()
    errors = config.validate()
    if errors:
        raise ConfigError("; ".join(errors))
    return config
