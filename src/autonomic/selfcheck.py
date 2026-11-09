"""`doctor` - one-shot environment and configuration diagnosis.

Every check is read-only and explains what to do when it fails, because this is
the first command a user runs on a fresh VPS.
"""

from __future__ import annotations

import os
import platform
import shutil
import sys
from typing import Optional

from . import util
from .config import Config, load_config
from .errors import AutonomicError
from .version import VERSION


def run(config_path: str, config: Optional[Config] = None) -> dict:
    checks: list[dict] = []

    def add(name: str, ok: bool, detail: str = "", hint: str = "", level: str = "error") -> None:
        checks.append({"check": name, "ok": bool(ok), "detail": detail, "hint": hint, "level": level if not ok else "ok"})

    add("python", sys.version_info >= (3, 9), f"{platform.python_version()} on {platform.platform()}",
        "Python 3.9+ is required")
    add("version", True, VERSION)
    try:
        with open(config_path, "r", encoding="utf-8") as fh:
            fh.read(1)
        add("config-readable", True, config_path)
    except OSError as exc:
        add("config-readable", False, str(exc), "check the path and file permissions")
        return {"ok": False, "checks": checks, "config": config_path}

    try:
        cfg = config or load_config(config_path)
        add("config-valid", True, f"{cfg.get('agent.name')} node={cfg.get('agent.node_id')}")
    except AutonomicError as exc:
        add("config-valid", False, exc.message, "fix the YAML or the reported key")
        return {"ok": False, "checks": checks, "config": config_path}

    errors = cfg.check_dirs()
    add("directories", not errors, "; ".join(errors) if errors else "data/log/run/backup dirs writable",
        "create the directories or run as the service user")

    # yaml / pyyaml availability
    try:
        import yaml  # noqa: F401
        add("pyyaml", True, "PyYAML present", level="info")
    except ImportError:
        add("pyyaml", True, "PyYAML absent - built-in YAML subset parser will be used", level="info")

    # rules
    from .rules import RuleEngine
    engine = RuleEngine(cfg, None, None)
    count = engine.load(cfg.get("rules.path"))
    add("rules", count > 0, f"{count} rules loaded, {len(engine.load_errors)} errors",
        "check config/rules/*.yaml", level="warning" if count else "error")

    # capabilities
    is_root = util.is_root()
    systemd = os.path.isdir("/run/systemd/system")
    add("root", is_root, "running as root" if is_root else "running unprivileged (privileged actions degrade)",
        "run as root for iptables/systemctl remediation", level="warning")
    add("systemd", systemd, "systemd online" if systemd else "systemd offline; use the pidfile supervisor",
        "install systemd or run `autonomic-ops service start`", level="warning")
    add("nft", util.which("nft") is not None, util.which("nft") or "nft not installed",
        "install nftables for the preferred firewall backend", level="info")
    add("iptables", util.which("iptables") is not None, util.which("iptables") or "iptables not installed",
        "install iptables as a fallback", level="info")
    add("ssh", util.which("ssh") is not None, util.which("ssh") or "ssh client missing",
        "install openssh-client for remote bootstrap")

    # sandbox capability
    from .sandbox import Sandbox
    sandbox = Sandbox(cfg)
    caps = sandbox.capabilities()
    add("sandbox", True, f"netns={caps.get('netns')} ulimit={caps.get('ulimit')} notes={caps.get('netns_error', '')}",
        "network namespace isolation is best-effort without root", level="info" if caps.get("netns") else "warning")

    # disk space for data dir
    try:
        usage = shutil.disk_usage(cfg.get("agent.data_dir"))
        free_gb = usage.free / 1024 ** 3
        add("disk-space", free_gb >= 1, f"{free_gb:.1f} GiB free at {cfg.get('agent.data_dir')}",
            "free at least 1 GiB for backups and logs")
    except OSError as exc:
        add("disk-space", False, str(exc), "check the data_dir mount")

    # core integrity
    try:
        integrity = __import__("autonomic.policy", fromlist=["CoreIntegrity"]).CoreIntegrity(cfg).verify()
        add("core-integrity", integrity["ok"],
            "unchanged" if integrity["ok"] else f"changed={integrity['changed']} added={integrity['added']}",
            "if this is a fresh install run `autonomic-ops audit verify`; otherwise restore from package")
    except Exception as exc:  # noqa: BLE001
        add("core-integrity", False, str(exc), "rebuild the core manifest")

    # config secret permissions
    try:
        mode = os.stat(config_path).st_mode & 0o777
        add("config-permissions", not (mode & 0o077), f"mode {oct(mode)}",
            "chmod 600 the config if it contains an API key", level="warning")
    except OSError:
        pass

    # runtime state
    add("socket", os.path.exists(cfg.get("agent.socket")),
        cfg.get("agent.socket"), "start the daemon to create the control socket", level="warning")
    add("pidfile", os.path.exists(cfg.get("agent.pidfile")),
        cfg.get("agent.pidfile"), "start the daemon", level="warning")

    failed = [c for c in checks if not c["ok"] and c["level"] == "error"]
    return {"ok": not failed, "checks": checks, "failed": len(failed),
            "warnings": len([c for c in checks if not c["ok"] and c["level"] != "error"]),
            "config": config_path}
