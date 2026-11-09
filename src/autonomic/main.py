"""Daemon entry point.

Terminal discipline:
  * default mode daemonises (double fork) and prints at most one line
  * stdout/stderr of the daemon are redirected to ``console.log`` so a stray
    ``print`` from a plugin can never paint the operator's terminal
  * ``--foreground`` exists for systemd (Type=simple); it still logs to files
    unless ``--log-stdout`` is passed explicitly
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from typing import Optional

from . import util
from .config import load_config
from .errors import AutonomicError
from .version import VERSION, version_string


def _find_config(explicit: Optional[str]) -> str:
    candidates = [
        explicit,
        os.environ.get("AUTONOMIC_CONFIG"),
        "/etc/autonomic-ops/config.yaml",
        "/opt/autonomic-ops/config/config.yaml",
        os.path.join(os.getcwd(), "config", "config.yaml"),
        os.path.join(os.getcwd(), "config", "config.example.yaml"),
    ]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    return explicit or "/opt/autonomic-ops/config/config.yaml"


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


def _daemonize(stdout_path: str) -> tuple[bool, int]:
    """Double-fork. Returns (is_child, parent_pid_or_child_pid)."""
    read_fd, write_fd = os.pipe()
    first = os.fork()
    if first > 0:
        os.close(write_fd)
        os.waitpid(first, 0)
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                data = os.read(read_fd, 64)
            except OSError:
                data = b""
            if data:
                os.close(read_fd)
                return False, int(data.decode().strip() or 0)
            time.sleep(0.2)
        os.close(read_fd)
        return False, 0

    # first child
    os.close(read_fd)
    os.setsid()
    second = os.fork()
    if second > 0:
        os._exit(0)

    # grandchild: real daemon
    os.umask(0o027)
    util.ensure_dir(os.path.dirname(stdout_path), 0o750)
    fd = os.open(stdout_path, os.O_CREAT | os.O_WRONLY | os.O_APPEND, 0o640)
    os.dup2(fd, 1)
    os.dup2(fd, 2)
    if fd > 2:
        os.close(fd)
    os.write(write_fd, str(os.getpid()).encode())
    os.close(write_fd)
    return True, os.getpid()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autonomic-ops-daemon",
                                     description=f"{version_string()} - unattended operations agent")
    parser.add_argument("--config", "-c", help="path to config.yaml")
    parser.add_argument("--no-daemon", "--foreground", dest="foreground", action="store_true",
                        help="stay in the foreground (systemd Type=simple)")
    parser.add_argument("--log-stdout", action="store_true",
                        help="also log to stdout (foreground debugging only)")
    parser.add_argument("--check-config", action="store_true", help="validate config and exit")
    parser.add_argument("--doctor", action="store_true", help="run environment diagnosis and exit")
    parser.add_argument("--version", action="store_true")
    parser.add_argument("--quiet", action="store_true", help="print nothing on successful start")
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(version_string())
        return 0

    config_path = _find_config(args.config)
    try:
        config = load_config(config_path)
    except AutonomicError as exc:
        sys.stderr.write(f"config error ({config_path}): {exc.message}\n")
        return 2

    if args.check_config:
        errors = config.validate() + config.check_dirs()
        payload = {"ok": not errors, "config": config_path, "errors": errors,
                   "node_id": config.get("agent.node_id"),
                   "workers": config.get("scheduler.workers")}
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if not errors else 2

    if args.doctor:
        from .selfcheck import run
        result = run(config_path, config)
        print(json.dumps(result, ensure_ascii=False, indent=2, default=str))
        return 0 if result.get("ok") else 1

    # refuse a second copy before forking
    pidfile = config.get("agent.pidfile")
    if os.path.exists(pidfile):
        try:
            old_pid = int(util.read_text(pidfile).strip())
        except ValueError:
            old_pid = 0
        if old_pid and _pid_alive(old_pid) and old_pid != os.getpid():
            sys.stderr.write(f"another daemon is already running (pid {old_pid}, pidfile {pidfile})\n")
            return 3
        try:
            os.unlink(pidfile)
        except OSError:
            pass

    if not args.foreground:
        console_log = os.path.join(config.get("agent.log_dir"), "console.log")
        is_child, pid = _daemonize(console_log)
        if not is_child:
            if not args.quiet:
                if pid:
                    print(f"started pid={pid} config={config_path} logs={config.get('agent.log_dir')}")
                else:
                    sys.stderr.write("daemon failed to report readiness; check error.log\n")
                    return 1
            return 0 if pid else 1

    from .daemon import Daemon
    daemon = Daemon(config, console=args.log_stdout)
    try:
        return daemon.run()
    except KeyboardInterrupt:
        daemon._shutdown_reason = "keyboard interrupt"
        daemon._shutdown(0)
        return 0
    except Exception as exc:  # noqa: BLE001
        import logging
        logging.getLogger("autonomic.errors").critical("fatal daemon error: %s", exc, exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
