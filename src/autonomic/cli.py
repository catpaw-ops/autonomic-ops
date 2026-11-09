"""Operator CLI.

This is the *only* thing a human runs interactively. It never imports the
daemon object graph; it talks to the control socket, so a CLI crash can never
take the supervisor down. The exceptions are `doctor`, `deploy` and `service`,
which are local one-shot operations by design.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from typing import Optional

from . import util
from .config import load_config
from .errors import AutonomicError
from .ipc import IPCClient
from .version import version_string

LOG_CHANNELS = ("runtime", "error", "task", "decision", "security", "plugin", "metrics",
                "codegen", "chat", "backup", "audit")


def _find_config(explicit: Optional[str]) -> str:
    candidates = [explicit, os.environ.get("AUTONOMIC_CONFIG"), "/etc/autonomic-ops/config.yaml",
                  "/opt/autonomic-ops/config/config.yaml", os.path.join(os.getcwd(), "config", "config.yaml")]
    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return os.path.abspath(candidate)
    return explicit or "/opt/autonomic-ops/config/config.yaml"


def _print_json(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _print_status(data: dict) -> None:
    q = data.get("queue", {})
    workers = q.get("workers", {})
    metrics = data.get("metrics", {})
    print(f"{data.get('node_id')}  {data.get('state')}  pid={data.get('pid')}  "
          f"uptime={util.duration_text(data.get('uptime_seconds', 0))}  version={data.get('version')}")
    print(f"queue: depth={q.get('queue_depth')} running={q.get('running')} "
          f"workers={workers.get('busy')}/{workers.get('size')} pending_approval={data.get('pending_approval')}")
    print(f"metrics: cpu={metrics.get('cpu_percent')}% load1={metrics.get('load1')} "
          f"mem={metrics.get('mem_percent')}% ssh_fail={metrics.get('ssh_failures')}")
    disks = metrics.get("disks") or []
    if disks:
        print("disk: " + "  ".join(f"{d['path']}={d['percent']}%" for d in disks))
    sec = data.get("security", {}).get("firewall", {})
    print(f"security: backend={sec.get('backend')} simulated={sec.get('simulated')} "
          f"bans={sec.get('active_bans')}")
    audit = data.get("audit", {})
    print(f"audit: records={audit.get('records')} last_hash={str(audit.get('last_hash'))[:16]}")
    plugins = data.get("plugins", {})
    print(f"plugins: loaded={plugins.get('loaded')}  rules={data.get('rules', {}).get('count')}")
    decisions = q.get("recent_decisions") or []
    if decisions:
        print("recent decisions:")
        for d in decisions[-5:]:
            print(f"  {d['ts']} {d['kind']:<8} task={d['task_id']} p={d['priority']} {d['reason'][:90]}")


def _print_tasks(tasks: list[dict]) -> None:
    if not tasks:
        print("no tasks")
        return
    print(f"{'ID':<14} {'STATE':<10} {'P':<3} {'KIND':<10} {'WORKER':<8} {'TITLE'}")
    for task in tasks:
        print(f"{task.get('id',''):<14} {task.get('state',''):<10} {task.get('priority',''):<3} "
              f"{task.get('kind',''):<10} {str(task.get('worker') or '-'):<8} {task.get('title','')[:60]}")


def _print_pending(items: list[dict]) -> None:
    if not items:
        print("no pending approvals")
        return
    for item in items:
        req = item.get("request", {})
        dec = item.get("decision", {})
        print(f"{req.get('id')}  {req.get('action')} -> {req.get('target') or '-'}  risk={dec.get('risk')}")
        print(f"    reason: {dec.get('reason')}")
        print(f"    created: {item.get('created_at')}")


def _follow(path: str, lines: int) -> None:
    for line in util.tail_lines(path, lines):
        print(line)
    try:
        offset = os.path.getsize(path)
    except OSError:
        offset = 0
    try:
        while True:
            time.sleep(0.4)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < offset:  # rotated
                offset = 0
            if size == offset:
                continue
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(offset)
                chunk = fh.read(size - offset)
                offset = fh.tell()
            sys.stdout.write(chunk)
            sys.stdout.flush()
    except KeyboardInterrupt:
        return


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="autonomic-ops", description=version_string())
    parser.add_argument("--config", "-c", help="path to config.yaml")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--timeout", type=float, default=15.0, help="IPC timeout seconds")
    parser.add_argument("--version", action="store_true")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("status", help="daemon and cluster status")
    sub.add_parser("metrics", help="latest metrics sample")
    sub.add_parser("doctor", help="environment/configuration diagnosis")

    p = sub.add_parser("tasks", help="list tasks")
    p.add_argument("--all", action="store_true", help="include finished tasks")
    p.add_argument("--limit", type=int, default=50)

    p = sub.add_parser("task", help="show one task")
    p.add_argument("id")

    p = sub.add_parser("cancel", help="cancel a task")
    p.add_argument("id")

    p = sub.add_parser("submit", help="submit a task")
    p.add_argument("--kind", default="shell", choices=["shell", "diagnostic", "plugin", "codegen",
                                                      "action", "deploy", "noop"])
    p.add_argument("--command", dest="cmd_value", default="")
    p.add_argument("--title", default="")
    p.add_argument("--priority", type=int, default=50)
    p.add_argument("--timeout", type=int, default=120)

    p = sub.add_parser("chat", help="send a control command (deterministic keyword routing)")
    p.add_argument("message")

    p = sub.add_parser("logs", help="tail a log channel")
    p.add_argument("channel", nargs="?", default="runtime", choices=LOG_CHANNELS)
    p.add_argument("-n", "--lines", type=int, default=40)
    p.add_argument("-f", "--follow", action="store_true")

    sub.add_parser("pending", help="list proposals awaiting approval")

    p = sub.add_parser("approve", help="approve a pending action")
    p.add_argument("id")

    p = sub.add_parser("reject", help="reject a pending action")
    p.add_argument("id")
    p.add_argument("--reason", default="")

    p = sub.add_parser("rollback", help="restore a snapshot")
    p.add_argument("snapshot")

    p = sub.add_parser("snapshots", help="list snapshots")
    p.add_argument("--limit", type=int, default=20)

    p = sub.add_parser("plugins", help="plugin management")
    p.add_argument("action", nargs="?", default="list", choices=["list", "reload", "install", "unload"])
    p.add_argument("arg", nargs="?", default="")

    p = sub.add_parser("plugin-push", help="push a plugin file to a remote node")
    p.add_argument("--host", required=True)
    p.add_argument("--file", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--key", default="")

    p = sub.add_parser("rules", help="rule management")
    p.add_argument("action", nargs="?", default="list", choices=["list", "reload"])

    sub.add_parser("bans", help="list firewall bans")

    p = sub.add_parser("unban", help="lift a firewall ban")
    p.add_argument("ip")

    p = sub.add_parser("audit", help="audit log")
    p.add_argument("action", nargs="?", default="tail", choices=["tail", "verify", "query"])
    p.add_argument("--lines", type=int, default=30)
    p.add_argument("--actor", default="")
    p.add_argument("--action-filter", default="")

    p = sub.add_parser("workers", help="resize the worker pool")
    p.add_argument("size", type=int)

    p = sub.add_parser("config", help="config inspection / hot reload")
    p.add_argument("action", nargs="?", default="get", choices=["get", "validate", "reload"])

    p = sub.add_parser("codegen", help="generate and validate a config/script/patch")
    p.add_argument("action", nargs="?", default="preview", choices=["preview", "apply"])
    p.add_argument("--target", required=True, help="absolute target path")
    p.add_argument("--purpose", default="config_fragment")
    p.add_argument("--requirements", default="")
    p.add_argument("--approved", action="store_true", help="approve the write (otherwise a proposal is stored)")

    p = sub.add_parser("deploy", help="bootstrap a remote server")
    p.add_argument("--host", required=True)
    p.add_argument("--user", default="root")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--key", default="")
    p.add_argument("--token", default=os.environ.get("AUTONOMIC_BOOTSTRAP_TOKEN", ""))
    p.add_argument("--install-root", default="")
    p.add_argument("--apply", action="store_true", help="actually deploy (default: plan only)")
    p.add_argument("--simulate", action="store_true", help="run the pipeline against a local fake root")
    p.add_argument("--yes", action="store_true", help="skip the interactive confirmation")

    p = sub.add_parser("service", help="systemd / pidfile service control")
    p.add_argument("action", choices=["start", "stop", "restart", "status"])

    sub.add_parser("stop", help="stop the daemon")

    p = sub.add_parser("serve", help="read-only web dashboard (localhost by default)")
    p.add_argument("--bind", default="127.0.0.1:8787", help="HOST:PORT to bind (default 127.0.0.1:8787)")
    p.add_argument("--token", default="", help="required when binding a non-loopback address")
    return parser


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(version_string())
        return 0
    if not args.command:
        parser.print_help()
        return 2

    config_path = _find_config(args.config)
    try:
        config = load_config(config_path)
    except AutonomicError as exc:
        sys.stderr.write(f"config error ({config_path}): {exc.message}\n")
        return 2

    if args.command == "doctor":
        from .selfcheck import run
        result = run(config_path, config)
        if args.json:
            _print_json(result)
        else:
            for check in result["checks"]:
                mark = "OK  " if check["ok"] else {"warning": "WARN", "info": "INFO"}.get(check.get("level"), "FAIL")
                print(f"[{mark}] {check['check']:<22} {check['detail']}")
                if not check["ok"] and check.get("hint"):
                    print(f"       -> {check['hint']}")
            print(f"\n{'PASS' if result.get('ok') else 'FAIL'}  checks={len(result['checks'])} "
                  f"failed={result.get('failed')} warnings={result.get('warnings', 0)}")
        return 0 if result.get("ok") else 1

    if args.command == "deploy":
        from .bootstrap import Deployer
        deployer = Deployer(config, project_root=_project_root())
        target = {"host": args.host, "user": args.user, "port": args.port, "key": args.key,
                  "install_root": args.install_root or config.get("bootstrap.install_root")}
        if args.simulate:
            result = deployer.deploy(target, provided_token=args.token, simulate=True)
        elif args.apply:
            if not args.yes:
                answer = input(f"Deploy to {args.host} as {args.user}? type 'yes': ")
                if answer.strip() != "yes":
                    print("aborted")
                    return 1
            result = deployer.deploy(target, provided_token=args.token, apply=True)
        else:
            result = deployer.deploy(target, provided_token=args.token, apply=False)
        _print_json(result)
        return 0 if result.get("ok") else 1

    if args.command == "service":
        return _service(config, args.action)

    if args.command == "serve":
        from .dashboard import serve
        return serve(config, args.bind, args.token)

    client = IPCClient(config, timeout=args.timeout)
    try:
        return _run_remote_command(client, args, config)
    except AutonomicError as exc:
        sys.stderr.write(f"{exc.code}: {exc.message}\n")
        if exc.code in ("ipc.unavailable", "ipc.no_token"):
            sys.stderr.write("hint: start the daemon with `autonomic-ops service start` "
                             f"(config: {config_path})\n")
        return 1


def _run_remote_command(client: IPCClient, args, config) -> int:
    cmd = args.command

    if cmd == "status":
        data = client.call("status")
        if args.json:
            _print_json(data)
        else:
            _print_status(data)
        return 0

    if cmd == "metrics":
        data = client.call("metrics")
        _print_json(data)
        return 0

    if cmd == "tasks":
        data = client.call("tasks", {"all": args.all, "limit": args.limit})
        if args.json:
            _print_json(data)
        else:
            _print_tasks(data.get("tasks", []))
        return 0

    if cmd == "task":
        _print_json(client.call("task.get", {"id": args.id}))
        return 0

    if cmd == "cancel":
        _print_json(client.call("task.cancel", {"id": args.id}))
        return 0

    if cmd == "submit":
        data = client.call("task.submit", {"kind": args.kind, "command": args.cmd_value, "title": args.title,
                                           "priority": args.priority, "timeout": args.timeout})
        _print_json(data)
        return 0

    if cmd == "chat":
        data = client.call("chat", {"message": args.message}, timeout=max(args.timeout, 30))
        if args.json:
            _print_json(data)
        else:
            print(data.get("reply", ""))
            decision = data.get("decision") or {}
            if decision:
                print(f"\n[decision] {decision.get('kind')} p={decision.get('priority')} "
                      f"queue={decision.get('queue_position')}")
        return 0 if data.get("ok", True) else 1

    if cmd == "logs":
        if args.channel == "audit":
            path = config.get("audit.file")
        else:
            path = os.path.join(config.get("agent.log_dir"), f"{args.channel}.log")
        if args.follow:
            _follow(path, args.lines)
        else:
            data = client.call("logs", {"channel": args.channel, "lines": args.lines})
            for line in data.get("lines", []):
                print(line if isinstance(line, str) else json.dumps(line, ensure_ascii=False))
        return 0

    if cmd == "pending":
        data = client.call("pending")
        if args.json:
            _print_json(data)
        else:
            _print_pending(data.get("pending", []))
        return 0

    if cmd == "approve":
        _print_json(client.call("approve", {"id": args.id}))
        return 0

    if cmd == "reject":
        _print_json(client.call("reject", {"id": args.id, "reason": args.reason}))
        return 0

    if cmd == "rollback":
        _print_json(client.call("rollback", {"snapshot": args.snapshot}, timeout=60))
        return 0

    if cmd == "snapshots":
        _print_json(client.call("snapshots", {"limit": args.limit}))
        return 0

    if cmd == "plugins":
        if args.action == "install" and not args.arg:
            sys.stderr.write("usage: autonomic-ops plugins install /path/to/plugin.py\n")
            return 2
        _print_json(client.call("plugins", {"action": args.action, "path": args.arg, "name": args.arg}))
        return 0

    if cmd == "plugin-push":
        return _push_plugin(config, args)

    if cmd == "rules":
        _print_json(client.call("rules", {"action": args.action}))
        return 0

    if cmd == "bans":
        _print_json(client.call("bans"))
        return 0

    if cmd == "unban":
        _print_json(client.call("unban", {"ip": args.ip}))
        return 0

    if cmd == "audit":
        data = client.call("audit", {"action": args.action, "lines": args.lines,
                                     "actor": args.actor, "filter_action": args.action_filter})
        _print_json(data)
        return 0

    if cmd == "workers":
        _print_json(client.call("workers", {"size": args.size}))
        return 0

    if cmd == "config":
        _print_json(client.call("config", {"action": args.action}))
        return 0

    if cmd == "codegen":
        spec = {"target_path": args.target, "purpose": args.purpose, "requirements": args.requirements}
        _print_json(client.call("codegen", {"action": args.action, "spec": spec, "approved": args.approved},
                                timeout=60))
        return 0

    if cmd == "stop":
        _print_json(client.call("stop"))
        return 0

    sys.stderr.write(f"unknown command: {cmd}\n")
    return 2


def _push_plugin(config, args) -> int:
    """Copy a plugin into a remote node's plugin dir and hot-reload it."""
    path = os.path.abspath(args.file)
    if not os.path.isfile(path):
        sys.stderr.write(f"plugin not found: {path}\n")
        return 2
    remote_dir = str(config.get("bootstrap.install_root")) + "/plugins/user"
    ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
                "-p", str(args.port)] + (["-i", args.key] if args.key else []) + [f"{args.user}@{args.host}"]
    scp_base = ["scp", "-P", str(args.port), "-o", "StrictHostKeyChecking=accept-new"] + \
               (["-i", args.key] if args.key else [])
    try:
        subprocess.run(ssh_base + [f"mkdir -p {remote_dir}"], check=True, timeout=30)
        subprocess.run(scp_base + [path, f"{args.user}@{args.host}:{remote_dir}/"], check=True, timeout=60)
        subprocess.run(ssh_base + [f"{config.get('bootstrap.install_root')}/bin/autonomic-ops plugins reload"],
                       check=True, timeout=60)
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, OSError) as exc:
        sys.stderr.write(f"plugin push failed: {exc}\n")
        return 1
    print(f"plugin pushed to {args.host}:{remote_dir}/{os.path.basename(path)} and hot-reloaded")
    return 0


def _service(config, action: str) -> int:
    unit = "autonomic-ops"
    systemd_online = os.path.isdir("/run/systemd/system")
    pidfile = config.get("agent.pidfile")
    config_path = config.path
    lib_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def read_pid() -> int:
        try:
            return int(util.read_text(pidfile).strip())
        except (ValueError, OSError):
            return 0

    if systemd_online:
        try:
            proc = subprocess.run(["systemctl", action, unit], capture_output=True, text=True, timeout=60, check=False)
            if proc.returncode == 0:
                print(f"systemd {action} {unit}: ok")
                return 0
        except (subprocess.TimeoutExpired, OSError):
            pass

    if action == "status":
        pid = read_pid()
        alive = False
        if pid:
            try:
                os.kill(pid, 0)
                alive = True
            except OSError:
                alive = False
        print(json.dumps({"service": unit, "mode": "pidfile", "pid": pid, "alive": alive,
                          "pidfile": pidfile, "systemd_online": systemd_online}, indent=2))
        return 0 if alive else 1

    if action == "start":
        if read_pid() and _alive(read_pid()):
            print(f"already running pid={read_pid()}")
            return 0
        env = dict(os.environ)
        env["PYTHONPATH"] = lib_path + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        proc = subprocess.run([sys.executable, "-m", "autonomic.main", "--config", config_path],
                              env=env, capture_output=True, text=True, timeout=30, check=False)
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        return proc.returncode

    if action == "stop":
        pid = read_pid()
        if not pid:
            print("not running (no pidfile)")
            return 0
        try:
            os.kill(pid, signal.SIGTERM)
        except OSError as exc:
            sys.stderr.write(f"stop failed: {exc}\n")
            return 1
        for _ in range(40):
            if not _alive(pid):
                print(f"stopped pid={pid}")
                return 0
            time.sleep(0.25)
        sys.stderr.write(f"pid {pid} did not exit within 10s\n")
        return 1

    if action == "restart":
        rc = _service(config, "stop")
        time.sleep(0.5)
        return _service(config, "start") if rc == 0 else rc
    return 2


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except OSError:
        return False


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


if __name__ == "__main__":
    sys.exit(main())
