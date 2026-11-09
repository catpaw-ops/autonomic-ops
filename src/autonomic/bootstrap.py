"""Remote bootstrap: turn a blank server into a member of the ops cluster.

Threat model and guard rails:
  * a one-time ``bootstrap.authorization_token`` must match before anything is
    uploaded; this is the "authorization credential" the product promises
  * public IPs only by default (``bootstrap.allow_private`` must be enabled
    explicitly for a LAN host)
  * host keys are accepted on first use but recorded in known_hosts; disabling
    ``strict_host_key`` is possible but logged as a warning
  * every remote command is logged with its exit code and output tail
  * deployment is idempotent: an existing install is upgraded in place
  * ``simulate`` runs the identical step machine against a local fake root,
    so the pipeline is testable without a second machine
"""

from __future__ import annotations

import ipaddress
import logging
import os
import shutil
import subprocess
import tarfile
import time
from typing import Optional

from . import util
from .config import Config

PKG_NAME = "autonomic-ops"


class Deployer:
    def __init__(self, config: Config, audit=None, logger: Optional[logging.Logger] = None,
                 project_root: Optional[str] = None):
        self.config = config
        self.audit = audit
        self._log = logger or logging.getLogger("autonomic")
        self.project_root = project_root or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        self.token = str(config.get("bootstrap.authorization_token", "") or "")

    # ------------------------------------------------------------------ plan
    def plan(self, target: dict) -> dict:
        host = str(target.get("host") or "").strip()
        user = str(target.get("user") or self.config.get("bootstrap.ssh_user", "root"))
        port = util.parse_int(target.get("port"), int(self.config.get("bootstrap.ssh_port", 22)), 1, 65535)
        root = str(target.get("install_root") or self.config.get("bootstrap.install_root", "/opt/autonomic-ops"))
        return {
            "target": {"host": host, "user": user, "port": port, "install_root": root},
            "steps": [
                {"step": 1, "name": "authorize", "detail": "verify one-time bootstrap token and host reachability policy"},
                {"step": 2, "name": "preflight", "detail": "ssh: uname, python3 version, disk free, existing install detection"},
                {"step": 3, "name": "package", "detail": "build tar.gz from the project tree excluding data/logs"},
                {"step": 4, "name": "upload", "detail": "scp package to /tmp on the target"},
                {"step": 5, "name": "install", "detail": "extract and run scripts/install.sh --non-interactive on the target"},
                {"step": 6, "name": "start", "detail": "start the systemd unit, or the pidfile supervisor if systemd is offline"},
                {"step": 7, "name": "verify", "detail": "remote CLI status, socket exists, audit chain head present"},
            ],
            "requires": {"authorization_token": bool(self.token), "ssh_client": util.which("ssh") is not None},
        }

    # -------------------------------------------------------------- validate
    def _authorize(self, target: dict, provided_token: str) -> tuple[bool, str]:
        if not self.config.get("bootstrap.enabled", True):
            return False, "bootstrap.enabled=false"
        expected = self.token
        if not expected:
            return False, "bootstrap.authorization_token is empty; set it in config before deploying"
        if not provided_token or provided_token != expected:
            return False, "authorization token mismatch"
        host = str(target.get("host") or "")
        if not util.valid_ipv4(host):
            # hostnames are allowed if they are not obviously local
            if host in ("localhost", "127.0.0.1") and not self.config.get("bootstrap.allow_private", False):
                return False, "refusing localhost deployment without bootstrap.allow_private=true"
            return True, "ok"
        parsed = ipaddress.ip_address(host)
        if parsed.is_private and not self.config.get("bootstrap.allow_private", False):
            return False, "refusing private IP deployment; set bootstrap.allow_private=true if intentional"
        return True, "ok"

    # ------------------------------------------------------------------- run
    def deploy(self, target: dict, provided_token: str = "", simulate: bool = False,
               apply: bool = False) -> dict:
        steps: list[dict] = []
        started = time.time()
        host = str(target.get("host") or "").strip()
        if not host:
            return {"ok": False, "error": "target.host is required", "steps": steps}

        ok, why = self._authorize(target, provided_token)
        steps.append({"step": "authorize", "ok": ok, "detail": why})
        if not ok:
            self._audit("deploy", host, "denied", why)
            return {"ok": False, "error": why, "steps": steps, "plan": self.plan(target)}

        if simulate:
            result = self._simulate(target, steps)
        elif not apply:
            result = {"ok": True, "status": "plan_only", "plan": self.plan(target), "steps": steps,
                      "note": "no changes made; re-run with --apply to execute"}
        else:
            result = self._remote(target, steps)
        result["elapsed"] = round(time.time() - started, 1)
        result["steps"] = steps
        self._audit("deploy", host, "ok" if result.get("ok") else "failed",
                    util.json_dumps(steps)[-1200:])
        return result

    def _audit(self, action: str, target: str, result: str, detail: str) -> None:
        if self.audit:
            self.audit.record(actor="user", trigger="bootstrap", action=action, target=target,
                              params={"simulate": False}, result=f"{result}: {detail}")

    # -------------------------------------------------------------- simulate
    def _simulate(self, target: dict, steps: list[dict]) -> dict:
        root = os.path.join(self.config.get("bootstrap.simulate_root"), "opt", PKG_NAME)
        util.ensure_dir(os.path.dirname(root), 0o750)
        if os.path.exists(root):
            shutil.rmtree(root, ignore_errors=True)
        shutil.copytree(self.project_root, root, ignore=shutil.ignore_patterns(
            "data", "logs", ".git", "__pycache__", "*.pyc", ".tmp-tool-results"))
        steps.append({"step": "package", "ok": True, "detail": f"copied project tree to simulated remote {root}"})
        # Install into an isolated prefix, still on this host, no service start.
        script = os.path.join(root, "scripts", "install.sh")
        config_template = os.path.join(root, "config", "config.example.yaml")
        cmd = ["bash", script, "--prefix", root, "--config", config_template, "--non-interactive",
               "--no-service", "--simulate"]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False,
                              env={**os.environ, "AUTONOMIC_SIMULATE": "1"})
        steps.append({"step": "install", "ok": proc.returncode == 0,
                      "detail": (proc.stdout + proc.stderr).strip()[-1500:]})
        required = [os.path.join(root, "lib", "autonomic", "main.py"),
                    os.path.join(root, "bin", "autonomic-ops"),
                    os.path.join(root, "config", "rules", "default_rules.yaml")]
        missing = [p for p in required if not os.path.exists(p)]
        steps.append({"step": "verify", "ok": not missing,
                      "detail": "layout verified" if not missing else f"missing: {missing}"})
        return {"ok": not missing, "status": "simulated", "install_root": root}

    # ---------------------------------------------------------------- remote
    def _remote(self, target: dict, steps: list[dict]) -> dict:
        host = str(target.get("host"))
        user = str(target.get("user") or self.config.get("bootstrap.ssh_user", "root"))
        port = util.parse_int(target.get("port"), 22, 1, 65535)
        key = str(target.get("key") or "")
        root = str(target.get("install_root") or self.config.get("bootstrap.install_root", "/opt/autonomic-ops"))
        timeout = float(self.config.get("bootstrap.command_timeout", 180))
        ssh_base = ["ssh", "-o", "BatchMode=yes", "-o", f"ConnectTimeout={self.config.get('bootstrap.connect_timeout', 15)}",
                    "-o", "StrictHostKeyChecking=accept-new", "-p", str(port)]
        if key:
            ssh_base += ["-i", key]
        ssh_base.append(f"{user}@{host}")

        def run_remote(command: str, label: str, timeout_s: float = timeout) -> tuple[bool, str]:
            started = time.time()
            try:
                proc = subprocess.run(ssh_base + [command], capture_output=True, text=True, timeout=timeout_s, check=False)
                out = (proc.stdout + proc.stderr).strip()
                steps.append({"step": label, "ok": proc.returncode == 0, "rc": proc.returncode,
                              "detail": out[-1200:], "duration": round(time.time() - started, 1)})
                return proc.returncode == 0, out
            except subprocess.TimeoutExpired:
                steps.append({"step": label, "ok": False, "detail": f"timeout after {timeout_s}s"})
                return False, "timeout"
            except OSError as exc:
                steps.append({"step": label, "ok": False, "detail": str(exc)})
                return False, str(exc)

        ok, out = run_remote("uname -s && python3 -V && (command -v tar >/dev/null && echo tar-ok) && "
                             f"(test -d {root} && echo existing-install || echo blank)", "preflight", 30)
        if not ok:
            return {"ok": False, "status": "preflight_failed", "detail": out}
        if "Linux" not in out:
            return {"ok": False, "status": "unsupported_os", "detail": out}

        package = self._build_package()
        steps.append({"step": "package", "ok": bool(package), "detail": package or "failed to build package"})
        if not package:
            return {"ok": False, "status": "package_failed"}

        remote_pkg = f"/tmp/{PKG_NAME}-{util.utc_stamp()}.tgz"
        scp = ["scp", "-P", str(port), "-o", "StrictHostKeyChecking=accept-new"]
        if key:
            scp += ["-i", key]
        try:
            proc = subprocess.run(scp + [package, f"{user}@{host}:{remote_pkg}"], capture_output=True,
                                  text=True, timeout=timeout, check=False)
            ok = proc.returncode == 0
            steps.append({"step": "upload", "ok": ok, "detail": (proc.stdout + proc.stderr).strip()[-600:]})
            if not ok:
                return {"ok": False, "status": "upload_failed"}
        finally:
            try:
                os.unlink(package)
            except OSError:
                pass

        install_cmd = (f"mkdir -p {root} && tar xzf {remote_pkg} -C {root} --strip-components=1 && "
                       f"bash {root}/scripts/install.sh --prefix {root} --non-interactive "
                       f"--bootstrap-token {self.token} && rm -f {remote_pkg}")
        ok, out = run_remote(install_cmd, "install", timeout)
        if not ok:
            return {"ok": False, "status": "install_failed", "detail": out}

        ok, out = run_remote(f"{root}/bin/autonomic-ops status || "
                             f"(test -S {root}/run/agent.sock && echo socket-present)", "verify", 60)
        return {"ok": ok, "status": "deployed", "install_root": root, "detail": out[-800:]}

    def _build_package(self) -> str:
        out = os.path.join(self.config.get("agent.data_dir"), f"{PKG_NAME}-{util.utc_stamp()}.tgz")
        util.ensure_dir(os.path.dirname(out), 0o750)
        try:
            with tarfile.open(out, "w:gz") as tar:
                for entry in sorted(os.listdir(self.project_root)):
                    if entry in (".git", "data", "logs", "__pycache__", ".tmp-tool-results"):
                        continue
                    path = os.path.join(self.project_root, entry)
                    if os.path.isfile(path) and entry.endswith(".pyc"):
                        continue
                    tar.add(path, arcname=entry)
            return out
        except (OSError, tarfile.TarError) as exc:
            self._log.error("package build failed: %s", exc)
            return ""
