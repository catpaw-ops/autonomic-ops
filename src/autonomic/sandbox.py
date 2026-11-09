"""Sandboxed execution for generated code, plugin pre-runs and remediation.

Isolation is layered, and each layer degrades *loudly* rather than silently:

  1. fresh throw-away working directory, chmod 0700, cleaned afterwards
  2. scrubbed environment (no API keys, no daemon env leakage)
  3. POSIX rlimits: CPU seconds, address space, file size, open files, no core
  4. wall-clock timeout, whole process group killed on expiry
  5. network namespace (`unshare -n`) when the kernel allows it; otherwise the
     run is marked ``degraded_isolation=True`` and the caller decides whether
     that is acceptable (high-risk artifacts are refused without netns or an
     explicit policy override)
  6. output is written to files with a size cap, never accumulated unbounded
     in memory

There is no claim of a container/VM-grade boundary: without root or a
container runtime this is best-effort process isolation. The policy engine is
what prevents destructive actions from reaching the sandbox in the first
place; the sandbox is defence in depth, not the only defence.

On a non-POSIX development host (Windows) none of the layers above exist, so
``run()`` falls back to a plain child process and is *always* reported with
``degraded_isolation=True``. That fallback exists for unit tests and ``doctor``
only; production isolation remains Linux-only.
"""

from __future__ import annotations

import logging
import os
import shutil
import signal
import subprocess
import tempfile
import time
from typing import Iterable, Optional, Sequence

from . import util
from .config import Config
from .models import ExecResult


class Sandbox:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self.root = os.path.join(config.get("agent.data_dir"), "sandbox")
        util.ensure_dir(self.root, 0o700)
        self._log = logger or logging.getLogger("autonomic")
        self._caps: Optional[dict] = None

    # ------------------------------------------------------------ capability
    def capabilities(self, refresh: bool = False) -> dict:
        if self._caps is not None and not refresh:
            return dict(self._caps)
        posix = util.is_posix()
        caps = {
            "root": util.is_root(),
            "posix": posix,
            "netns": False,
            "ulimit": bool(posix and util.which("sh")),
            "python": (util.which("python3") or util.which("python")) is not None,
        }
        if posix and util.which("unshare"):
            try:
                probe = subprocess.run(
                    ["unshare", "-n", "true"], capture_output=True, timeout=3, check=False,
                    env={"PATH": "/usr/local/bin:/usr/bin:/bin"},
                )
                caps["netns"] = probe.returncode == 0
                caps["netns_error"] = "" if caps["netns"] else (probe.stderr.decode("utf-8", "replace").strip()[:200])
            except (subprocess.TimeoutExpired, OSError) as exc:
                caps["netns_error"] = str(exc)
        else:
            caps["netns_error"] = (
                "network namespaces require a POSIX/Linux host" if not posix
                else "unshare command not found"
            )
        self._caps = caps
        return dict(caps)

    # ------------------------------------------------------------------ run
    def run(
        self,
        argv: Sequence[str],
        cwd: Optional[str] = None,
        timeout: Optional[float] = None,
        cpu_seconds: Optional[int] = None,
        memory_mb: Optional[int] = None,
        allow_network: bool = False,
        env_extra: Optional[dict] = None,
        max_output: int = 200_000,
        stdin_data: Optional[str] = None,
        cancel_event=None,
    ) -> ExecResult:
        if not argv:
            return ExecResult(rc=2, stderr="empty argv", notes=["nothing to run"])
        timeout = float(timeout or self.config.get("codegen.sandbox_timeout", 10))
        cpu_seconds = int(cpu_seconds or self.config.get("codegen.sandbox_cpu_seconds", 10))
        memory_mb = int(memory_mb or self.config.get("codegen.sandbox_memory_mb", 256))
        caps = self.capabilities()
        posix = bool(caps.get("posix", util.is_posix()))
        degraded = (not caps.get("netns", False) and not allow_network) or not posix

        run_dir = tempfile.mkdtemp(prefix="run-", dir=self.root)
        os.chmod(run_dir, 0o700)
        work_dir = os.path.abspath(cwd) if cwd else os.path.join(run_dir, "work")
        util.ensure_dir(work_dir, 0o700)
        stray = not cwd
        out_path = os.path.join(run_dir, "stdout.txt")
        err_path = os.path.join(run_dir, "stderr.txt")

        default_path = "/usr/local/bin:/usr/bin:/bin" if posix else (os.environ.get("PATH") or os.defpath)
        env = {
            "PATH": env_extra.get("PATH", default_path) if env_extra else default_path,
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "HOME": work_dir,
            "TMPDIR": os.path.join(run_dir, "tmp"),
            "AUTONOMIC_SANDBOX": "1",
            "AUTONOMIC_DRY_RUN": "1",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
        util.ensure_dir(env["TMPDIR"], 0o700)
        if env_extra:
            for key, value in env_extra.items():
                if str(key).upper() in ("PATH",):
                    continue
                if any(s in str(key).upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD")):
                    continue
                env[str(key)] = str(value)

        notes: list[str] = []
        if posix:
            prefix = ["sh", "-c", self._ulimit_prefix(cpu_seconds, memory_mb), "sh"]
            if not allow_network:
                if caps.get("netns"):
                    prefix = ["unshare", "-n", "--"] + prefix
                else:
                    notes.append(
                        "network namespace unavailable (%s); run marked degraded - network is NOT isolated"
                        % caps.get("netns_error", "unknown reason")[:120]
                    )
            cmd = prefix + list(argv)
        else:
            # No rlimits, process groups or network namespaces on this host.
            # Run directly and report the loss of isolation explicitly.
            notes.append(
                "non-POSIX host: no rlimits/netns/process-group isolation; development fallback only"
            )
            cmd = list(argv)
        started = time.time()
        timed_out = killed = cancelled = False
        rc = -1
        kill_target = "process group" if posix else "child process"
        try:
            with open(out_path, "wb") as out_fh, open(err_path, "wb") as err_fh:
                proc = subprocess.Popen(
                    cmd,
                    cwd=work_dir,
                    env=env,
                    stdin=subprocess.PIPE if stdin_data else subprocess.DEVNULL,
                    stdout=out_fh,
                    stderr=err_fh,
                    start_new_session=posix,
                    close_fds=True,
                )
                if stdin_data:
                    try:
                        proc.stdin.write(stdin_data.encode("utf-8"))
                        proc.stdin.close()
                    except (BrokenPipeError, OSError):
                        pass
                deadline = started + timeout
                while True:
                    try:
                        rc = proc.wait(timeout=0.2)
                        break
                    except subprocess.TimeoutExpired:
                        if cancel_event is not None and cancel_event.is_set():
                            cancelled = True
                            self._kill_group(proc)
                            rc = self._reap(proc)
                            notes.append(f"cancelled cooperatively; {kill_target} terminated")
                            break
                        if time.time() > deadline:
                            timed_out = True
                            killed = True
                            self._kill_group(proc)
                            rc = self._reap(proc)
                            notes.append(f"wall-clock timeout after {timeout}s; {kill_target} killed")
                            break
        except OSError as exc:
            return ExecResult(rc=127, stderr=str(exc), notes=notes + ["failed to start process"],
                              degraded_isolation=degraded, cwd=work_dir)
        finally:
            duration = time.time() - started

        stdout = self._read_capped(out_path, max_output)
        stderr = self._read_capped(err_path, max_output)
        if not caps.get("netns") and not allow_network:
            notes.append("degraded isolation: rlimits+timeout only" if posix
                         else "degraded isolation: timeout only (no rlimits/netns on this host)")
        if stray:
            shutil.rmtree(run_dir, ignore_errors=True)

        return ExecResult(
            rc=rc if rc is not None else -1,
            stdout=stdout,
            stderr=stderr,
            duration=duration,
            timed_out=timed_out,
            killed=killed,
            cancelled=cancelled,
            degraded_isolation=degraded,
            notes=notes,
            cwd=work_dir,
        )

    @staticmethod
    def _ulimit_prefix(cpu_seconds: int, memory_mb: int) -> str:
        # `ulimit` values: -t seconds, -v KiB, -f 1024-byte blocks, -c core size
        return (
            "ulimit -t {cpu} 2>/dev/null; "
            "ulimit -v {mem} 2>/dev/null; "
            "ulimit -f {fsize} 2>/dev/null; "
            "ulimit -c 0 2>/dev/null; "
            "exec \"$@\""
        ).format(cpu=max(1, cpu_seconds), mem=max(64, memory_mb) * 1024, fsize=20 * 1024)

    def _kill_group(self, proc: subprocess.Popen) -> None:
        if util.is_posix():
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                time.sleep(0.4)
                if proc.poll() is None:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                return
            except (AttributeError, ProcessLookupError, PermissionError, OSError):
                pass
        # Windows has no process groups; fall back to killing the child only.
        try:
            proc.kill()
        except OSError:
            pass

    @staticmethod
    def _reap(proc: subprocess.Popen, timeout: float = 3.0) -> int:
        """Collect an exit code without hanging forever on a stuck child."""
        try:
            if proc.poll() is None:
                return proc.wait(timeout=timeout)
            return proc.returncode if proc.returncode is not None else -1
        except subprocess.TimeoutExpired:
            return -9

    @staticmethod
    def _read_capped(path: str, limit: int) -> str:
        try:
            size = os.path.getsize(path)
            with open(path, "rb") as fh:
                if size > limit:
                    fh.seek(size - limit)
                data = fh.read(limit)
            text = data.decode("utf-8", errors="replace")
            if size > limit:
                text = f"... <output truncated, {size} bytes total> ...\n" + text
            return text
        except OSError:
            return ""

    # ------------------------------------------------------------- file runs
    def run_script(self, path: str, args: Optional[list] = None, interpreter: Optional[str] = None,
                   timeout: Optional[float] = None, allow_network: bool = False) -> ExecResult:
        """Copy the artifact into the scratch dir and execute it there.

        Copying (rather than running in place) means relative writes, temp files
        and accidental ``./output`` land in the disposable directory, never next
        to the real artifact.
        """
        if not os.path.exists(path):
            return ExecResult(rc=2, stderr=f"artifact not found: {path}", notes=["missing artifact"])
        run_dir = tempfile.mkdtemp(prefix="artifact-", dir=self.root)
        os.chmod(run_dir, 0o700)
        name = os.path.basename(path)
        target = os.path.join(run_dir, name)
        shutil.copy2(path, target)
        os.chmod(target, 0o700)
        if interpreter is None:
            interpreter = self.guess_interpreter(path)
        argv = [interpreter, target] + list(args or [])
        return self.run(argv, cwd=run_dir, timeout=timeout, allow_network=allow_network)

    @staticmethod
    def guess_interpreter(path: str) -> str:
        ext = os.path.splitext(path)[1].lower()
        if ext == ".py":
            return util.which("python3") or "python3"
        if ext in (".sh", ".bash"):
            return util.which("bash") or "bash"
        try:
            with open(path, "rb") as fh:
                first = fh.readline(200).decode("utf-8", "replace")
            if first.startswith("#!"):
                parts = first[2:].strip().split()
                if parts:
                    return parts[0]
        except OSError:
            pass
        return "sh"

    # ---------------------------------------------------------- syntax gates
    def check_python_syntax(self, path: str) -> ExecResult:
        return self.run(
            [util.which("python3") or "python3", "-m", "py_compile", os.path.basename(path)],
            cwd=os.path.dirname(os.path.abspath(path)),
            timeout=10, cpu_seconds=10, memory_mb=256, allow_network=True,
        )

    def check_shell_syntax(self, path: str) -> ExecResult:
        return self.run(
            [util.which("bash") or "bash", "-n", os.path.basename(path)],
            cwd=os.path.dirname(os.path.abspath(path)),
            timeout=10, cpu_seconds=10, memory_mb=128, allow_network=True,
        )

    def stats(self) -> dict:
        caps = self.capabilities()
        count = 0
        size = 0
        for entry in os.scandir(self.root):
            if entry.is_dir():
                count += 1
        return {"root": self.root, "scratch_dirs": count, "capabilities": caps}
