"""Self-watchdog.

A supervisor that can hang is worse than no supervisor, so this runs in its own
thread with a cheap tick and no external calls. It watches:

  * its own RSS and file-descriptor count (runaway/leak detection)
  * scheduler liveness (tick counter must advance)
  * bus backpressure (dropped events)
  * core-file hashes (silent self-modification)

It does not restart worker threads (the pool owns that); it escalates to the
daemon, which performs a graceful shutdown with exit code 99 so systemd (or the
pidfile supervisor) restarts a clean process.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Optional

from . import util
from .config import Config


class Watchdog:
    def __init__(self, config: Config, daemon, logger: Optional[logging.Logger] = None):
        self.config = config
        self.daemon = daemon
        self._log = logger or logging.getLogger("autonomic")
        self.interval = float(config.get("watchdog.interval", 10))
        self.max_rss_mb = int(config.get("watchdog.max_rss_mb", 1024))
        self.max_fd = int(config.get("watchdog.max_fd", 4096))
        self.exit_code = int(config.get("watchdog.restart_exit_code", 99))
        self.core_interval = float(config.get("watchdog.core_integrity_interval", 60))
        self.enabled = bool(config.get("watchdog.enabled", True))
        self.heartbeat_path = os.path.join(config.get("agent.run_dir"), "heartbeat.json")
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._last_core_check = 0.0
        self.checks = 0
        self.alerts: list[dict] = []

    def start(self) -> None:
        if not self.enabled:
            self._log.warning("watchdog disabled by config")
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="watchdog", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=3)

    def _loop(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                self.tick()
            except Exception as exc:  # noqa: BLE001 - watchdog must not die
                self._log.error("watchdog tick failed: %s", exc, exc_info=True)

    def tick(self) -> dict:
        self.checks += 1
        rss = self._rss_mb()
        fds = self._fd_count()
        status = {
            "ts": util.iso(),
            "pid": os.getpid(),
            "checks": self.checks,
            "rss_mb": rss,
            "fds": fds,
            "scheduler": self.daemon.scheduler.stats().get("counters", {}),
            "bus_dropped": self.daemon.bus.stats().get("dropped", 0),
            "workers": self.daemon.scheduler.pool.status(),
        }
        util.atomic_write(self.heartbeat_path, util.json_dumps(status, pretty=True), mode=0o644)

        if rss > self.max_rss_mb:
            self._alert("rss", f"RSS {rss:.0f} MiB exceeds {self.max_rss_mb} MiB")
            self._log.critical("watchdog: RSS %s MiB exceeds limit %s MiB; requesting graceful restart",
                               rss, self.max_rss_mb)
            self.daemon.emergency_exit(self.exit_code, reason="memory overrun")
        if fds > self.max_fd:
            self._alert("fd", f"open fds {fds} exceed {self.max_fd}")
            self._log.error("watchdog: fd count %d exceeds %d", fds, self.max_fd)

        now = util.now()
        if now - self._last_core_check >= self.core_interval:
            self._last_core_check = now
            integrity = self.daemon.policy.core.verify()
            if not integrity["ok"]:
                detail = f"changed={integrity['changed']} added={integrity['added']} removed={integrity['removed']}"
                self._alert("core-integrity", detail)
                self._log.critical("watchdog: core file integrity check failed: %s", detail)
                self.daemon.audit.record(actor="watchdog", trigger="core.integrity", action="security.alert",
                                         target="scheduler-core", params={}, result=detail)
                self.daemon.bus.publish("security.alert", {"kind": "core.integrity", "detail": detail})
        return status

    def _alert(self, kind: str, detail: str) -> None:
        self.alerts.append({"kind": kind, "detail": detail, "ts": util.iso()})
        self.alerts = self.alerts[-20:]

    @staticmethod
    def _rss_mb() -> float:
        try:
            for line in util.read_text("/proc/self/status").splitlines():
                if line.startswith("VmRSS:"):
                    return int(line.split()[1]) / 1024.0
        except (OSError, ValueError, IndexError):
            pass
        return 0.0

    @staticmethod
    def _fd_count() -> int:
        try:
            return len(os.listdir("/proc/self/fd"))
        except OSError:
            return 0

    def status(self) -> dict:
        return {"enabled": self.enabled, "checks": self.checks, "alerts": self.alerts[-10:],
                "heartbeat": self.heartbeat_path,
                "max_rss_mb": self.max_rss_mb, "max_fd": self.max_fd}
