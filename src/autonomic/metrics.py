"""Metric collection straight from /proc, /sys and the auth log.

No psutil, no external agent: a small VPS may have no package manager access,
and the whole point is that this runs on a blank box. Everything here is read
from kernel interfaces that exist on any Linux host.

Sampling is cheap enough to run every 10s on a 1-vCPU box: directory scans are
bounded, auth logs are read from a tail window, and connections are parsed
from /proc/net/tcp without shelling out.
"""

from __future__ import annotations

import glob
import logging
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from collections import deque
from typing import Optional

from . import util
from .config import Config

_FAIL_RE = re.compile(r"Failed password for (?:invalid user )?([^\s]+) from ([\d.]+)")
_INVALID_RE = re.compile(r"Invalid user ([^\s]+) from ([\d.]+)")
_ACCEPT_RE = re.compile(r"Accepted \S+ for ([^\s]+) from ([\d.]+)")


class MetricsCollector:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self._log = logger or logging.getLogger("autonomic.metrics")
        self._prev_cpu: Optional[tuple[int, int]] = None
        self._prev_net: Optional[tuple[float, int, int]] = None
        self._lock = threading.Lock()

    # ------------------------------------------------------------- top level
    def sample(self) -> dict:
        with self._lock:
            started = time.time()
            data = {
                "ts": started,
                "ts_iso": util.iso(started),
                "host": self.config.get("agent.node_id"),
                "uptime_seconds": self._uptime(),
                "cpu": self._cpu(),
                "load": self._load(),
                "memory": self._memory(),
                "disks": self._disks(),
                "network": self._network(),
                "ports": self._ports(),
                "processes": self._processes(),
                "units": self._units(),
                "connections": self._connections(),
                "ssh": self._ssh(),
                "systemd_online": os.path.isdir("/run/systemd/system"),
                "collect_ms": round((time.time() - started) * 1000, 1),
            }
            return data

    # ------------------------------------------------------------------ cpu
    def _cpu(self) -> dict:
        try:
            with open("/proc/stat", "r", encoding="utf-8") as fh:
                fields = fh.readline().split()
            values = [int(v) for v in fields[1:]]
            idle = values[3] + (values[4] if len(values) > 4 else 0)
            total = sum(values)
            if self._prev_cpu:
                d_total = total - self._prev_cpu[0]
                d_idle = idle - self._prev_cpu[1]
                percent = 0.0 if d_total <= 0 else max(0.0, min(100.0, 100.0 * (d_total - d_idle) / d_total))
            else:
                percent = 0.0
            self._prev_cpu = (total, idle)
            return {"percent": round(percent, 1), "cores": util.cpu_count()}
        except (OSError, ValueError, IndexError) as exc:
            self._log.warning("cpu read failed: %s", exc)
            return {"percent": 0.0, "cores": util.cpu_count(), "error": str(exc)}

    def _load(self) -> dict:
        try:
            one, five, fifteen = open("/proc/loadavg", "r", encoding="utf-8").read().split()[:3]
            return {"load1": float(one), "load5": float(five), "load15": float(fifteen),
                    "per_core": round(float(one) / max(1, util.cpu_count()), 2)}
        except (OSError, ValueError):
            return {"load1": 0.0, "load5": 0.0, "load15": 0.0, "per_core": 0.0}

    def _memory(self) -> dict:
        info = {}
        try:
            with open("/proc/meminfo", "r", encoding="utf-8") as fh:
                for line in fh:
                    key, _, rest = line.partition(":")
                    info[key.strip()] = int(rest.strip().split()[0]) * 1024
        except (OSError, ValueError):
            return {"total": 0, "available": 0, "used": 0, "percent": 0.0}
        total = info.get("MemTotal", 0)
        available = info.get("MemAvailable", info.get("MemFree", 0))
        used = max(0, total - available)
        percent = round(100.0 * used / total, 1) if total else 0.0
        swap_total = info.get("SwapTotal", 0)
        swap_free = info.get("SwapFree", 0)
        return {
            "total": total,
            "available": available,
            "used": used,
            "percent": percent,
            "swap_total": swap_total,
            "swap_percent": round(100.0 * (swap_total - swap_free) / swap_total, 1) if swap_total else 0.0,
        }

    # ----------------------------------------------------------------- disk
    def _disks(self) -> list[dict]:
        out = []
        for path in self.config.get("metrics.disk_paths", []) or []:
            try:
                usage = shutil.disk_usage(path)
            except OSError:
                continue
            # Match `df` Use% semantics: df reports used / (used + available),
            # where "available" excludes blocks reserved for root (typically 5%
            # on ext4). Reporting used/total would under-report by the reserved
            # fraction and blind the agent exactly when an operator watching df
            # expects it to act.
            denom = usage.used + usage.free
            percent = round(100.0 * usage.used / denom, 1) if denom else 0.0
            out.append({
                "path": path,
                "total": usage.total,
                "used": usage.used,
                "free": usage.free,
                "percent": percent,
            })
        return out

    # -------------------------------------------------------------- network
    def _network(self) -> dict:
        interfaces = {}
        try:
            with open("/proc/net/dev", "r", encoding="utf-8") as fh:
                lines = fh.readlines()[2:]
            total_rx = total_tx = 0
            for line in lines:
                name, _, rest = line.partition(":")
                fields = rest.split()
                if len(fields) < 9:
                    continue
                rx, tx = int(fields[0]), int(fields[8])
                interfaces[name.strip()] = {"rx_bytes": rx, "tx_bytes": tx}
                if name.strip() != "lo":
                    total_rx += rx
                    total_tx += tx
        except (OSError, ValueError, IndexError) as exc:
            return {"error": str(exc), "interfaces": {}, "rx_rate": 0.0, "tx_rate": 0.0}

        now = time.time()
        rx_rate = tx_rate = 0.0
        if self._prev_net:
            prev_ts, prev_rx, prev_tx = self._prev_net
            delta = max(0.001, now - prev_ts)
            rx_rate = max(0.0, (total_rx - prev_rx) / delta)
            tx_rate = max(0.0, (total_tx - prev_tx) / delta)
        self._prev_net = (now, total_rx, total_tx)
        return {
            "interfaces": interfaces,
            "rx_bytes": total_rx,
            "tx_bytes": total_tx,
            "rx_rate": round(rx_rate, 1),
            "tx_rate": round(tx_rate, 1),
            "rx_mbps": round(rx_rate * 8 / 1_000_000, 3),
            "tx_mbps": round(tx_rate * 8 / 1_000_000, 3),
        }

    # ---------------------------------------------------------------- ports
    def _ports(self) -> list[dict]:
        results = []
        for item in self.config.get("metrics.watch_ports", []) or []:
            host = str(item.get("host", "127.0.0.1"))
            port = util.parse_int(item.get("port"), 0, 1, 65535)
            if not port:
                continue
            started = time.time()
            is_open = False
            error = ""
            try:
                with socket.create_connection((host, port), timeout=1.0):
                    is_open = True
            except (ConnectionRefusedError, socket.timeout, OSError) as exc:
                error = type(exc).__name__
            results.append({
                "name": item.get("name") or f"{host}:{port}",
                "host": host,
                "port": port,
                "open": is_open,
                "latency_ms": round((time.time() - started) * 1000, 1),
                "critical": bool(item.get("critical", False)),
                "error": "" if is_open else error,
            })
        return results

    # ------------------------------------------------------------ processes
    def _processes(self) -> list[dict]:
        targets = self.config.get("metrics.watch_processes", []) or []
        if not targets:
            return []
        found: dict[str, list[dict]] = {str(t.get("name", "")): [] for t in targets}
        for pid_dir in glob.glob("/proc/[0-9]*"):
            pid = os.path.basename(pid_dir)
            try:
                with open(os.path.join(pid_dir, "comm"), "r", encoding="utf-8", errors="replace") as fh:
                    comm = fh.read().strip()
                with open(os.path.join(pid_dir, "cmdline"), "rb") as fh:
                    cmdline = fh.read(4096).replace(b"\x00", b" ").decode("utf-8", "replace").strip()
            except (OSError, ValueError):
                continue
            if not comm:
                continue
            statm = self._statm(pid)
            for target in targets:
                name = str(target.get("name", ""))
                pattern = target.get("match") or name
                try:
                    hit = bool(re.search(str(pattern), comm, re.I) or re.search(str(pattern), cmdline, re.I))
                except re.error:
                    hit = (str(pattern) == comm)
                if hit:
                    found.setdefault(name, []).append({
                        "pid": int(pid),
                        "comm": comm,
                        "cmdline": cmdline[:200],
                        "rss_bytes": statm.get("rss_bytes", 0),
                    })
        out = []
        for target in targets:
            name = str(target.get("name", ""))
            pids = found.get(name, [])
            pidfile = target.get("pidfile")
            pidfile_alive = None
            if pidfile:
                pidfile_alive = self._pidfile_alive(str(pidfile))
            out.append({
                "name": name,
                "alive": bool(pids) if pidfile_alive is None else bool(pidfile_alive),
                "matched": pids[:10],
                "pidfile": pidfile,
                "pidfile_alive": pidfile_alive,
            })
        return out

    @staticmethod
    def _statm(pid: str) -> dict:
        try:
            with open(f"/proc/{pid}/statm", "r", encoding="utf-8") as fh:
                fields = fh.read().split()
            page = os.sysconf("SC_PAGE_SIZE")
            return {"rss_bytes": int(fields[1]) * page}
        except (OSError, ValueError, IndexError):
            return {}

    def _pidfile_alive(self, path: str) -> bool:
        try:
            pid = int(util.read_text(path).strip())
            return os.path.exists(f"/proc/{pid}")
        except (ValueError, OSError):
            return False

    # ---------------------------------------------------------------- units
    def _units(self) -> list[dict]:
        units = self.config.get("metrics.watch_units", []) or []
        out = []
        for unit in units:
            unit = str(unit)
            if not os.path.isdir("/run/systemd/system"):
                out.append({"unit": unit, "active": None, "note": "systemd offline"})
                continue
            try:
                proc = subprocess.run(
                    ["systemctl", "is-active", unit], capture_output=True, timeout=5, check=False,
                    text=True,
                )
                out.append({"unit": unit, "active": proc.stdout.strip() == "active",
                            "state": proc.stdout.strip()})
            except (subprocess.TimeoutExpired, OSError) as exc:
                out.append({"unit": unit, "active": None, "note": str(exc)})
        return out

    # ---------------------------------------------------------- connections
    def _connections(self) -> dict:
        per_ip: dict[str, int] = {}
        total = established = 0
        for path in ("/proc/net/tcp", "/proc/net/tcp6"):
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    lines = fh.readlines()[1:]
            except OSError:
                continue
            for line in lines:
                fields = line.split()
                if len(fields) < 4:
                    continue
                total += 1
                if fields[3] != "01":  # 01 = ESTABLISHED
                    continue
                established += 1
                ip = self._decode_proc_ip(fields[2])
                if ip and not ip.startswith(("127.", "0.0.0.0", "::")):
                    per_ip[ip] = per_ip.get(ip, 0) + 1
        ordered = sorted(per_ip.items(), key=lambda kv: -kv[1])
        return {
            "total": total,
            "established": established,
            "unique_peers": len(per_ip),
            "per_ip": [{"ip": ip, "count": count} for ip, count in ordered[:20]],
            "top_count": ordered[0][1] if ordered else 0,
        }

    @staticmethod
    def _decode_proc_ip(field: str) -> str:
        try:
            addr, _port = field.split(":")
            if len(addr) == 8:
                raw = bytes.fromhex(addr)
                octets = [raw[3], raw[2], raw[1], raw[0]]
                return ".".join(str(b) for b in octets)
            if len(addr) == 32:
                # IPv6: show as compressed-ish placeholder; we only need identity
                raw = bytes.fromhex(addr)
                parts = [raw[i:i + 2].hex() for i in range(0, 16, 2)]
                return ":".join(parts)
        except (ValueError, IndexError):
            return ""
        return ""

    # ----------------------------------------------------------------- ssh
    def _ssh(self) -> dict:
        window = int(self.config.get("metrics.ssh_fail_window", 600))
        max_bytes = int(self.config.get("metrics.auth_log_max_bytes", 4 * 1024 * 1024))
        failures: dict[str, int] = {}
        success: dict[str, int] = {}
        failed_total = success_total = 0
        source = ""
        for path in self.config.get("metrics.ssh_log_paths", []) or []:
            if not os.path.exists(path) or not os.access(path, os.R_OK):
                continue
            try:
                with open(path, "rb") as fh:
                    fh.seek(0, os.SEEK_END)
                    size = fh.tell()
                    fh.seek(max(0, size - max_bytes))
                    blob = fh.read(max_bytes).decode("utf-8", "replace")
            except OSError:
                continue
            source = path
            for user, ip in _FAIL_RE.findall(blob):
                failures[ip] = failures.get(ip, 0) + 1
                failed_total += 1
            for user, ip in _INVALID_RE.findall(blob):
                failures[ip] = failures.get(ip, 0) + 1
                failed_total += 1
            for user, ip in _ACCEPT_RE.findall(blob):
                success[ip] = success.get(ip, 0) + 1
                success_total += 1
            break  # first readable log wins; avoid double counting rotated copies
        return {
            "source": source,
            "failed_total": failed_total,
            "success_total": success_total,
            "failed_by_ip": [{"ip": ip, "count": n} for ip, n in sorted(failures.items(), key=lambda kv: -kv[1])[:20]],
            "success_by_ip": [{"ip": ip, "count": n} for ip, n in sorted(success.items(), key=lambda kv: -kv[1])[:20]],
            "window_seconds": window,
            "note": "counts are parsed from the tail window of the first readable auth log; "
                    "verify against your journal retention before acting",
        }

    @staticmethod
    def _uptime() -> float:
        try:
            return float(open("/proc/uptime", "r", encoding="utf-8").read().split()[0])
        except (OSError, ValueError, IndexError):
            return 0.0


class MetricsSampler:
    """Periodic sampler with an in-memory ring buffer and bus publication."""

    def __init__(self, config: Config, bus, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self.collector = MetricsCollector(config, logger)
        self.interval = float(config.get("metrics.interval", 10))
        self.history = deque(maxlen=720)
        self.latest: Optional[dict] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._log = logger or logging.getLogger("autonomic.metrics")
        self._seeded = False

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="metrics-sampler", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _loop(self) -> None:
        # first sample immediately, then at the configured cadence
        while not self._stop.is_set():
            started = time.time()
            try:
                sample = self.collector.sample()
                self.latest = sample
                self.history.append(sample)
                self.bus.publish("metrics.sample", {"sample": sample})
                if not self._seeded or int(started) % 60 < self.interval:
                    self._log.info(
                        "sample cpu=%.1f%% load1=%.2f mem=%.1f%% disk=%s ports_down=%d conns=%d",
                        sample["cpu"]["percent"], sample["load"]["load1"], sample["memory"]["percent"],
                        ",".join(f"{d['path']}:{d['percent']}%" for d in sample["disks"]) or "-",
                        sum(1 for p in sample["ports"] if not p["open"]),
                        sample["connections"]["established"],
                    )
                self._seeded = True
            except Exception as exc:  # noqa: BLE001 - sampler must survive
                self._log.error("metrics sampling failed: %s", exc, exc_info=True)
            elapsed = time.time() - started
            self._stop.wait(max(0.5, self.interval - elapsed))

    def stats(self) -> dict:
        latest = self.latest or {}
        return {
            "interval": self.interval,
            "samples": len(self.history),
            "latest_ts": latest.get("ts_iso"),
            "cpu_percent": latest.get("cpu", {}).get("percent"),
            "load1": latest.get("load", {}).get("load1"),
            "mem_percent": latest.get("memory", {}).get("percent"),
            "collect_ms": latest.get("collect_ms"),
            "disk": latest.get("disks", []),
            "ports": latest.get("ports", []),
            "connections": latest.get("connections", {}),
        }
