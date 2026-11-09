"""Fault detection.

Detectors are pure functions of a metrics sample (plus optional state) that
return ``Finding`` objects. They never act: acting is the rule engine's and
policy gate's job. That separation is what makes "detect -> grade -> approve ->
execute -> audit -> rollback" auditable.

Sustained-threshold logic matters for load/disk/memory: a single spike must not
trigger remediation. The engine requires N consecutive breaching samples
(``metrics.sustained_samples``) before emitting.
"""

from __future__ import annotations

import logging
import threading
from typing import Callable, Optional

from . import util
from .config import Config
from .models import Finding, severity_rank


class _Sustained:
    def __init__(self, need: int):
        self.need = max(1, need)
        self.counts: dict[str, int] = {}

    def hit(self, key: str) -> bool:
        self.counts[key] = self.counts.get(key, 0) + 1
        return self.counts[key] >= self.need

    def clear(self, key: str) -> None:
        self.counts.pop(key, None)


class DetectorEngine:
    def __init__(self, config: Config, bus, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self._log = logger or logging.getLogger("autonomic.metrics")
        self._detectors: dict[str, Callable[[dict], list[Finding]]] = {}
        self._lock = threading.RLock()
        self._cooldowns: dict[str, float] = {}
        self.cooldown = float(config.get("metrics.detector_cooldown", 300) or 300)
        self.sustained = _Sustained(int(config.get("metrics.sustained_samples", 3)))
        self.emitted = 0
        self.suppressed = 0
        self.last_errors: list[dict] = []
        self._register_builtin()

    # -------------------------------------------------------------- registry
    def register(self, name: str, fn: Callable[[dict], list[Finding]]) -> None:
        with self._lock:
            self._detectors[name] = fn

    def unregister(self, name: str) -> None:
        with self._lock:
            self._detectors.pop(name, None)

    def detector_names(self) -> list[str]:
        with self._lock:
            return sorted(self._detectors)

    def _register_builtin(self) -> None:
        self.register("load", self._detect_load)
        self.register("memory", self._detect_memory)
        self.register("disk", self._detect_disk)
        self.register("port", self._detect_ports)
        self.register("process", self._detect_processes)
        self.register("unit", self._detect_units)
        self.register("ssh", self._detect_ssh)
        self.register("conn", self._detect_connections)
        self.register("traffic", self._detect_traffic)

    # ------------------------------------------------------------------ feed
    def on_sample(self, sample: dict) -> list[Finding]:
        findings: list[Finding] = []
        with self._lock:
            detectors = list(self._detectors.items())
        for name, fn in detectors:
            try:
                produced = fn(sample) or []
                findings.extend(produced)
            except Exception as exc:  # noqa: BLE001 - one bad detector must not stop the rest
                self._log.error("detector %s failed: %s", name, exc, exc_info=True)
                self.last_errors.append({"detector": name, "error": util.redact(str(exc)), "ts": util.iso()})
                self.last_errors = self.last_errors[-10:]
        for finding in findings:
            if self._should_emit(finding):
                self.emitted += 1
                self.bus.publish("detect.finding", {"finding": finding.to_dict(), "finding_obj": finding})
                self._log.info(
                    "finding kind=%s target=%s severity=%s value=%s detector=%s",
                    finding.kind, finding.target, finding.severity, _short(finding.value), finding.detector,
                )
            else:
                self.suppressed += 1
        return findings

    def plugin_finding(self, finding: Finding) -> None:
        """Plugins may emit findings outside the sample cadence."""
        if self._should_emit(finding):
            self.emitted += 1
            self.bus.publish("detect.finding", {"finding": finding.to_dict(), "finding_obj": finding})
            self._log.info("finding(plugin) kind=%s target=%s severity=%s", finding.kind, finding.target, finding.severity)

    def _should_emit(self, finding: Finding) -> bool:
        key = finding.dedupe_key
        last = self._cooldowns.get(key)
        now = util.now()
        if last and now - last < self.cooldown:
            # allow a severity escalation through even inside cooldown
            if severity_rank(finding.severity) < 3:
                return False
        self._cooldowns[key] = now
        if len(self._cooldowns) > 5000:
            cutoff = now - self.cooldown * 4
            self._cooldowns = {k: v for k, v in self._cooldowns.items() if v >= cutoff}
        return True

    # ------------------------------------------------------------- built-ins
    def _detect_load(self, sample: dict) -> list[Finding]:
        load = sample.get("load", {})
        value = float(load.get("load1", 0.0))
        warn = float(self.config.get("metrics.load_warn", 4.0))
        crit = float(self.config.get("metrics.load_critical", 8.0))
        if value >= crit and self.sustained.hit("load:crit"):
            return [Finding(kind="load.high", target=sample.get("host", "host"), value=value,
                            severity="critical", detector="load",
                            message=f"1-minute load {value} >= critical {crit}")]
        if value >= warn and self.sustained.hit("load:warn"):
            self.sustained.clear("load:crit")
            return [Finding(kind="load.high", target=sample.get("host", "host"), value=value,
                            severity="high", detector="load",
                            message=f"1-minute load {value} >= warn {warn}")]
        if value < warn:
            self.sustained.clear("load:warn")
            self.sustained.clear("load:crit")
        return []

    def _detect_memory(self, sample: dict) -> list[Finding]:
        mem = sample.get("memory", {})
        percent = float(mem.get("percent", 0.0))
        warn = float(self.config.get("metrics.mem_warn_percent", 85))
        crit = float(self.config.get("metrics.mem_critical_percent", 95))
        if percent >= crit and self.sustained.hit("mem:crit"):
            return [Finding(kind="memory.high", target=sample.get("host", "host"), value=percent,
                            severity="critical", detector="memory",
                            message=f"memory usage {percent}% >= critical {crit}%")]
        if percent >= warn and self.sustained.hit("mem:warn"):
            self.sustained.clear("mem:crit")
            return [Finding(kind="memory.high", target=sample.get("host", "host"), value=percent,
                            severity="high", detector="memory",
                            message=f"memory usage {percent}% >= warn {warn}%")]
        if percent < warn:
            self.sustained.clear("mem:warn")
            self.sustained.clear("mem:crit")
        return []

    def _detect_disk(self, sample: dict) -> list[Finding]:
        findings = []
        warn = float(self.config.get("metrics.disk_warn_percent", 80))
        crit = float(self.config.get("metrics.disk_critical_percent", 92))
        for disk in sample.get("disks", []):
            key = f"disk:{disk['path']}"
            percent = float(disk.get("percent", 0))
            if percent >= crit and self.sustained.hit(key + ":crit"):
                findings.append(Finding(kind="disk.high", target=disk["path"], value=percent,
                                        severity="critical", detector="disk",
                                        message=f"{disk['path']} usage {percent}% >= critical {crit}%",
                                        evidence={"disk": disk}))
            elif percent >= warn and self.sustained.hit(key + ":warn"):
                self.sustained.clear(key + ":crit")
                findings.append(Finding(kind="disk.high", target=disk["path"], value=percent,
                                        severity="high", detector="disk",
                                        message=f"{disk['path']} usage {percent}% >= warn {warn}%",
                                        evidence={"disk": disk}))
            if percent < warn:
                self.sustained.clear(key + ":warn")
                self.sustained.clear(key + ":crit")
        return findings

    def _detect_ports(self, sample: dict) -> list[Finding]:
        findings = []
        for port in sample.get("ports", []):
            if port.get("open"):
                continue
            findings.append(Finding(
                kind="port.closed", target=str(port.get("name")), value=port.get("port"),
                severity="high" if port.get("critical") else "medium", detector="port",
                message=f"expected port {port.get('host')}:{port.get('port')} is closed",
                evidence={"port": port},
            ))
        return findings

    def _detect_processes(self, sample: dict) -> list[Finding]:
        findings = []
        for proc in sample.get("processes", []):
            if proc.get("alive"):
                continue
            findings.append(Finding(
                kind="process.absent", target=str(proc.get("name")), value="absent",
                severity="high", detector="process",
                message=f"watched process '{proc.get('name')}' is not running",
                evidence={"process": proc},
            ))
        return findings

    def _detect_units(self, sample: dict) -> list[Finding]:
        findings = []
        for unit in sample.get("units", []):
            if unit.get("active") is False:
                findings.append(Finding(
                    kind="unit.inactive", target=str(unit.get("unit")), value=unit.get("state", "inactive"),
                    severity="high", detector="unit",
                    message=f"systemd unit '{unit.get('unit')}' is not active",
                    evidence={"unit": unit},
                ))
        return findings

    def _detect_ssh(self, sample: dict) -> list[Finding]:
        threshold = int(self.config.get("metrics.ssh_fail_threshold", 5))
        findings = []
        ssh = sample.get("ssh", {})
        for entry in ssh.get("failed_by_ip", []):
            if int(entry.get("count", 0)) >= threshold:
                findings.append(Finding(
                    kind="ssh.bruteforce", target=str(entry["ip"]), value=int(entry["count"]),
                    severity="high", detector="ssh",
                    message=f"{entry['count']} failed SSH logins from {entry['ip']} (threshold {threshold})",
                    evidence={"source": ssh.get("source"), "window_seconds": ssh.get("window_seconds"),
                              "note": ssh.get("note")},
                ))
        return findings

    def _detect_connections(self, sample: dict) -> list[Finding]:
        threshold = int(self.config.get("metrics.conn_per_ip_threshold", 100))
        findings = []
        for entry in sample.get("connections", {}).get("per_ip", []):
            if int(entry.get("count", 0)) >= threshold:
                findings.append(Finding(
                    kind="conn.flood", target=str(entry["ip"]), value=int(entry["count"]),
                    severity="high", detector="conn",
                    message=f"{entry['count']} established connections from {entry['ip']} (threshold {threshold})",
                ))
        return findings

    def _detect_traffic(self, sample: dict) -> list[Finding]:
        threshold = float(self.config.get("metrics.traffic_warn_mbps", 100))
        net = sample.get("network", {})
        peak = max(float(net.get("rx_mbps", 0)), float(net.get("tx_mbps", 0)))
        if peak >= threshold and self.sustained.hit("traffic"):
            return [Finding(kind="traffic.high", target=sample.get("host", "host"), value=peak,
                            severity="medium", detector="traffic",
                            message=f"network throughput {peak} Mbps >= {threshold} Mbps")]
        if peak < threshold * 0.8:
            self.sustained.clear("traffic")
        return []

    # ----------------------------------------------------------------- stats
    def stats(self) -> dict:
        return {
            "detectors": self.detector_names(),
            "emitted": self.emitted,
            "suppressed_by_cooldown": self.suppressed,
            "cooldown_seconds": self.cooldown,
            "recent_errors": self.last_errors,
        }


def _short(value, limit: int = 60) -> str:
    text = str(value)
    return text if len(text) <= limit else text[:limit] + "..."
