"""Security subsystem: firewall control, ban bookkeeping, config audit.

Firewall backends are capability-detected, never assumed:

    nft        preferred on modern hosts, requires root + nft binary
    iptables   legacy host fallback, requires root
    recorder   no privileges: writes an auditable intent record and reports
               "simulated" instead of pretending a rule exists

The recorder backend exists because silently failing to ban while claiming
success is worse than not banning at all. It is also what makes the whole
system testable in an unprivileged container.

Self-lockout protection is mandatory: loopback, RFC1918, CGNAT, link-local,
multicast and the agent's own IPs can never be banned. A compromised-but-alive
box is better than a box you cannot SSH into.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import threading
from typing import Optional

from . import util
from .config import Config
from .models import Finding


class Firewall:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self._log = logger or logging.getLogger("autonomic.security")
        self.state_dir = os.path.join(config.get("agent.data_dir"), "security")
        util.ensure_dir(self.state_dir, 0o750)
        self.state_path = os.path.join(self.state_dir, "bans.json")
        self.recorder_path = os.path.join(self.state_dir, "firewall-intents.jsonl")
        self.backend = self._detect_backend()
        self._lock = threading.Lock()
        self._bans: dict[str, dict] = {}
        self._load()

    # -------------------------------------------------------------- backend
    def _detect_backend(self) -> str:
        requested = str(self.config.get("security.firewall_backend", "auto"))
        is_root = util.is_root()
        dry = bool(self.config.get("policy.dry_run", False))
        if requested == "recorder" or dry:
            return "recorder"
        has_nft = util.which("nft") is not None
        has_iptables = util.which("iptables") is not None
        if requested == "nft":
            if has_nft and is_root:
                return "nft"
            self._log.warning("nft requested but unavailable (root=%s nft=%s); falling back to recorder", is_root, has_nft)
            return "recorder"
        if requested == "iptables":
            if has_iptables and is_root:
                return "iptables"
            self._log.warning("iptables requested but unavailable (root=%s); falling back to recorder", is_root)
            return "recorder"
        if has_nft and is_root:
            return "nft"
        if has_iptables and is_root:
            return "iptables"
        return "recorder"

    @property
    def simulated(self) -> bool:
        return self.backend == "recorder"

    # ------------------------------------------------------------------ bans
    def _load(self) -> None:
        data = util.json_loads(util.read_text(self.state_path), {}) or {}
        self._bans = data.get("bans", {}) if isinstance(data, dict) else {}
        # drop expired entries
        now = util.now()
        self._bans = {ip: rec for ip, rec in self._bans.items() if rec.get("expires_at", 0) > now}
        self._persist()

    def _persist(self) -> None:
        payload = {"backend": self.backend, "updated_at": util.iso(), "bans": self._bans}
        util.atomic_write(self.state_path, util.json_dumps(payload, pretty=True), mode=0o600)

    def guard_ip(self, ip: str) -> tuple[bool, str]:
        ip = str(ip).strip()
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return False, "not a valid IP address"
        # Only globally-routable addresses may be banned. ``is_global`` is False
        # for loopback, RFC1918, CGNAT, link-local, multicast, documentation and
        # reserved ranges alike, so one rule covers all of them. A typo or a
        # hostile input can therefore never lock the operator out of the box.
        if not parsed.is_global:
            if self.config.get("security.protect_private_ips", True):
                return False, "non-global (private/loopback/link-local/reserved) address is protected by policy"
        if ip in set(util.local_ips()):
            return False, "refusing to ban the agent's own address"
        return True, "ok"

    def ban(self, ip: str, reason: str = "", duration: Optional[int] = None) -> dict:
        ok, why = self.guard_ip(ip)
        if not ok:
            return {"ok": False, "backend": self.backend, "ip": ip, "error": why, "simulated": self.simulated}
        duration = int(duration or self.config.get("security.ban_duration", 3600))
        with self._lock:
            if ip in self._bans:
                existing = self._bans[ip]
                remaining = max(0, int(existing.get("expires_at", 0) - util.now()))
                return {"ok": True, "backend": self.backend, "ip": ip, "already_banned": True,
                        "simulated": self.simulated, "bans": len(self._bans),
                        "command": existing.get("command", ""), "verified": existing.get("verified"),
                        "expires_in": remaining, "detail": "ban already active; no new firewall rule applied"}
            command = ""
            result_ok = True
            detail = ""
            if self.backend == "nft":
                self._ensure_nft_table()
                command = f"nft add rule inet filter input ip saddr {ip} counter drop"
                result_ok, detail = self._run(command)
            elif self.backend == "iptables":
                command = f"iptables -I INPUT -s {ip} -j DROP"
                result_ok, detail = self._run(command)
            else:
                command = f"SIMULATED: iptables -I INPUT -s {ip} -j DROP"
                detail = "no privilege: intent recorded only, host firewall unchanged"
            if not result_ok:
                return {"ok": False, "backend": self.backend, "ip": ip, "error": detail, "command": command,
                        "simulated": self.simulated}
            record = {
                "ip": ip,
                "reason": reason,
                "created_at": util.now(),
                "created_iso": util.iso(),
                "expires_at": util.now() + duration,
                "duration": duration,
                "backend": self.backend,
                "command": command,
                "simulated": self.simulated,
                "verified": False,
            }
            record["verified"] = self._verify(ip) if self.backend != "recorder" else False
            self._bans[ip] = record
            self._persist()
            with open(self.recorder_path, "a", encoding="utf-8") as fh:
                fh.write(util.json_dumps(record) + "\n")
        self._log.warning("ban ip=%s backend=%s simulated=%s reason=%s", ip, self.backend, self.simulated,
                          util.redact(reason)[:160])
        return {"ok": True, "backend": self.backend, "ip": ip, "command": command, "detail": detail,
                "simulated": self.simulated, "verified": record["verified"], "expires_in": duration}

    def unban(self, ip: str, reason: str = "manual") -> dict:
        with self._lock:
            record = self._bans.pop(ip, None)
            if not record:
                return {"ok": True, "ip": ip, "already_absent": True, "backend": self.backend}
            command = ""
            detail = ""
            ok = True
            if self.backend == "nft":
                handle = self._nft_handle_for(ip)
                if handle is None:
                    command = f"nft delete rule inet filter input ip saddr {ip} counter drop"
                    ok, detail = True, "no matching nft rule found (already absent)"
                else:
                    command = f"nft delete rule inet filter input handle {handle}"
                    ok, detail = self._run(command)
            elif self.backend == "iptables":
                command = f"iptables -D INPUT -s {ip} -j DROP"
                ok, detail = self._run(command)
            else:
                command = f"SIMULATED: iptables -D INPUT -s {ip} -j DROP"
                detail = "no privilege: intent record removed only"
            self._persist()
            with open(self.recorder_path, "a", encoding="utf-8") as fh:
                fh.write(util.json_dumps({"event": "unban", "ip": ip, "reason": reason, "ts": util.iso(),
                                          "backend": self.backend, "command": command}) + "\n")
        self._log.info("unban ip=%s backend=%s reason=%s", ip, self.backend, reason)
        return {"ok": ok, "ip": ip, "backend": self.backend, "command": command, "detail": detail}

    def _run(self, command: str) -> tuple[bool, str]:
        argv = command.split()
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=10, text=True, check=False)
            return proc.returncode == 0, (proc.stderr or proc.stdout).strip()[:400]
        except (subprocess.TimeoutExpired, OSError) as exc:
            return False, str(exc)

    def _nft_handle_for(self, ip: str) -> Optional[int]:
        """Return the nft rule handle matching a banned IP, or None.

        nftables cannot delete a rule by its match expression; deletion is
        handle-based. ``nft delete rule inet filter input ip saddr X ...`` fails
        with "syntax error, unexpected ip, expecting handle", so the handle is
        looked up with ``nft -a list`` first.
        """
        try:
            proc = subprocess.run(["nft", "-a", "list", "table", "inet", "filter"],
                                  capture_output=True, timeout=8, text=True, check=False)
        except (subprocess.TimeoutExpired, OSError):
            return None
        for line in (proc.stdout or "").splitlines():
            if f"saddr {ip}" in line and "# handle" in line:
                try:
                    return int(line.rsplit("# handle", 1)[1].strip())
                except ValueError:
                    return None
        return None

    def _ensure_nft_table(self) -> None:
        """Create the nftables table/base chain we write into, if missing.

        Older builds assumed ``inet filter input`` already existed. That holds on
        hosts configured with nftables, but a stock Ubuntu/Debian box uses
        iptables-nft (ufw) and has no ``inet filter`` table, so
        ``nft add rule inet filter input ...`` failed with
        "Could not process rule: No such file or directory".  Creating the table
        and the base input chain first (ignoring "already exists" errors) makes
        real bans work on a fresh host while leaving an existing ruleset intact.
        """
        subprocess.run(["nft", "add", "table", "inet", "filter"],
                       capture_output=True, timeout=8, check=False)
        subprocess.run(["nft", "add", "chain", "inet", "filter", "input",
                        "{ type filter hook input priority 0 ; policy accept ; }"],
                       capture_output=True, timeout=8, text=True, check=False)

    def _verify(self, ip: str) -> bool:
        if self.backend == "iptables":
            try:
                proc = subprocess.run(["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                                      capture_output=True, timeout=8, check=False)
                return proc.returncode == 0
            except (subprocess.TimeoutExpired, OSError):
                return False
        if self.backend == "nft":
            try:
                proc = subprocess.run(["nft", "list", "table", "inet", "filter"], capture_output=True, timeout=8, text=True, check=False)
                return ip in (proc.stdout or "")
            except (subprocess.TimeoutExpired, OSError):
                return False
        return False

    def is_banned(self, ip: str) -> bool:
        record = self._bans.get(ip)
        return bool(record and record.get("expires_at", 0) > util.now())

    def list_bans(self) -> list[dict]:
        now = util.now()
        return [
            {**rec, "remaining": max(0, int(rec.get("expires_at", now) - now))}
            for rec in sorted(self._bans.values(), key=lambda r: -r.get("created_at", 0))
        ]

    def sweep(self) -> int:
        """Lift expired bans. Called by the daemon ticker."""
        now = util.now()
        expired = [ip for ip, rec in self._bans.items() if rec.get("expires_at", 0) <= now]
        for ip in expired:
            self.unban(ip, reason="expired")
        return len(expired)

    def stats(self) -> dict:
        return {
            "backend": self.backend,
            "simulated": self.simulated,
            "active_bans": len(self._bans),
            "intent_log": self.recorder_path,
        }


class BanPolicy:
    """Rate limiting + hard guards around automated bans."""

    def __init__(self, config: Config):
        self.per_hour = int(config.get("security.max_bans_per_hour", 50))
        self._events: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> tuple[bool, str]:
        with self._lock:
            now = util.now()
            self._events = [t for t in self._events if now - t < 3600]
            if len(self._events) >= self.per_hour:
                return False, f"hourly ban limit ({self.per_hour}) reached"
            self._events.append(now)
            return True, "ok"


class ConfigAuditor:
    """Read-only security posture audit. Findings require human approval to fix."""

    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self._log = logger or logging.getLogger("autonomic.security")

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._audit_ssh())
        findings.extend(self._audit_exposed_ports())
        findings.extend(self._audit_config_permissions())
        if findings:
            self._log.info("config audit produced %d findings", len(findings))
        return findings

    def _audit_ssh(self) -> list[Finding]:
        path = str(self.config.get("security.ssh_config_path", "/etc/ssh/sshd_config"))
        if not os.path.exists(path):
            return [Finding(kind="security.misconfig", target="sshd_config", value="missing",
                            severity="info", detector="config-audit",
                            message=f"sshd_config not found at {path}; audit skipped")]
        text = util.read_text(path)
        out = []
        checks = [
            (r"(?im)^\s*PermitRootLogin\s+yes", "PermitRootLogin is enabled", "high",
             "set 'PermitRootLogin prohibit-password' or 'no'"),
            (r"(?im)^\s*PasswordAuthentication\s+yes", "SSH password authentication is enabled", "medium",
             "prefer key-only authentication"),
            (r"(?im)^\s*PermitEmptyPasswords\s+yes", "empty SSH passwords are permitted", "critical",
             "set 'PermitEmptyPasswords no' immediately"),
            (r"(?im)^\s*X11Forwarding\s+yes", "X11 forwarding is enabled", "low", "disable if unused"),
        ]
        for pattern, message, severity, remedy in checks:
            if re.search(pattern, text):
                out.append(Finding(kind="security.misconfig", target=f"sshd:{message}", value=message,
                                   severity=severity, detector="config-audit",
                                   message=f"{message} ({path}); recommended: {remedy}"))
        return out

    def _audit_exposed_ports(self) -> list[Finding]:
        out = []
        sensitive = {int(p) for p in (self.config.get("security.expose_check_ports", []) or [])}
        try:
            proc = subprocess.run(["ss", "-ltn"], capture_output=True, timeout=8, text=True, check=False)
            lines = proc.stdout.splitlines()
        except (subprocess.TimeoutExpired, OSError):
            return out
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 4:
                continue
            local = parts[3]
            if local.startswith(("0.0.0.0:", "[::]:", "*:")):
                try:
                    port = int(local.rsplit(":", 1)[1])
                except ValueError:
                    continue
                if port in sensitive and port != 22:
                    out.append(Finding(kind="security.misconfig", target=f"port:{port}",
                                       value="publicly_listening", severity="high", detector="config-audit",
                                       message=f"sensitive service port {port} listens on all interfaces; "
                                               f"bind to 127.0.0.1 or firewall it"))
        return out

    def _audit_config_permissions(self) -> list[Finding]:
        out = []
        path = self.config.path
        if path and os.path.exists(path):
            mode = os.stat(path).st_mode & 0o777
            if mode & 0o077:
                out.append(Finding(kind="security.misconfig", target="agent-config", value=oct(mode),
                                   severity="medium", detector="config-audit",
                                   message=f"agent config {path} is readable by group/others (mode {oct(mode)}); "
                                           f"it may contain API keys - chmod 600"))
        return out


class SecurityEngine:
    def __init__(self, config: Config, firewall: Firewall, logger: Optional[logging.Logger] = None):
        self.config = config
        self.firewall = firewall
        self.ban_policy = BanPolicy(config)
        self.auditor = ConfigAuditor(config, logger)
        self._log = logger or logging.getLogger("autonomic.security")
        self.ids_enabled = bool(config.get("security.ids_enabled", True))

    def can_auto_ban(self) -> tuple[bool, str]:
        if not self.config.get("security.auto_ban", False):
            return False, "security.auto_ban is disabled"
        if self.config.get("security.ban_requires_approval", True):
            return False, "security.ban_requires_approval is enabled"
        return self.ban_policy.allow()

    def ban(self, ip: str, reason: str, duration: Optional[int] = None) -> dict:
        ok, why = self.firewall.guard_ip(ip)
        if not ok:
            self._log.warning("ban refused for %s: %s", ip, why)
            return {"ok": False, "ip": ip, "error": why}
        allowed, why2 = self.can_auto_ban()
        if not allowed:
            return {"ok": False, "ip": ip, "error": why2, "requires_approval": True}
        return self.firewall.ban(ip, reason=reason, duration=duration)

    def audit(self) -> list[Finding]:
        if not self.config.get("security.config_audit", True):
            return []
        return self.auditor.audit()

    def stats(self) -> dict:
        return {
            "ids_enabled": self.ids_enabled,
            "auto_ban": self.config.get("security.auto_ban", False),
            "ban_requires_approval": self.config.get("security.ban_requires_approval", True),
            "firewall": self.firewall.stats(),
            "bans": self.firewall.list_bans(),
        }
