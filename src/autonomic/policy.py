"""Policy gate - the single choke point every mutation must pass through.

Grading model (deliberately deny-by-default for automation):

    low / medium  + in whitelist + auto_remediate on  -> execute automatically
    anything else                                    -> do NOT execute;
                                                        persist a proposal,
                                                        wait for CLI approval
    forbidden path / core file / rate limited        -> hard deny

The important nuance: an action being *whitelisted* is not enough on its own.
It must also be at or below ``policy.max_auto_risk``. A user who whitelists
``firewall.ban_ip`` still needs ``max_auto_risk: high`` before the agent will
ban an IP unattended. This prevents a careless whitelist edit from silently
arming destructive automation.
"""

from __future__ import annotations

import glob
import json
import logging
import os
import re
import threading
from typing import Iterable, Optional

from . import util
from .config import Config
from .errors import PolicyDenied
from .models import ActionRequest, PolicyDecision

RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

DEFAULT_RISK = {
    "noop": "low",
    "notify": "low",
    "diagnostic": "low",
    "log.rotate": "low",
    "cache.cleanup": "low",
    "plugin.action": "medium",
    "disk.cleanup": "medium",
    "process.restart": "medium",
    "service.restart": "medium",
    "code.patch": "high",
    "plugin.install": "high",
    "firewall.ban_ip": "high",
    "firewall.unban_ip": "medium",
    "file.delete": "high",
    "system.config.modify": "high",
    "package.install": "high",
    "shell.exec": "high",
    "sudo.modify": "critical",
    "core.self_modify": "critical",
}


class RateLimiter:
    def __init__(self, per_minute: int):
        self.per_minute = max(1, per_minute)
        self._events: list[float] = []
        self._lock = threading.Lock()

    def allow(self) -> bool:
        with self._lock:
            now = util.now()
            self._events = [t for t in self._events if now - t < 60]
            if len(self._events) >= self.per_minute:
                return False
            self._events.append(now)
            return True


class CoreIntegrity:
    """Hash manifest for the scheduler core, so it cannot silently self-modify.

    Plugins are explicitly *outside* this boundary: extending behaviour is
    allowed, rewriting the scheduler that supervises the extensions is not.
    """

    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self.package_dir = os.path.dirname(os.path.abspath(__file__))
        self.manifest_path = config.get("codegen.core_manifest")
        self.allow_self_modify = bool(config.get("policy.core_self_modify", False))
        self._log = logger or logging.getLogger("autonomic")
        self._lock = threading.Lock()

    def core_files(self) -> list[str]:
        files = []
        for path in glob.glob(os.path.join(self.package_dir, "*.py")):
            files.append(os.path.abspath(path))
        return sorted(files)

    def build_manifest(self) -> dict:
        files = {os.path.basename(p): util.sha256_file(p) for p in self.core_files()}
        payload = {"generated_at": util.iso(), "package_dir": self.package_dir, "files": files}
        util.ensure_dir(os.path.dirname(self.manifest_path), 0o750)
        util.atomic_write(self.manifest_path, util.json_dumps(payload, pretty=True), mode=0o600)
        return payload

    def _load(self) -> dict:
        if not os.path.exists(self.manifest_path):
            return self.build_manifest()
        data = util.json_loads(util.read_text(self.manifest_path), {}) or {}
        if not data.get("files"):
            return self.build_manifest()
        return data

    def verify(self) -> dict:
        reference = self._load().get("files", {})
        current = {os.path.basename(p): util.sha256_file(p) for p in self.core_files()}
        changed = [f for f in reference if f in current and reference[f] != current[f]]
        added = [f for f in current if f not in reference]
        removed = [f for f in reference if f not in current]
        return {"ok": not (changed or added or removed), "changed": changed, "added": added, "removed": removed}

    def is_core_path(self, path: str) -> bool:
        try:
            real = os.path.realpath(path)
            return os.path.commonpath([real, os.path.realpath(self.package_dir)]) == os.path.realpath(self.package_dir)
        except (ValueError, OSError):
            return False

    def guard_write(self, path: str, approved: bool = False) -> None:
        if not self.is_core_path(path):
            return
        if not self.allow_self_modify:
            raise PolicyDenied(
                "writing the scheduler core is disabled (policy.core_self_modify=false); "
                "extend behaviour via a plugin instead",
                path=path,
            )
        if not approved:
            raise PolicyDenied("core self-modification requires explicit human approval", path=path)


class PendingStore:
    """Proposals that automation refused to execute on its own."""

    def __init__(self, data_dir: str):
        self.dir = os.path.join(data_dir, "pending")
        util.ensure_dir(self.dir, 0o750)
        self._lock = threading.Lock()

    def _path(self, request_id: str) -> str:
        return os.path.join(self.dir, f"{request_id}.json")

    def add(self, request: ActionRequest, decision: PolicyDecision) -> str:
        record = {
            "request": request.to_dict(),
            "decision": decision.to_dict(),
            "created_at": util.iso(),
            "created_epoch": util.now(),
            "status": "pending",
        }
        with self._lock:
            util.atomic_write(self._path(request.id), util.json_dumps(record, pretty=True), mode=0o600)
        return request.id

    def find_similar(self, action: str, target: str) -> Optional[str]:
        """Return the id of an existing pending proposal for the same action+target.

        Prevents the same remediation request from stacking up multiple
        identical approval prompts while the first one is still waiting.
        """
        with self._lock:
            for path in glob.glob(os.path.join(self.dir, "*.json")):
                record = util.json_loads(util.read_text(path), {})
                if not record or record.get("status") != "pending":
                    continue
                req = record.get("request", {})
                if req.get("action") == action and (req.get("target") or "") == (target or ""):
                    return req.get("id") or os.path.splitext(os.path.basename(path))[0]
        return None

    def list(self, limit: int = 50) -> list[dict]:
        items = []
        for path in glob.glob(os.path.join(self.dir, "*.json")):
            record = util.json_loads(util.read_text(path), {})
            if not record or record.get("status") != "pending":
                continue
            items.append(record)
        items.sort(key=lambda r: r.get("created_epoch", 0), reverse=True)
        return items[:limit]

    def get(self, request_id: str) -> Optional[dict]:
        path = self._path(request_id)
        if not os.path.exists(path):
            return None
        record = util.json_loads(util.read_text(path), {})
        return record or None

    def pop(self, request_id: str) -> Optional[dict]:
        with self._lock:
            path = self._path(request_id)
            if not os.path.exists(path):
                return None
            record = util.json_loads(util.read_text(path), {})
            try:
                os.unlink(path)
            except OSError:
                pass
            return record or None

    def count(self) -> int:
        return len(glob.glob(os.path.join(self.dir, "*.json")))

    def expire(self, days: int = 14) -> int:
        cutoff = util.now() - days * 86400
        removed = 0
        for path in glob.glob(os.path.join(self.dir, "*.json")):
            record = util.json_loads(util.read_text(path), {})
            if record.get("created_epoch", 0) < cutoff:
                try:
                    os.unlink(path)
                    removed += 1
                except OSError:
                    pass
        return removed


class PolicyEngine:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.config = config
        self.auto_remediate = bool(config.get("policy.auto_remediate", True))
        self.dry_run = bool(config.get("policy.dry_run", False))
        self.max_auto_risk = str(config.get("policy.max_auto_risk", "medium"))
        self.whitelist = set(config.get("policy.whitelist", []) or [])
        self.approval_required = set(config.get("policy.approval_required", []) or [])
        self.forbidden_paths = [os.path.abspath(p) for p in (config.get("policy.forbidden_paths", []) or [])]
        self.cleanup_paths = [os.path.abspath(p) for p in (config.get("policy.cleanup_paths", []) or [])]
        self.critical_always_approval = bool(config.get("policy.critical_always_approval", True))
        self.shell_allowlist = [s.strip() for s in (config.get("policy.shell_allowlist", []) or []) if s.strip()]
        self.shell_forbidden = [re.compile(p) for p in (config.get("policy.shell_forbidden_patterns", []) or [])]
        self.limiter = RateLimiter(int(config.get("scheduler.max_actions_per_minute", 30)))
        self.core = CoreIntegrity(config, logger)
        self._log = logger or logging.getLogger("autonomic")
        self._log_shell_uses = 0

    # --------------------------------------------------------------- checks
    def risk_of(self, action: str, declared: str = "") -> str:
        if declared and declared in RISK_ORDER:
            return declared
        return DEFAULT_RISK.get(action, "high")

    def is_forbidden_path(self, path: str) -> bool:
        if not path:
            return False
        real = os.path.realpath(os.path.abspath(os.path.expanduser(path)))
        for forbidden in self.forbidden_paths:
            if real == forbidden or real.startswith(forbidden.rstrip("/") + "/"):
                return True
        return False

    def in_cleanup_scope(self, path: str) -> bool:
        real = os.path.realpath(os.path.abspath(path))
        for root in self.cleanup_paths:
            if real == root or real.startswith(root.rstrip("/") + "/"):
                return True
        return False

    def check_shell(self, command: str) -> PolicyDecision:
        text = str(command or "").strip()
        if not text:
            return PolicyDecision(False, True, "empty shell command", "high")
        for pattern in self.shell_forbidden:
            if pattern.search(text):
                return PolicyDecision(False, False, f"command matches forbidden pattern /{pattern.pattern}/", "critical")
        first = text.split()[0] if text.split() else ""
        allowed_prefix = any(text.startswith(prefix) for prefix in self.shell_allowlist)
        if allowed_prefix and not re.search(r"[;&|`$<>]", text):
            return PolicyDecision(True, False, "read-only command in allowlist", "low",
                                  rule_hit="policy.shell_allowlist")
        return PolicyDecision(False, True, "shell command outside read-only allowlist", "high",
                              rule_hit="policy.shell_default_deny")

    def check_restart_command(self, command: str) -> PolicyDecision:
        """Validate an administrator-authored restart recipe from the config.

        Restart recipes legitimately use redirection and backgrounding, so the
        read-only shell allowlist does not apply here. We still enforce the hard
        forbidden patterns plus basic sanity checks, so a tampered config file
        cannot silently turn into arbitrary command execution with root rights.
        """
        text = str(command or "").strip()
        if not text:
            return PolicyDecision(False, False, "empty restart command", "high")
        if len(text) > 4096:
            return PolicyDecision(False, False, "restart command too long", "high")
        if re.search(r"[\x00-\x08\x0b\x0c\x0e-\x1f]", text):
            return PolicyDecision(False, False, "restart command contains control characters", "critical")
        for pattern in self.shell_forbidden:
            if pattern.search(text):
                return PolicyDecision(False, False,
                                      f"restart command matches forbidden pattern /{pattern.pattern}/", "critical")
        return PolicyDecision(True, False, "restart recipe passed forbidden-pattern scan", "medium",
                              rule_hit="policy.restart_recipe")

    # ---------------------------------------------------------------- decide
    def decide(self, request: ActionRequest, approved_by: Optional[str] = None) -> PolicyDecision:
        risk = self.risk_of(request.action, request.risk)
        request.risk = risk

        target_path = str(request.params.get("path") or request.params.get("target_path") or "")
        if target_path and self.is_forbidden_path(target_path):
            return PolicyDecision(False, False, f"target path is hard-forbidden by policy: {target_path}", risk,
                                  rule_hit="policy.forbidden_path")

        if target_path and self.core.is_core_path(target_path):
            if not self.core.allow_self_modify:
                return PolicyDecision(False, False,
                                      "target is the scheduler core; self-modification is disabled", "critical",
                                      rule_hit="policy.core_protected")
            risk = "critical"

        if approved_by:
            return PolicyDecision(True, False, f"explicitly approved by {approved_by}", risk, rule_hit="policy.human_approval")

        if not self.limiter.allow():
            return PolicyDecision(False, False, "action rate limit exceeded for this minute", risk,
                                  rule_hit="policy.rate_limit")

        if not self.auto_remediate:
            return PolicyDecision(False, True, "auto remediation is disabled; proposal queued for human decision", risk,
                                  rule_hit="policy.auto_off")

        if risk == "critical" and self.critical_always_approval:
            return PolicyDecision(False, True, "critical-risk action always requires human approval", risk,
                                  rule_hit="policy.critical")

        if request.action in self.approval_required:
            return PolicyDecision(False, True,
                                  f"action '{request.action}' is on the approval-required list", risk,
                                  rule_hit="policy.approval_list")

        if request.action not in self.whitelist:
            return PolicyDecision(False, True,
                                  f"action '{request.action}' is outside the auto-remediation whitelist", risk,
                                  rule_hit="policy.not_whitelisted")

        if RISK_ORDER.get(risk, 3) > RISK_ORDER.get(self.max_auto_risk, 1):
            return PolicyDecision(False, True,
                                  f"risk '{risk}' exceeds max_auto_risk '{self.max_auto_risk}'", risk,
                                  rule_hit="policy.risk_ceiling")

        suffix = " (dry-run: executor will simulate only)" if self.dry_run else ""
        return PolicyDecision(True, False, f"whitelisted and within auto-risk ceiling{suffix}", risk,
                              rule_hit="policy.whitelisted")

    # -------------------------------------------------------------- describe
    def describe(self) -> dict:
        return {
            "auto_remediate": self.auto_remediate,
            "dry_run": self.dry_run,
            "max_auto_risk": self.max_auto_risk,
            "whitelist": sorted(self.whitelist),
            "approval_required": sorted(self.approval_required),
            "forbidden_paths": self.forbidden_paths,
            "cleanup_paths": self.cleanup_paths,
            "core_self_modify": self.core.allow_self_modify,
            "core_files": len(self.core.core_files()),
            "core_integrity": self.core.verify(),
        }
