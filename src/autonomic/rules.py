"""Rule engine: finding -> proposed action.

Rules are declarative YAML so an operator can add a remediation without
touching Python and without restarting the daemon (``rules reload``). The
engine never executes anything itself; it emits ``action.request`` events that
the coordinator grades through the policy gate.

Template context available in ``then.params``:
    {{target}} {{value}} {{severity}} {{host}} {{finding_id}}
    {{evidence.<dotted.path>}}
"""

from __future__ import annotations

import glob
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from . import util
from .config import Config, parse_yaml
from .models import ActionRequest, Finding, severity_rank

_TPL_RE = re.compile(r"\{\{\s*([a-zA-Z0-9_.]+)\s*\}\}")


@dataclass
class Rule:
    id: str
    name: str
    kind: str
    action: str
    target: str = ""
    target_regex: str = ""
    min_severity: str = "medium"
    params: dict = field(default_factory=dict)
    risk: str = ""
    enabled: bool = True
    cooldown: int = 300
    max_attempts: int = 3
    description: str = ""
    source_file: str = ""
    priority: int = 55

    def matches(self, finding: Finding) -> bool:
        if not self.enabled:
            return False
        if self.kind != finding.kind:
            return False
        if severity_rank(finding.severity) < severity_rank(self.min_severity):
            return False
        if self.target_regex:
            try:
                if not re.search(self.target_regex, finding.target):
                    return False
            except re.error:
                return False
        elif self.target and self.target != finding.target:
            return False
        return True

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "enabled": self.enabled,
            "when": {"kind": self.kind, "target_regex": self.target_regex, "min_severity": self.min_severity},
            "then": {"action": self.action, "params": self.params, "risk": self.risk},
            "cooldown": self.cooldown,
            "max_attempts": self.max_attempts,
            "description": self.description,
            "source": self.source_file,
        }


def _render(value: Any, context: dict) -> Any:
    if isinstance(value, str):
        def repl(match: re.Match) -> str:
            path = match.group(1)
            node: Any = context
            for part in path.split("."):
                if isinstance(node, dict) and part in node:
                    node = node[part]
                else:
                    return ""
            return str(node)

        return _TPL_RE.sub(repl, value)
    if isinstance(value, list):
        return [_render(v, context) for v in value]
    if isinstance(value, dict):
        return {k: _render(v, context) for k, v in value.items()}
    return value


class RuleEngine:
    def __init__(self, config: Config, bus, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self._log = logger or logging.getLogger("autonomic")
        self.rules: list[Rule] = []
        self.rules_dir = ""
        self._attempts: dict[str, list[float]] = {}
        self.evaluated = 0
        self.proposed = 0
        self.suppressed = 0
        self.load_errors: list[str] = []

    # ------------------------------------------------------------------ load
    def load(self, path: str) -> int:
        """Load one file or every *.yaml/*.yml in a directory."""
        self.rules = []
        self.load_errors = []
        self.rules_dir = path
        files: list[str] = []
        if os.path.isdir(path):
            files = sorted(glob.glob(os.path.join(path, "*.yaml")) + glob.glob(os.path.join(path, "*.yml")))
        elif os.path.exists(path):
            files = [path]
        else:
            self._log.warning("rules path does not exist: %s", path)
            return 0

        seen: set[str] = set()
        for file in files:
            try:
                data = parse_yaml(util.read_text(file)) or {}
            except Exception as exc:  # noqa: BLE001 - report and skip bad file
                self.load_errors.append(f"{os.path.basename(file)}: {exc}")
                self._log.error("rule file %s failed to parse: %s", file, exc)
                continue
            defaults = data.get("defaults", {}) if isinstance(data, dict) else {}
            items = data.get("rules", []) if isinstance(data, dict) else []
            if not isinstance(items, list):
                self.load_errors.append(f"{os.path.basename(file)}: 'rules' must be a list")
                continue
            for item in items:
                try:
                    rule = self._parse_rule(item, defaults, file)
                except Exception as exc:  # noqa: BLE001
                    self.load_errors.append(f"{os.path.basename(file)}: {exc}")
                    self._log.error("invalid rule in %s: %s", file, exc)
                    continue
                if rule.id in seen:
                    self.load_errors.append(f"duplicate rule id: {rule.id}")
                    continue
                seen.add(rule.id)
                self.rules.append(rule)
        self._log.info("rules loaded=%d path=%s errors=%d", len(self.rules), path, len(self.load_errors))
        return len(self.rules)

    def _parse_rule(self, item: dict, defaults: dict, file: str) -> Rule:
        if not isinstance(item, dict):
            raise ValueError("rule must be a mapping")
        when = item.get("when") or {}
        then = item.get("then") or {}
        if not when.get("kind"):
            raise ValueError("rule.when.kind is required")
        if not then.get("action"):
            raise ValueError("rule.then.action is required")
        return Rule(
            id=str(item.get("id") or util.new_id("r_")),
            name=str(item.get("name") or item.get("id") or "unnamed rule"),
            kind=str(when.get("kind")),
            target=str(when.get("target") or ""),
            target_regex=str(when.get("target_regex") or ""),
            min_severity=str(when.get("min_severity") or defaults.get("min_severity") or "medium"),
            action=str(then.get("action")),
            params=dict(then.get("params") or {}),
            risk=str(then.get("risk") or ""),
            enabled=util.parse_bool(item.get("enabled", defaults.get("enabled", True)), True),
            cooldown=util.parse_int(item.get("cooldown", defaults.get("cooldown", 300)), 300, 1, 86400),
            max_attempts=util.parse_int(item.get("max_attempts", defaults.get("max_attempts", 3)), 3, 1, 20),
            description=str(item.get("description") or ""),
            source_file=os.path.basename(file),
            priority=util.parse_int(then.get("priority", defaults.get("priority", 55)), 55, 1, 99),
        )

    # ---------------------------------------------------------------- match
    def on_finding(self, finding: Finding) -> list[ActionRequest]:
        self.evaluated += 1
        out: list[ActionRequest] = []
        now = util.now()
        for rule in self.rules:
            if not rule.matches(finding):
                continue
            key = f"{rule.id}:{finding.target}"
            history = [t for t in self._attempts.get(key, []) if now - t <= max(rule.cooldown, 3600)]
            if len(history) >= rule.max_attempts:
                self.suppressed += 1
                self._log.warning(
                    "rule %s suppressed for %s: max_attempts=%d reached within window",
                    rule.id, finding.target, rule.max_attempts,
                )
                continue
            context = {
                "target": finding.target,
                "value": finding.value,
                "severity": finding.severity,
                "host": self.config.get("agent.node_id"),
                "finding_id": finding.id,
                "evidence": finding.evidence,
            }
            params = _render(rule.params, context)
            if not isinstance(params, dict):
                params = {}
            params.setdefault("finding", finding.to_dict())
            request = ActionRequest(
                action=rule.action,
                target=str(_render(rule.target or finding.target, context)),
                params=params,
                risk=rule.risk,
                source="auto",
                reason=f"rule '{rule.id}' matched {finding.kind} on {finding.target}: {finding.message}",
                rule_id=rule.id,
                finding_id=finding.id,
            )
            history.append(now)
            self._attempts[key] = history
            self.proposed += 1
            out.append(request)
            self._log.info("rule=%s matched finding=%s target=%s proposed action=%s",
                           rule.id, finding.kind, finding.target, rule.action)
        return out

    # ------------------------------------------------------------- runtime
    def add_runtime_rule(self, rule: dict, source: str = "runtime") -> Optional[str]:
        """Register a rule at runtime (used by plugins); no restart required."""
        candidate = dict(rule or {})
        base_id = str(candidate.get("id") or util.new_id("r_"))
        existing = {r.id for r in self.rules}
        rule_id = base_id
        suffix = 1
        while rule_id in existing:
            suffix += 1
            rule_id = f"{base_id}.{suffix}"
        candidate["id"] = rule_id
        parsed = self._parse_rule(candidate, {}, f"runtime:{source}")
        parsed.description = parsed.description or f"registered by {source}"
        self.rules.append(parsed)
        self._log.info("runtime rule registered id=%s source=%s action=%s", rule_id, source, parsed.action)
        return rule_id

    def remove_runtime_rule(self, rule_id: str) -> bool:
        before = len(self.rules)
        self.rules = [r for r in self.rules if r.id != rule_id]
        return len(self.rules) != before

    # ---------------------------------------------------------------- reload
    def reload(self) -> int:
        if not self.rules_dir:
            return 0
        runtime = [r for r in self.rules if r.source_file.startswith("runtime:")]
        count = self.load(self.rules_dir)
        for rule in runtime:
            if not any(existing.id == rule.id for existing in self.rules):
                self.rules.append(rule)
        return len(self.rules)

    def stats(self) -> dict:
        return {
            "count": len(self.rules),
            "enabled": sum(1 for r in self.rules if r.enabled),
            "evaluated": self.evaluated,
            "proposed": self.proposed,
            "suppressed": self.suppressed,
            "errors": self.load_errors,
            "path": self.rules_dir,
        }
