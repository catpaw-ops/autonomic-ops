"""Domain objects shared by scheduler, detectors, executor, IPC and CLI.

Everything is a plain dataclass with explicit ``to_dict`` so it can cross the
Unix-socket boundary or be journalled to disk without pickling (pickle would
make the on-disk task journal executable code - a needless attack surface).
"""

from __future__ import annotations

import enum
import threading
import time
from dataclasses import dataclass, field, asdict
from typing import Any, Optional

from . import util


class Priority(enum.IntEnum):
    """Higher number wins. Ranges are documented so operators can reason."""

    BACKGROUND = 10       # maintenance, pruning, low-value scans
    ROUTINE = 30          # scheduled inspection
    SECURITY = 55         # security findings
    USER = 70             # human instruction
    REMOTE = 60           # remote control plane instruction
    CRITICAL = 90         # active outage / attack mitigation
    EMERGENCY = 99        # watchdog-triggered


PRIORITY_NAMES = {
    10: "background",
    30: "routine",
    55: "security",
    60: "remote",
    70: "user",
    90: "critical",
    99: "emergency",
}


def priority_name(value: int) -> str:
    nearest = min(PRIORITY_NAMES, key=lambda k: abs(k - value))
    return PRIORITY_NAMES[nearest]


class TaskState(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    PREEMPTED = "preempted"
    REJECTED = "rejected"
    PENDING_APPROVAL = "pending_approval"

    @property
    def terminal(self) -> bool:
        return self in (
            TaskState.SUCCEEDED,
            TaskState.FAILED,
            TaskState.TIMEOUT,
            TaskState.CANCELLED,
            TaskState.REJECTED,
        )


class TaskKind(str, enum.Enum):
    SHELL = "shell"
    DIAGNOSTIC = "diagnostic"
    PLUGIN = "plugin"
    CODEGEN = "codegen"
    ACTION = "action"
    CHAT = "chat"
    DEPLOY = "deploy"
    NOOP = "noop"


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def severity_rank(value: str) -> int:
    return SEVERITY_RANK.get(str(value).lower(), 0)


@dataclass
class Task:
    kind: str
    payload: dict = field(default_factory=dict)
    priority: int = int(Priority.ROUTINE)
    source: str = "auto"             # auto | user | remote | plugin | watchdog
    title: str = ""
    timeout: float = 120.0
    cpu_seconds: int = 300
    memory_mb: int = 512
    preemptible: bool = True
    max_attempts: int = 2
    id: str = field(default_factory=lambda: util.new_id("t_"))
    state: str = TaskState.QUEUED.value
    created_at: float = field(default_factory=util.now)
    queued_at: float = field(default_factory=util.now)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    attempts: int = 0
    worker: Optional[str] = None
    result: Optional[dict] = None
    error: Optional[str] = None
    rule_id: Optional[str] = None
    finding_id: Optional[str] = None
    decision: Optional[str] = None
    wait_seconds: float = 0.0
    cancel_event: threading.Event = field(default_factory=threading.Event, repr=False, compare=False)
    lock: threading.Lock = field(default_factory=threading.Lock, repr=False, compare=False)

    def __post_init__(self):
        if not self.title:
            self.title = self.payload.get("title") or f"{self.kind} task"

    @property
    def elapsed(self) -> float:
        if not self.started_at:
            return 0.0
        return (self.finished_at or util.now()) - self.started_at

    def effective_priority(self, aging_rate: float, aging_cap: float) -> float:
        waited = max(0.0, util.now() - self.queued_at)
        return float(self.priority) + min(aging_cap, waited * aging_rate)

    def to_dict(self) -> dict:
        data = {
            "id": self.id,
            "kind": self.kind,
            "title": self.title,
            "source": self.source,
            "priority": self.priority,
            "priority_name": priority_name(self.priority),
            "state": self.state,
            "attempts": self.attempts,
            "worker": self.worker,
            "created_at": util.iso(self.created_at),
            "started_at": util.iso(self.started_at) if self.started_at else None,
            "finished_at": util.iso(self.finished_at) if self.finished_at else None,
            "elapsed": round(self.elapsed, 2),
            "wait_seconds": round(self.wait_seconds, 2),
            "result": self.result,
            "error": self.error,
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "decision": self.decision,
            "timeout": self.timeout,
            "preemptible": self.preemptible,
            "payload": _safe_payload(self.payload),
        }
        return data


def _safe_payload(payload: dict) -> dict:
    """Strip secrets and oversized blobs from task payloads before display."""
    out = {}
    for key, value in (payload or {}).items():
        if str(key).lower() in ("password", "token", "api_key", "secret", "private_key"):
            out[key] = "***"
        elif isinstance(value, str) and len(value) > 4000:
            out[key] = value[:2000] + f"... <truncated {len(value)} chars>"
        else:
            out[key] = value
    return out


@dataclass
class Finding:
    kind: str
    target: str
    value: Any = None
    severity: str = "medium"
    detector: str = "core"
    message: str = ""
    evidence: dict = field(default_factory=dict)
    id: str = field(default_factory=lambda: util.new_id("f_"))
    ts: float = field(default_factory=util.now)

    @property
    def dedupe_key(self) -> str:
        return f"{self.kind}:{self.target}"

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "kind": self.kind,
            "target": self.target,
            "value": self.value,
            "severity": self.severity,
            "detector": self.detector,
            "message": self.message,
            "evidence": self.evidence,
            "ts": util.iso(self.ts),
        }


@dataclass
class ActionRequest:
    action: str
    target: str = ""
    params: dict = field(default_factory=dict)
    risk: str = ""              # empty = derive from policy action risk table
    source: str = "auto"
    reason: str = ""
    rule_id: Optional[str] = None
    finding_id: Optional[str] = None
    task_id: Optional[str] = None
    id: str = field(default_factory=lambda: util.new_id("a_"))
    ts: float = field(default_factory=util.now)
    approved_by: Optional[str] = None
    dry_run: bool = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "action": self.action,
            "target": self.target,
            "params": _safe_payload(self.params),
            "risk": self.risk,
            "source": self.source,
            "reason": self.reason,
            "rule_id": self.rule_id,
            "finding_id": self.finding_id,
            "task_id": self.task_id,
            "ts": util.iso(self.ts),
            "approved_by": self.approved_by,
            "dry_run": self.dry_run,
        }


@dataclass
class ActionResult:
    ok: bool
    action: str
    detail: str = ""
    changed_files: list = field(default_factory=list)
    rollback_point: Optional[str] = None
    verified: bool = False
    skipped: bool = False
    output: str = ""
    duration: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class PolicyDecision:
    allowed: bool
    needs_approval: bool
    reason: str
    risk: str
    rule_hit: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Decision:
    """A scheduler decision, persisted so humans can audit *why*."""

    kind: str                     # submit | queue | preempt | reject | continue | cancel
    task_id: str
    priority: int
    reason: str
    compared_with: Optional[str] = None
    queue_position: Optional[int] = None
    ts: float = field(default_factory=util.now)
    id: str = field(default_factory=lambda: util.new_id("d_"))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "ts": util.iso(self.ts),
            "kind": self.kind,
            "task_id": self.task_id,
            "priority": self.priority,
            "reason": self.reason,
            "compared_with": self.compared_with,
            "queue_position": self.queue_position,
        }


@dataclass
class ExecResult:
    rc: int
    stdout: str = ""
    stderr: str = ""
    duration: float = 0.0
    timed_out: bool = False
    killed: bool = False
    cancelled: bool = False
    degraded_isolation: bool = False
    notes: list = field(default_factory=list)
    cwd: str = ""

    @property
    def ok(self) -> bool:
        return self.rc == 0 and not self.timed_out

    def to_dict(self) -> dict:
        return {
            "rc": self.rc,
            "ok": self.ok,
            "duration": round(self.duration, 3),
            "timed_out": self.timed_out,
            "killed": self.killed,
            "cancelled": self.cancelled,
            "degraded_isolation": self.degraded_isolation,
            "notes": self.notes,
            "stdout": self.stdout[-4000:],
            "stderr": self.stderr[-4000:],
        }
