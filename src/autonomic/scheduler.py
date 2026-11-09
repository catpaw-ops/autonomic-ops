"""Priority scheduler.

One thread owns every queue decision; workers only execute what they are
handed. That single-writer design is what makes the three-way choice
(continue / queue / preempt) explainable and auditable.

Priority model:
  * base priority: 10 background ... 99 emergency
  * aging: a queued task gains ``aging_rate`` effective points per second,
    capped at ``aging_cap``, so routine work cannot starve forever
  * preemption: only if the newcomer is at least ``preempt_threshold`` points
    above the lowest-priority *preemptible* running task, and only that task
    is cancelled - never the whole pool

Preempted tasks are requeued (bounded by ``preempt_requeue_limit``) so a user
instruction can jump the line without destroying automatic repair work.
"""

from __future__ import annotations

import logging
import os
import threading
from collections import deque
from typing import Optional

from . import util
from .config import Config
from .models import Decision, Priority, Task, TaskKind, TaskState
from .workers import Worker, WorkerPool

TERMINAL = {s.value for s in TaskState if s.terminal}


class Scheduler:
    def __init__(self, config: Config, bus, runner, audit=None, logger: Optional[logging.Logger] = None):
        self.config = config
        self.bus = bus
        self.audit = audit
        self._log = logger or logging.getLogger("autonomic.task")
        self._dlog = logging.getLogger("autonomic.decision")
        self._lock = threading.RLock()
        self.waiting: list[Task] = []
        self.running: dict[str, Task] = {}
        self._stop = threading.Event()
        self._tick_thread: Optional[threading.Thread] = None
        self.queue_max = int(config.get("scheduler.queue_max", 200))
        self.max_timeout = float(config.get("scheduler.max_task_timeout", 1800))
        self.default_timeout = float(config.get("scheduler.default_task_timeout", 120))
        self.default_cpu = int(config.get("scheduler.default_cpu_seconds", 300))
        self.default_mem = int(config.get("scheduler.default_memory_mb", 512))
        self.aging_rate = float(config.get("scheduler.aging_rate", 0.25))
        self.aging_cap = float(config.get("scheduler.aging_cap", 25))
        self.preemption = bool(config.get("scheduler.preemption", True))
        self.preempt_threshold = int(config.get("scheduler.preempt_threshold", 15))
        self.preempt_requeue_limit = int(config.get("scheduler.preempt_requeue_limit", 2))
        self.dedupe_window = float(config.get("scheduler.dedupe_window", 30))
        self.journal_path = os.path.join(config.get("agent.data_dir"), "tasks.jsonl")
        self.journal_max = int(config.get("scheduler.journal_max_entries", 500))
        self.decisions: deque = deque(maxlen=100)
        self.counters = {"submitted": 0, "completed": 0, "failed": 0, "rejected": 0,
                         "preempted": 0, "cancelled": 0, "deduped": 0}
        self.pool = WorkerPool(runner, self._on_worker_done,
                               size=int(config.get("scheduler.workers", 4)),
                               max_size=int(config.get("scheduler.max_workers", 16)),
                               logger=self._log)
        util.ensure_dir(os.path.dirname(self.journal_path), 0o750)
        self._journal_seq = 0

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        self.pool.start()
        if self._tick_thread and self._tick_thread.is_alive():
            return
        self._stop.clear()
        self._tick_thread = threading.Thread(target=self._tick_loop, name="scheduler", daemon=True)
        self._tick_thread.start()
        self._log.info("scheduler started workers=%d queue_max=%d preemption=%s",
                       len(self.pool.workers), self.queue_max, self.preemption)

    def stop(self, timeout: float = 8.0) -> None:
        self._stop.set()
        if self._tick_thread:
            self._tick_thread.join(timeout=3)
        with self._lock:
            for task in list(self.running.values()):
                task.cancel_event.set()
        self.pool.stop(timeout=timeout)

    # ---------------------------------------------------------------- submit
    def submit(self, task: Task) -> Decision:
        self._normalise(task)
        with self._lock:
            self.counters["submitted"] += 1
            duplicate = self._find_duplicate(task)
            if duplicate is not None:
                self.counters["deduped"] += 1
                decision = Decision("dedupe", task.id, task.priority,
                                    f"identical task already {duplicate.state}: {duplicate.id}",
                                    compared_with=duplicate.id)
                self._record(decision)
                return decision

            if len(self.waiting) >= self.queue_max:
                victim = min(self.waiting, key=lambda t: (t.priority, t.queued_at))
                if task.priority > victim.priority:
                    self.waiting.remove(victim)
                    victim.state = TaskState.REJECTED.value
                    victim.finished_at = util.now()
                    victim.error = "evicted from a full queue by a higher-priority task"
                    self.counters["rejected"] += 1
                    self._journal(victim, "rejected")
                    self._dlog.warning("queue full: evicted task=%s priority=%d for task=%s priority=%d",
                                       victim.id, victim.priority, task.id, task.priority)
                else:
                    task.state = TaskState.REJECTED.value
                    task.finished_at = util.now()
                    task.error = "queue full and task is not higher priority than the queue tail"
                    self.counters["rejected"] += 1
                    decision = Decision("reject", task.id, task.priority, task.error)
                    self._record(decision)
                    self._journal(task, "rejected")
                    return decision

            victim_running = self._pick_preemption_victim(task) if self.preemption else None
            if victim_running is not None:
                victim_running.cancel_event.set()
                victim_running.decision = "preempted"
                self.counters["preempted"] += 1
                task.state = TaskState.QUEUED.value
                task.queued_at = util.now()
                self.waiting.append(task)
                decision = Decision(
                    "preempt", task.id, task.priority,
                    f"priority {task.priority} >= running {victim_running.priority} + threshold "
                    f"{self.preempt_threshold}; safely cancelling {victim_running.kind} task "
                    f"(preemptible={victim_running.preemptible})",
                    compared_with=victim_running.id, queue_position=1,
                )
                self._record(decision)
                self._journal(task, "queued")
                self.bus.publish("task.preempt", {"task": task.to_dict(), "victim": victim_running.to_dict(),
                                                  "decision": decision.to_dict()})
                self._log.warning("preempting task=%s (p=%d) for task=%s (p=%d)",
                                  victim_running.id, victim_running.priority, task.id, task.priority)
                return decision

            task.state = TaskState.QUEUED.value
            task.queued_at = util.now()
            self.waiting.append(task)
            position = self._position(task)
            decision = Decision("queue", task.id, task.priority,
                                f"queued at position {position}; all workers busy or lower priority",
                                queue_position=position)
            self._record(decision)
            self._journal(task, "queued")
        self.bus.publish("task.queued", {"task": task.to_dict(), "decision": decision.to_dict()})
        return decision

    def _normalise(self, task: Task) -> None:
        if task.kind not in {k.value for k in TaskKind}:
            raise ValueError(f"unknown task kind: {task.kind}")
        task.priority = int(max(1, min(99, task.priority)))
        task.timeout = float(max(1, min(self.max_timeout, task.timeout or self.default_timeout)))
        task.cpu_seconds = int(max(1, min(3600, task.cpu_seconds or self.default_cpu)))
        task.memory_mb = int(max(16, min(8192, task.memory_mb or self.default_mem)))
        task.max_attempts = int(max(1, min(10, task.max_attempts)))
        if task.state in TERMINAL:
            task.state = TaskState.QUEUED.value

    def _find_duplicate(self, task: Task) -> Optional[Task]:
        key = task.payload.get("dedupe_key") or f"{task.kind}:{task.title}"
        now = util.now()
        for existing in list(self.waiting) + list(self.running.values()):
            if existing.id == task.id:
                continue
            other = existing.payload.get("dedupe_key") or f"{existing.kind}:{existing.title}"
            if other == key and now - existing.created_at <= self.dedupe_window:
                return existing
        return None

    def _pick_preemption_victim(self, newcomer: Task) -> Optional[Task]:
        candidates = [
            t for t in self.running.values()
            if t.preemptible and not t.cancel_event.is_set()
            and newcomer.priority - t.priority >= self.preempt_threshold
        ]
        if not candidates:
            return None
        return min(candidates, key=lambda t: (t.priority, t.started_at or 0))

    def _position(self, task: Task) -> int:
        better = 0
        for other in self.waiting:
            if other is task:
                continue
            if other.effective_priority(self.aging_rate, self.aging_cap) > task.effective_priority(self.aging_rate, self.aging_cap):
                better += 1
        return better + 1

    # ------------------------------------------------------------------ tick
    def _tick_loop(self) -> None:
        interval = float(self.config.get("scheduler.tick_interval", 0.5))
        while not self._stop.wait(interval):
            try:
                self._dispatch()
            except Exception as exc:  # noqa: BLE001 - scheduler must never die
                self._log.error("scheduler tick failed: %s", exc, exc_info=True)

    def _dispatch(self) -> None:
        while True:
            with self._lock:
                if not self.waiting:
                    return
                idle = self.pool.idle()
                if not idle:
                    return
                task = max(self.waiting, key=lambda t: (t.effective_priority(self.aging_rate, self.aging_cap),
                                                        -t.created_at))
                self.waiting.remove(task)
                worker = idle[0]
                task.wait_seconds = util.now() - task.queued_at
                if not worker.assign(task):
                    self.waiting.append(task)
                    return
                task.state = TaskState.RUNNING.value
                self.running[task.id] = task
            self._journal(task, "started")
            self.bus.publish("task.started", {"task": task.to_dict(), "worker": worker.wid})
            self._log.info("dispatch task=%s worker=%s priority=%d waited=%.2fs",
                           task.id, worker.wid, task.priority, task.wait_seconds)

    # ------------------------------------------------------------- completion
    def _on_worker_done(self, worker: Worker, task: Task) -> None:
        with self._lock:
            self.running.pop(task.id, None)
            state = task.state
            if state == TaskState.RUNNING.value:
                ok = bool((task.result or {}).get("ok"))
                task.state = TaskState.SUCCEEDED.value if ok else TaskState.FAILED.value
                state = task.state
            if state == TaskState.CANCELLED.value and task.decision == "preempted" \
                    and task.attempts <= self.preempt_requeue_limit:
                task.state = TaskState.QUEUED.value
                task.queued_at = util.now()
                task.cancel_event = threading.Event()
                task.decision = "requeued_after_preempt"
                task.worker = None
                task.started_at = None
                self.waiting.append(task)
                self.bus.publish("task.requeued", {"task": task.to_dict(), "reason": "preempted"})
                self._journal(task, "requeued")
                self._log.info("requeue preempted task=%s attempt=%d", task.id, task.attempts)
                return
            task.finished_at = task.finished_at or util.now()
            if task.state == TaskState.SUCCEEDED.value:
                self.counters["completed"] += 1
            elif task.state == TaskState.CANCELLED.value:
                self.counters["cancelled"] += 1
            else:
                self.counters["failed"] += 1
            self._journal(task, "finished")
        self.bus.publish("task.finished", {"task": task.to_dict()})

    # --------------------------------------------------------------- control
    def cancel(self, task_id: str, reason: str = "cancelled by operator") -> dict:
        with self._lock:
            for task in self.waiting:
                if task.id == task_id:
                    self.waiting.remove(task)
                    task.state = TaskState.CANCELLED.value
                    task.finished_at = util.now()
                    task.error = reason
                    self.counters["cancelled"] += 1
                    self._journal(task, "cancelled")
                    return {"ok": True, "task_id": task_id, "state": task.state, "was": "queued"}
            task = self.running.get(task_id)
            if task:
                task.cancel_event.set()
                task.decision = "cancel_requested"
                self._journal(task, "cancel_requested")
                return {"ok": True, "task_id": task_id, "state": "cancel_requested", "was": "running",
                        "note": "cooperative cancel: the runner stops at its next checkpoint"}
        return {"ok": False, "error": f"task not found: {task_id}"}

    def set_workers(self, size: int) -> dict:
        status = self.pool.resize(size)
        self._log.info("worker pool resized to %s", status.get("size"))
        return status

    # --------------------------------------------------------------- journal
    def _journal(self, task: Task, event: str) -> None:
        if not self.config.get("agent.task_journal", True):
            return
        self._journal_seq += 1
        record = {"seq": self._journal_seq, "event": event, "ts": util.iso(), "task": task.to_dict()}
        try:
            with open(self.journal_path, "a", encoding="utf-8") as fh:
                fh.write(util.json_dumps(record) + "\n")
            if self._journal_seq % 200 == 0:
                self._trim_journal()
        except OSError as exc:
            self._log.warning("task journal write failed: %s", exc)

    def _trim_journal(self) -> None:
        try:
            lines = util.tail_lines(self.journal_path, self.journal_max)
            util.atomic_write(self.journal_path, "\n".join(lines) + "\n", mode=0o640)
        except OSError:
            pass

    def recover(self) -> dict:
        """After a crash, requeue *human* tasks only.

        Automatic action tasks are deliberately not replayed: a restart or
        firewall change may have already happened, and replaying it blindly is
        worse than asking the operator to re-issue it. Those are surfaced as
        ``needs_review`` instead.
        """
        if not os.path.exists(self.journal_path):
            return {"recovered": 0, "needs_review": 0}
        latest: dict[str, dict] = {}
        for line in util.tail_lines(self.journal_path, self.journal_max):
            record = util.json_loads(line, {})
            task = record.get("task") or {}
            if task.get("id"):
                latest[task["id"]] = {"task": task, "event": record.get("event")}
        recovered = review = 0
        for entry in latest.values():
            task_data, event = entry["task"], entry["event"]
            if event in ("finished", "rejected", "cancelled") or task_data.get("state") in TERMINAL:
                continue
            if task_data.get("payload", {}).get("_synthetic"):
                continue
            if task_data.get("source") in ("user", "remote") and task_data.get("kind") != TaskKind.ACTION.value:
                task = Task(
                    kind=task_data.get("kind", TaskKind.DIAGNOSTIC.value),
                    payload=task_data.get("payload") or {},
                    priority=int(task_data.get("priority", 30)),
                    source="recovery", title=(task_data.get("title") or "recovered task") + " (recovered)",
                    timeout=float(task_data.get("timeout", self.default_timeout)),
                    preemptible=bool(task_data.get("preemptible", True)),
                )
                task.payload["_recovered_from"] = task_data.get("id")
                self.submit(task)
                recovered += 1
            elif task_data.get("kind") == TaskKind.ACTION.value:
                self.bus.publish("task.needs_review", {"task": task_data,
                                                       "reason": "mutating task interrupted by daemon restart"})
                review += 1
        self._log.info("journal recovery: requeued=%d needs_review=%d", recovered, review)
        return {"recovered": recovered, "needs_review": review}

    # ----------------------------------------------------------------- stats
    def _record(self, decision: Decision) -> None:
        self.decisions.append(decision)
        self._dlog.info("decision kind=%s task=%s priority=%s compared_with=%s reason=%s",
                        decision.kind, decision.task_id, decision.priority,
                        decision.compared_with or "-", decision.reason)

    def stats(self) -> dict:
        with self._lock:
            waiting = [
                {"id": t.id, "title": t.title, "priority": t.priority, "state": t.state,
                 "waiting_seconds": round(util.now() - t.queued_at, 1),
                 "effective_priority": round(t.effective_priority(self.aging_rate, self.aging_cap), 1)}
                for t in sorted(self.waiting, key=lambda x: -x.effective_priority(self.aging_rate, self.aging_cap))
            ]
            running = [t.to_dict() for t in self.running.values()]
            return {
                "queue_depth": len(self.waiting),
                "queue_max": self.queue_max,
                "running": len(self.running),
                "workers": self.pool.status(),
                "waiting": waiting,
                "running_tasks": running,
                "counters": dict(self.counters),
                "recent_decisions": [d.to_dict() for d in list(self.decisions)[-15:]],
            }

    def task_list(self, include_terminal: bool = False, limit: int = 50) -> list[dict]:
        out = []
        with self._lock:
            for task in list(self.running.values()) + list(self.waiting):
                out.append(task.to_dict())
        if include_terminal:
            latest: dict[str, dict] = {}
            for line in util.tail_lines(self.journal_path, max(limit, 100)):
                record = util.json_loads(line, {})
                task = record.get("task") or {}
                if task.get("id"):
                    latest[task["id"]] = task
            for tid, task in latest.items():
                if all(t["id"] != tid for t in out):
                    out.append(task)
        out.sort(key=lambda t: (t.get("state") != "running", -int(t.get("priority", 0)), t.get("created_at") or ""))
        return out[:limit]
