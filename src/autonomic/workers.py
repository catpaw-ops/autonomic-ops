"""Worker execution units.

A Worker owns exactly one task at a time. The scheduler pushes work into the
worker's one-slot mailbox; the worker never pulls from the global queue, which
keeps priority decisions in a single place (the scheduler) and makes preemption
deterministic.

Timeout enforcement has two layers:
  * cooperative: ``task.cancel_event`` is checked before and by runners
  * hard: the runner executes in a watchdog thread and the worker stops waiting
    after ``task.timeout``. A subprocess runner is additionally killed by the
    sandbox's own timeout, so leaked threads are the rare case, not the norm.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from typing import Callable, Optional

from . import util
from .models import Task, TaskState

RunnerFn = Callable[[Task], dict]


class Worker(threading.Thread):
    def __init__(self, wid: str, runner: RunnerFn, on_done: Callable[["Worker", Task], None],
                 logger: Optional[logging.Logger] = None):
        super().__init__(name=f"worker-{wid}", daemon=True)
        self.wid = wid
        self.runner = runner
        self.on_done = on_done
        self._log = logger or logging.getLogger("autonomic.task")
        self._mailbox: "queue.Queue" = queue.Queue(maxsize=1)
        self._stop_event = threading.Event()
        self.current: Optional[Task] = None
        self.task_count = 0
        self.fail_count = 0

    @property
    def busy(self) -> bool:
        return self.current is not None

    def assign(self, task: Task) -> bool:
        if self.busy:
            return False
        try:
            self._mailbox.put_nowait(task)
        except queue.Full:
            return False
        # Reserve immediately: the thread may not have woken up yet, and a
        # second dispatch in that window would hand it another task.
        self.current = task
        return True

    def stop(self) -> None:
        self._stop_event.set()
        try:
            self._mailbox.put_nowait(None)
        except queue.Full:
            pass

    def run(self) -> None:  # noqa: D401 - thread body
        while not self._stop_event.is_set():
            try:
                task = self._mailbox.get(timeout=0.5)
            except queue.Empty:
                continue
            if task is None:
                break
            self._execute(task)

    def _execute(self, task: Task) -> None:
        self.current = task
        self.task_count += 1
        task.state = TaskState.RUNNING.value
        task.started_at = util.now()
        task.worker = self.wid
        task.attempts += 1
        self._log.info("task start id=%s worker=%s kind=%s priority=%s attempt=%d title=%s",
                       task.id, self.wid, task.kind, task.priority, task.attempts, task.title)
        started = time.time()
        outcome: dict = {}
        try:
            if task.cancel_event.is_set():
                task.state = TaskState.CANCELLED.value
                outcome = {"ok": False, "error": "cancelled before start"}
            else:
                outcome = self._run_with_deadline(task)
        except Exception as exc:  # noqa: BLE001 - worker must survive any runner bug
            task.state = TaskState.FAILED.value
            task.error = f"{type(exc).__name__}: {util.redact(str(exc))}"
            outcome = {"ok": False, "error": task.error}
            self._log.error("task crashed id=%s: %s", task.id, exc, exc_info=True)
        finally:
            duration = time.time() - started
            task.finished_at = util.now()
            task.result = {
                "ok": bool(outcome.get("ok")),
                "detail": str(outcome.get("detail") or outcome.get("error") or "")[:2000],
                "data": outcome.get("data"),
                "duration": round(duration, 2),
            }
            if outcome.get("cancelled"):
                task.state = TaskState.CANCELLED.value
            if task.state == TaskState.RUNNING.value:
                task.state = TaskState.SUCCEEDED.value if outcome.get("ok") else TaskState.FAILED.value
            if task.state == TaskState.FAILED.value:
                self.fail_count += 1
            self._log.info("task finish id=%s worker=%s state=%s duration=%.2fs detail=%s",
                           task.id, self.wid, task.state, duration, task.result.get("detail", "")[:300])
            self.current = None
            try:
                self.on_done(self, task)
            except Exception as exc:  # noqa: BLE001
                self._log.error("scheduler completion hook failed: %s", exc, exc_info=True)

    def _run_with_deadline(self, task: Task) -> dict:
        box: dict = {}

        def target() -> None:
            try:
                box["result"] = self.runner(task) or {"ok": True}
            except Exception as exc:  # noqa: BLE001
                box["error"] = f"{type(exc).__name__}: {util.redact(str(exc))}"

        thread = threading.Thread(target=target, name=f"run-{task.id[:10]}", daemon=True)
        thread.start()
        deadline = time.time() + max(1.0, float(task.timeout))
        while thread.is_alive():
            if task.cancel_event.is_set():
                thread.join(timeout=2.0)
                task.state = TaskState.CANCELLED.value
                task.error = "cancelled by scheduler before completion"
                if thread.is_alive():
                    self._log.warning("cancelled task id=%s runner did not stop within 2s", task.id)
                return {"ok": False, "cancelled": True, "detail": task.error}
            if time.time() > deadline:
                task.cancel_event.set()
                task.state = TaskState.TIMEOUT.value
                task.error = f"task exceeded wall-clock timeout of {task.timeout}s"
                thread.join(timeout=1.0)
                self._log.error("task timeout id=%s kind=%s timeout=%.1fs",
                                task.id, task.kind, task.timeout)
                return {"ok": False, "error": task.error, "detail": "timeout"}
            thread.join(timeout=0.2)
        if "error" in box:
            task.state = TaskState.FAILED.value
            task.error = box["error"]
            return {"ok": False, "error": box["error"]}
        return box.get("result") or {"ok": True}

    def status(self) -> dict:
        return {
            "id": self.wid,
            "busy": self.busy,
            "current_task": self.current.id if self.current else None,
            "current_title": self.current.title if self.current else None,
            "tasks": self.task_count,
            "failures": self.fail_count,
        }


class WorkerPool:
    def __init__(self, runner: RunnerFn, on_done: Callable[[Worker, Task], None],
                 size: int = 4, max_size: int = 16, logger: Optional[logging.Logger] = None):
        self.runner = runner
        self.on_done = on_done
        self.max_size = max(1, max_size)
        self._log = logger or logging.getLogger("autonomic.task")
        self._workers: list[Worker] = []
        self._lock = threading.RLock()
        self._counter = 0
        self.resize(size)

    @property
    def workers(self) -> list[Worker]:
        with self._lock:
            return list(self._workers)

    def start(self) -> None:
        for worker in self.workers:
            if not worker.is_alive():
                worker.start()

    def resize(self, size: int) -> dict:
        size = max(1, min(self.max_size, int(size)))
        with self._lock:
            alive = [w for w in self._workers if not w._stop_event.is_set()]
            if size > len(alive):
                for _ in range(size - len(alive)):
                    self._counter += 1
                    worker = Worker(str(self._counter), self.runner, self.on_done, self._log)
                    worker.start()
                    self._workers.append(worker)
            elif size < len(alive):
                for worker in alive[size:]:
                    worker.stop()
                self._workers = [w for w in self._workers if not w._stop_event.is_set()]
        return self.status()

    def idle(self) -> list[Worker]:
        return [w for w in self.workers if w.is_alive() and not w.busy]

    def all_busy(self) -> bool:
        workers = [w for w in self.workers if w.is_alive()]
        return bool(workers) and all(w.busy for w in workers)

    def stop(self, timeout: float = 5.0) -> None:
        for worker in self.workers:
            worker.stop()
        for worker in self.workers:
            worker.join(timeout=timeout)

    def status(self) -> dict:
        workers = self.workers
        return {
            "size": len(workers),
            "max_size": self.max_size,
            "busy": sum(1 for w in workers if w.busy),
            "idle": sum(1 for w in workers if not w.busy),
            "workers": [w.status() for w in workers],
        }
