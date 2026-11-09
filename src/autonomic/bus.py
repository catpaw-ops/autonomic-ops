"""In-process message bus.

Why an in-process bus instead of Redis/NATS: the product must run on a single
small VPS with zero external dependencies and survive a cold boot offline.
The bus is deliberately boring:

  * topic matching: exact (``task.finished``) or prefix wildcard (``task.*``)
  * each subscription owns a bounded queue, so a slow subscriber can never
    deadlock the publisher - it drops and increments a counter instead
  * handlers run on a small dispatcher pool, never on the publisher's thread
  * publish never blocks

Cross-process / cross-host traffic (CLI, remote control plane) enters through
the Unix socket IPC layer and is translated into bus events there.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from . import util


@dataclass
class Subscription:
    pattern: str
    handler: Callable[[str, dict], None]
    name: str
    queue: "queue.Queue"
    delivered: int = 0
    dropped: int = 0
    errors: int = 0
    active: bool = True
    thread: Optional[threading.Thread] = None


class Bus:
    def __init__(self, max_queue: int = 2000, threads: int = 2, logger: Optional[logging.Logger] = None):
        self.max_queue = max_queue
        self._threads = threads
        self._subs: list[Subscription] = []
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._dispatchers: list[threading.Thread] = []
        self._log = logger or logging.getLogger("autonomic")
        self._published = 0
        self._delivered = 0
        self._dropped = 0
        self._errors = 0
        self._started = False
        self._latencies: deque = deque(maxlen=200)
        self._topic_counts: dict[str, int] = {}

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._stop.clear()
            for idx in range(self._threads):
                thread = threading.Thread(target=self._dispatch_loop, name=f"bus-{idx}", daemon=True)
                thread.start()
                self._dispatchers.append(thread)

    def stop(self, timeout: float = 3.0) -> None:
        self._stop.set()
        for sub in self._subs:
            try:
                sub.queue.put_nowait(None)
            except queue.Full:
                pass
        for thread in self._dispatchers:
            thread.join(timeout=timeout)

    # ------------------------------------------------------------ pub / sub
    def subscribe(self, pattern: str, handler: Callable[[str, dict], None], name: str = "") -> Subscription:
        sub = Subscription(
            pattern=pattern,
            handler=handler,
            name=name or getattr(handler, "__qualname__", "anonymous"),
            queue=queue.Queue(maxsize=self.max_queue),
        )
        sub.thread = threading.Thread(target=self._sub_loop, args=(sub,), name=f"sub-{sub.name[:20]}", daemon=True)
        with self._lock:
            self._subs.append(sub)
        sub.thread.start()
        self._log.debug("bus subscribe pattern=%s name=%s", pattern, sub.name)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)
        sub.active = False
        try:
            sub.queue.put_nowait(None)
        except queue.Full:
            pass

    def unsubscribe_name(self, name: str) -> int:
        removed = 0
        with self._lock:
            targets = [s for s in self._subs if s.name == name]
        for sub in targets:
            self.unsubscribe(sub)
            removed += 1
        return removed

    def publish(self, topic: str, event: Optional[dict] = None, ttl: float = 0.0) -> int:
        payload = dict(event or {})
        payload.setdefault("_topic", topic)
        payload.setdefault("_ts", util.now())
        matched = 0
        with self._lock:
            subs = list(self._subs)
            self._published += 1
            self._topic_counts[topic] = self._topic_counts.get(topic, 0) + 1
        for sub in subs:
            if not sub.active or not _match(sub.pattern, topic):
                continue
            matched += 1
            try:
                sub.queue.put_nowait(payload)
            except queue.Full:
                sub.dropped += 1
                self._dropped += 1
                if sub.dropped in (1, 10, 100):
                    self._log.warning(
                        "bus subscriber '%s' queue full (dropped=%d pattern=%s topic=%s)",
                        sub.name, sub.dropped, sub.pattern, topic,
                    )
        return matched

    # ----------------------------------------------------------- dispatchers
    def _sub_loop(self, sub: Subscription) -> None:
        while sub.active and not self._stop.is_set():
            try:
                item = sub.queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if item is None:
                break
            started = time.time()
            try:
                sub.handler(item["_topic"], item)
                sub.delivered += 1
                self._delivered += 1
            except Exception as exc:  # noqa: BLE001 - a subscriber must not die
                sub.errors += 1
                self._errors += 1
                self._log.error(
                    "bus handler error name=%s topic=%s error=%s", sub.name, item.get("_topic"), util.redact(str(exc)),
                    exc_info=True,
                )
            finally:
                self._latencies.append(time.time() - started)

    def _dispatch_loop(self) -> None:
        # Kept for compatibility with earlier design: subscriptions each own a
        # thread, this loop only keeps the pool alive for future fan-out work.
        while not self._stop.wait(0.5):
            pass

    # ---------------------------------------------------------------- stats
    def stats(self) -> dict:
        with self._lock:
            subs = [
                {
                    "name": s.name,
                    "pattern": s.pattern,
                    "delivered": s.delivered,
                    "dropped": s.dropped,
                    "errors": s.errors,
                    "backlog": s.queue.qsize(),
                }
                for s in self._subs
            ]
            lat = sorted(self._latencies) if self._latencies else []
            p95 = lat[int(len(lat) * 0.95) - 1] if lat else 0.0
            return {
                "published": self._published,
                "delivered": self._delivered,
                "dropped": self._dropped,
                "errors": self._errors,
                "subscriptions": subs,
                "topics": dict(sorted(self._topic_counts.items(), key=lambda kv: -kv[1])[:20]),
                "p95_latency_ms": round(p95 * 1000, 2),
            }


def _match(pattern: str, topic: str) -> bool:
    if pattern == topic or pattern == "*":
        return True
    if pattern.endswith(".*"):
        prefix = pattern[:-1]  # keep the trailing dot
        return topic.startswith(prefix)
    if pattern.endswith("*"):
        return topic.startswith(pattern[:-1])
    return False
