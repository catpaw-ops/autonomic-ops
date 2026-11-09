"""Tamper-evident audit log.

Every action the agent takes - automatic or human-triggered - produces exactly
one audit record with:

    who triggered it, what ran, which files changed, the result, and the
    rollback point that can undo it

Records are hash-chained (``prev_hash`` + sha256 of the canonical record), so
silently editing or deleting a middle record breaks verification. The chain
survives rotation because the first record of a new file carries the previous
file's last hash.

This is *not* a blockchain and makes no claim of immutability against root;
it detects after-the-fact tampering by anyone who cannot rewrite the whole
chain, which is the realistic threat model for a single VPS.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any, Optional

from . import util
from .config import Config


GENESIS = "0" * 64


def _canonical(record: dict) -> str:
    body = {k: v for k, v in record.items() if k != "hash"}
    return json.dumps(body, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class AuditLog:
    def __init__(self, config: Config, logger: Optional[logging.Logger] = None):
        self.path = config.get("audit.file")
        self.max_bytes = int(config.get("audit.max_bytes", 32 * 1024 * 1024))
        self.backups = int(config.get("audit.backups", 5))
        self.enabled = bool(config.get("audit.enabled", True))
        self.chain = bool(config.get("audit.chain", True))
        self._lock = threading.Lock()
        self._log = logger or logging.getLogger("autonomic")
        self._seq = 0
        self._prev = GENESIS
        self._writes_since_fsync = 0
        self._last_hash = GENESIS
        util.ensure_dir(os.path.dirname(self.path), 0o750)
        self._recover_state()

    # ------------------------------------------------------------- recovery
    def _recover_state(self) -> None:
        """Read the tail of the current file so a restart keeps one chain."""
        if not os.path.exists(self.path):
            return
        try:
            lines = util.tail_lines(self.path, 5)
            for line in reversed(lines):
                try:
                    record = json.loads(line)
                except ValueError:
                    continue
                self._seq = int(record.get("seq", 0))
                self._prev = record.get("hash", GENESIS)
                self._last_hash = self._prev
                return
        except OSError as exc:
            self._log.warning("audit recovery failed: %s", exc)

    # ---------------------------------------------------------------- write
    def record(
        self,
        actor: str,
        trigger: str,
        action: str,
        target: str = "",
        params: Optional[dict] = None,
        result: str = "",
        files_changed: Optional[list] = None,
        rollback_point: Optional[str] = None,
        extra: Optional[dict] = None,
    ) -> dict:
        if not self.enabled:
            return {}
        with self._lock:
            self._rotate_if_needed()
            self._seq += 1
            entry = {
                "seq": self._seq,
                "ts": util.iso(),
                "epoch": round(util.now(), 3),
                "actor": actor,                 # auto | user | remote | plugin | watchdog | system
                "trigger": trigger,             # rule id, CLI command, chat text id, etc.
                "action": action,
                "target": target,
                "params": util.json_loads(util.json_dumps(params or {}), {}) if params else {},
                "result": util.redact(str(result))[:4000],
                "files_changed": files_changed or [],
                "rollback_point": rollback_point,
                "prev_hash": self._prev if self.chain else "",
                "extra": extra or {},
            }
            if self.chain:
                entry["hash"] = util.sha256_text(self._prev + _canonical(entry))
                self._prev = entry["hash"]
                self._last_hash = entry["hash"]
            else:
                entry["hash"] = ""
            line = json.dumps(entry, ensure_ascii=False, sort_keys=True, separators=(",", ":")) + "\n"
            try:
                with open(self.path, "a", encoding="utf-8") as fh:
                    fh.write(line)
                    fh.flush()
                    self._writes_since_fsync += 1
                    if self._writes_since_fsync >= 10:
                        os.fsync(fh.fileno())
                        self._writes_since_fsync = 0
                try:
                    os.chmod(self.path, 0o640)
                except OSError:
                    pass
            except OSError as exc:
                self._log.error("audit write failed: %s", exc)
                return {}
            return entry

    def _rotate_if_needed(self) -> None:
        try:
            if not os.path.exists(self.path) or os.path.getsize(self.path) < self.max_bytes:
                return
        except OSError:
            return
        stamp = util.utc_stamp()
        rotated = f"{self.path}.{stamp}"
        try:
            os.replace(self.path, rotated)
            self._log.info("audit rotated to %s", rotated)
            self._prune_rotated()
        except OSError as exc:
            self._log.error("audit rotation failed: %s", exc)

    def _prune_rotated(self) -> None:
        base = os.path.basename(self.path)
        directory = os.path.dirname(self.path)
        rotated = sorted(
            (os.path.join(directory, f) for f in os.listdir(directory) if f.startswith(base + ".")),
            key=lambda p: os.path.getmtime(p),
            reverse=True,
        )
        for path in rotated[self.backups:]:
            try:
                os.unlink(path)
            except OSError:
                pass

    # ----------------------------------------------------------------- read
    def tail(self, limit: int = 50) -> list[dict]:
        out = []
        for line in util.tail_lines(self.path, limit):
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
        return out

    def query(self, limit: int = 100, actor: str = "", action: str = "", since: float = 0.0) -> list[dict]:
        records = []
        if not os.path.exists(self.path):
            return records
        with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if actor and rec.get("actor") != actor:
                    continue
                if action and action not in str(rec.get("action", "")):
                    continue
                if since and float(rec.get("epoch", 0)) < since:
                    continue
                records.append(rec)
        return records[-limit:]

    def verify(self, path: Optional[str] = None) -> dict:
        target = path or self.path
        if not os.path.exists(target):
            return {"ok": True, "checked": 0, "reason": "audit file does not exist yet"}
        prev = GENESIS
        checked = 0
        broken = []
        with open(target, "r", encoding="utf-8", errors="replace") as fh:
            for line_no, line in enumerate(fh, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    broken.append({"line": line_no, "reason": "invalid json"})
                    continue
                checked += 1
                if rec.get("prev_hash") and rec["prev_hash"] != prev:
                    broken.append({"line": line_no, "reason": "prev_hash mismatch", "seq": rec.get("seq")})
                expected = util.sha256_text(prev + _canonical(rec)) if rec.get("hash") else ""
                if rec.get("hash") and rec["hash"] != expected:
                    broken.append({"line": line_no, "reason": "hash mismatch", "seq": rec.get("seq")})
                if rec.get("hash"):
                    prev = rec["hash"]
        return {"ok": not broken, "checked": checked, "last_hash": prev, "broken": broken[:20]}

    @property
    def last_hash(self) -> str:
        return self._last_hash

    def stats(self) -> dict:
        return {
            "path": self.path,
            "enabled": self.enabled,
            "chained": self.chain,
            "records": self._seq,
            "size": util.file_size(self.path),
            "last_hash": self._last_hash,
        }
