"""Logging topology.

Requirement: the daemon must never spam the terminal. Therefore:
  * no StreamHandler is installed in daemon mode at all
  * every record goes to ``runtime.log`` (single unified timeline)
  * warnings/errors are additionally mirrored to ``error.log``
  * task / decision / security / plugin / metrics / codegen channels get their
    own filtered file so an operator can follow one concern without grep-noise
  * audit is a separate append-only JSONL channel (see ``audit.py``)

The CLI never configures these handlers; it only tails files.
"""

from __future__ import annotations

import logging
import logging.handlers
import os
import sys
import threading
from typing import Optional

from . import util
from .config import Config

CHANNELS = ("runtime", "error", "task", "decision", "security", "plugin", "metrics", "codegen", "chat", "backup")

_LOGGER_NAMES = {
    "runtime": "autonomic",
    "error": "autonomic.errors",
    "task": "autonomic.task",
    "decision": "autonomic.decision",
    "security": "autonomic.security",
    "plugin": "autonomic.plugin",
    "metrics": "autonomic.metrics",
    "codegen": "autonomic.codegen",
    "chat": "autonomic.chat",
    "backup": "autonomic.backup",
}


class _SecretFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            record.msg = util.redact(record.msg)
        if record.args:
            record.args = tuple(util.redact(a) if isinstance(a, str) else a for a in record.args)
        return True


class LogManager:
    def __init__(self, config: Config, console: bool = False):
        self.config = config
        self.log_dir = config.get("agent.log_dir")
        self.max_bytes = int(config.get("agent.log_max_bytes", 10 * 1024 * 1024))
        self.backups = int(config.get("agent.log_backups", 5))
        self.level = getattr(logging, str(config.get("agent.log_level", "INFO")).upper(), logging.INFO)
        self.console = console
        self._handlers: list[logging.Handler] = []
        self._lock = threading.Lock()
        self._configured = False

    def path_for(self, channel: str) -> str:
        if channel == "runtime":
            return os.path.join(self.log_dir, "runtime.log")
        return os.path.join(self.log_dir, f"{channel}.log")

    def configure(self) -> None:
        with self._lock:
            if self._configured:
                return
            util.ensure_dir(self.log_dir, 0o750)
            formatter = logging.Formatter(
                fmt="%(asctime)s %(levelname)-7s pid=%(process)d tid=%(threadName)s "
                    "logger=%(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S%z",
            )

            root = logging.getLogger("autonomic")
            root.setLevel(self.level)
            root.handlers = []

            runtime = self._rotating(self.path_for("runtime"))
            runtime.setLevel(self.level)
            runtime.setFormatter(formatter)
            runtime.addFilter(_SecretFilter())
            root.addHandler(runtime)
            self._handlers.append(runtime)

            error = self._rotating(self.path_for("error"))
            error.setLevel(logging.WARNING)
            error.setFormatter(formatter)
            error.addFilter(_SecretFilter())
            root.addHandler(error)
            self._handlers.append(error)

            # filtered per-concern channels. They propagate to root so the
            # unified timeline still contains everything.
            for channel, name in _LOGGER_NAMES.items():
                if channel in ("runtime", "error"):
                    continue
                logger = logging.getLogger(name)
                handler = self._rotating(self.path_for(channel))
                handler.setLevel(self.level)
                handler.setFormatter(formatter)
                handler.addFilter(_SecretFilter())
                logger.addHandler(handler)
                logger.setLevel(self.level)
                logger.propagate = True
                self._handlers.append(handler)

            if self.console:
                stream = logging.StreamHandler(sys.stdout)
                stream.setLevel(self.level)
                stream.setFormatter(formatter)
                root.addHandler(stream)
                self._handlers.append(stream)

            logging.captureWarnings(True)
            threading.excepthook = _thread_excepthook
            sys.excepthook = _excepthook
            self._configured = True

    def _rotating(self, path: str) -> logging.Handler:
        util.ensure_dir(os.path.dirname(path), 0o750)
        handler = logging.handlers.RotatingFileHandler(
            path, maxBytes=self.max_bytes, backupCount=self.backups, encoding="utf-8", delay=False
        )
        try:
            os.chmod(path, 0o640)
        except OSError:
            pass
        return handler

    def get(self, name: str) -> logging.Logger:
        if not self._configured:
            self.configure()
        return logging.getLogger(name)

    def close(self) -> None:
        with self._lock:
            for handler in self._handlers:
                try:
                    handler.flush()
                    handler.close()
                except Exception:  # noqa: BLE001 - shutdown must not raise
                    pass
            self._handlers = []
            self._configured = False

    def tail(self, channel: str, lines: int = 50) -> list[str]:
        path = self.path_for(channel)
        return util.tail_lines(path, lines)

    def sizes(self) -> dict:
        return {ch: util.file_size(self.path_for(ch)) for ch in CHANNELS}


def _excepthook(exc_type, exc, tb) -> None:
    logging.getLogger("autonomic.errors").critical(
        "uncaught exception: %s: %s", exc_type.__name__, util.redact(str(exc)), exc_info=(exc_type, exc, tb)
    )


def _thread_excepthook(args) -> None:
    logging.getLogger("autonomic.errors").error(
        "uncaught thread exception in %s: %s: %s",
        getattr(args.thread, "name", "?"),
        args.exc_type.__name__,
        util.redact(str(args.exc_value)),
        exc_info=(args.exc_type, args.exc_value, args.exc_traceback),
    )


def get_logger(name: str) -> logging.Logger:
    """Fallback accessor used before LogManager is configured (CLI paths)."""
    return logging.getLogger(name)


def ensure_basic() -> None:
    """CLI-side minimal logging: only stderr, never files."""
    if not logging.getLogger("autonomic").handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
        logging.getLogger("autonomic").addHandler(handler)
        logging.getLogger("autonomic").setLevel(logging.WARNING)
