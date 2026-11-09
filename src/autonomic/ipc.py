"""Unix-socket control plane for the CLI.

Security posture:
  * socket lives in the run dir, mode 0600, owned by the service user
  * a random 256-bit bearer token is generated at every daemon start and
    stored in a 0600 file next to the socket
  * Linux ``SO_PEERCRED`` is checked: only the service UID or root may connect,
    even if the token leaked to another local account
  * every request line is size-capped; malformed JSON gets a generic error
  * the server never echoes Python tracebacks, only stable error codes

The protocol is newline-delimited JSON, one request per line:

    {"id": "...", "token": "...", "cmd": "status", "args": {}}
    {"id": "...", "ok": true, "data": {...}}
"""

from __future__ import annotations

import errno
import json
import logging
import os
import socket
import stat
import struct
import threading
import time
from typing import Callable, Optional

from . import util
from .config import Config
from .errors import AutonomicError

MAX_LINE = 1 << 20  # 1 MiB: enough for a chat message or a config dump


class IPCServer:
    def __init__(self, config: Config, handler: Callable[[str, dict], dict],
                 logger: Optional[logging.Logger] = None):
        self.config = config
        self.handler = handler
        self.path = config.get("agent.socket")
        self.token_path = os.path.join(config.get("agent.run_dir"), "agent.token")
        self.run_dir = config.get("agent.run_dir")
        util.ensure_dir(self.run_dir, 0o750)
        self._log = logger or logging.getLogger("autonomic")
        self._server: Optional[socket.socket] = None
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._sem = threading.Semaphore(32)
        self.token = util.new_id("") + util.new_id("")
        self.requests = 0
        self.errors = 0

    # ------------------------------------------------------------- lifecycle
    def start(self) -> None:
        util.ensure_dir(self.run_dir, 0o750)
        util.atomic_write(self.token_path, self.token + "\n", mode=0o600)
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(self.path)
        os.chmod(self.path, 0o600)
        server.listen(64)
        server.settimeout(1.0)
        self._server = server
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, name="ipc-server", daemon=True)
        self._thread.start()
        self._log.info("ipc listening socket=%s", self.path)

    def _accept_loop(self) -> None:
        while not self._stop.is_set():
            try:
                conn, _ = self._server.accept()
            except socket.timeout:
                continue
            except OSError as exc:
                if self._stop.is_set():
                    break
                self._log.error("ipc accept failed: %s", exc)
                continue
            if not self._sem.acquire(blocking=False):
                try:
                    conn.sendall(b'{"ok":false,"error":"too many connections"}\n')
                except OSError:
                    pass
                conn.close()
                continue
            thread = threading.Thread(target=self._handle_client, args=(conn,), name="ipc-client", daemon=True)
            thread.start()

    def _handle_client(self, conn: socket.socket) -> None:
        try:
            if not self._peer_allowed(conn):
                self._send(conn, {"ok": False, "error": {"code": "ipc.forbidden", "message": "peer uid not permitted"}})
                return
            conn.settimeout(30)
            buf = b""
            while not self._stop.is_set():
                try:
                    chunk = conn.recv(65536)
                except socket.timeout:
                    break
                except OSError:
                    break
                if not chunk:
                    break
                buf += chunk
                if len(buf) > MAX_LINE:
                    self._send(conn, {"ok": False, "error": {"code": "ipc.too_large", "message": "request exceeds 1 MiB"}})
                    break
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    if not line.strip():
                        continue
                    response = self._process_line(line)
                    self._send(conn, response)
        finally:
            self._sem.release()
            try:
                conn.close()
            except OSError:
                pass

    def _peer_allowed(self, conn: socket.socket) -> bool:
        try:
            raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, uid, _gid = struct.unpack("3i", raw)
        except (OSError, AttributeError):
            return True  # non-Linux platforms: token is the only gate
        return uid in (0, util.geteuid())

    def _process_line(self, line: bytes) -> dict:
        self.requests += 1
        try:
            request = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            self.errors += 1
            return {"ok": False, "error": {"code": "ipc.bad_json", "message": "malformed JSON request"}}
        if not isinstance(request, dict):
            return {"ok": False, "error": {"code": "ipc.bad_request", "message": "request must be an object"}}
        token = str(request.get("token") or "")
        if not _constant_time_equals(token, self.token):
            self.errors += 1
            return {"ok": False, "error": {"code": "ipc.unauthorized", "message": "invalid token"}}
        cmd = str(request.get("cmd") or "")
        args = request.get("args") or {}
        if not isinstance(args, dict):
            return {"ok": False, "error": {"code": "ipc.bad_request", "message": "args must be an object"}}
        rid = request.get("id")
        try:
            data = self.handler(cmd, args)
            response = {"id": rid, "ok": True, "data": data}
        except AutonomicError as exc:
            self.errors += 1
            response = {"id": rid, "ok": False, "error": exc.to_dict()}
        except Exception as exc:  # noqa: BLE001 - never leak tracebacks
            self.errors += 1
            self._log.error("ipc handler error cmd=%s: %s", cmd, exc, exc_info=True)
            response = {"id": rid, "ok": False,
                        "error": {"code": "ipc.internal", "message": util.redact(str(exc))[:400]}}
        return response

    def _send(self, conn: socket.socket, payload: dict) -> None:
        try:
            conn.sendall((util.json_dumps(payload) + "\n").encode("utf-8"))
        except OSError:
            pass

    def stop(self) -> None:
        self._stop.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=3)
        for path in (self.path, self.token_path):
            try:
                os.unlink(path)
            except OSError:
                pass

    def stats(self) -> dict:
        return {"socket": self.path, "requests": self.requests, "errors": self.errors,
                "max_line_bytes": MAX_LINE}


def _constant_time_equals(left: str, right: str) -> bool:
    if len(left) != len(right):
        return False
    diff = 0
    for a, b in zip(left, right):
        diff |= ord(a) ^ ord(b)
    return diff == 0


# ---------------------------------------------------------------------------
# client side (used by cli.py)
# ---------------------------------------------------------------------------

class IPCClient:
    def __init__(self, config: Config, timeout: float = 10.0):
        self.path = config.get("agent.socket")
        self.token_path = os.path.join(config.get("agent.run_dir"), "agent.token")
        self.timeout = timeout

    def _token(self) -> str:
        try:
            return util.read_text(self.token_path).strip()
        except OSError:
            return ""

    def available(self) -> bool:
        return os.path.exists(self.path) and bool(self._token())

    def call(self, cmd: str, args: Optional[dict] = None, timeout: Optional[float] = None) -> dict:
        if not os.path.exists(self.path):
            raise AutonomicError("daemon socket not found - is the service running?",
                                 code="ipc.unavailable", socket=self.path)
        token = self._token()
        if not token:
            raise AutonomicError("control token missing - check permissions on the run directory",
                                 code="ipc.no_token", path=self.token_path)
        payload = {"id": util.new_id("r_"), "token": token, "cmd": cmd, "args": args or {}}
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(timeout or self.timeout)
        try:
            sock.connect(self.path)
            sock.sendall((util.json_dumps(payload) + "\n").encode("utf-8"))
            chunks = b""
            while b"\n" not in chunks:
                data = sock.recv(65536)
                if not data:
                    break
                chunks += data
        finally:
            sock.close()
        if not chunks:
            raise AutonomicError("empty response from daemon", code="ipc.empty_response")
        response = util.json_loads(chunks.split(b"\n", 1)[0].decode("utf-8", "replace"), {})
        if not isinstance(response, dict):
            raise AutonomicError("malformed response from daemon", code="ipc.bad_response")
        if not response.get("ok"):
            err = response.get("error") or {}
            raise AutonomicError(str(err.get("message", "unknown error")), code=str(err.get("code", "ipc.error")))
        return response.get("data") or {}
