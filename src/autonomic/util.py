"""Small, dependency-free helpers shared by every module.

Design rule: no third-party imports here. This module is used by the CLI
(which must start fast and must not pull the whole daemon import graph).
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import socket
import stat
import sys
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Iterator, Optional

_SECRET_RE = re.compile(
    r"(?i)(api[_-]?key|token|secret|password|passwd|authorization)\s*[:=]\s*"
    r"(['\"]?)([^\s'\"]{4,})\2"
)
_IP_RE = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def now() -> float:
    return time.time()


def iso(ts: Optional[float] = None, timespec: str = "seconds") -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else now(), tz=timezone.utc)
    return dt.astimezone().isoformat(timespec=timespec)


def utc_stamp(ts: Optional[float] = None) -> str:
    dt = datetime.fromtimestamp(ts if ts is not None else now(), tz=timezone.utc)
    return dt.strftime("%Y%m%dT%H%M%SZ")


def new_id(prefix: str = "") -> str:
    raw = uuid.uuid4().hex[:12]
    return f"{prefix}{raw}" if prefix else raw


def ensure_dir(path: str, mode: int = 0o750) -> str:
    if path:
        os.makedirs(path, mode=mode, exist_ok=True)
    return path


def chmod_private(path: str) -> None:
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_file(path: str, chunk: int = 65536) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def file_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def read_text(path: str, default: str = "", max_bytes: int = 2_000_000) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read(max_bytes)
    except OSError:
        return default


def atomic_write(path: str, content: str, mode: Optional[int] = None) -> None:
    """Write via temp file + fsync + rename; never leaves a half-written file."""
    directory = os.path.dirname(os.path.abspath(path)) or "."
    ensure_dir(directory)
    tmp = os.path.join(directory, f".{os.path.basename(path)}.{uuid.uuid4().hex[:8]}.tmp")
    try:
        with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.unlink(tmp)
            except OSError:
                pass


def json_dumps(obj: Any, pretty: bool = False) -> str:
    return json.dumps(
        obj,
        ensure_ascii=False,
        sort_keys=pretty,
        indent=2 if pretty else None,
        separators=None if pretty else (",", ":"),
        default=str,
    )


def json_loads(text: str, default: Any = None) -> Any:
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        return default


def redact(text: str) -> str:
    """Redact secrets before they reach any log file or IPC response."""
    if not text:
        return text

    def _sub(match: re.Match) -> str:
        return f"{match.group(1)}=***REDACTED***"

    return _SECRET_RE.sub(_sub, str(text))


def human_bytes(num: float) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(num) < 1024.0:
            return f"{num:3.1f}{unit}"
        num /= 1024.0
    return f"{num:.1f}PiB"


def clamp(value: float, low: float, high: float) -> float:
    return max(low, min(high, value))


def valid_ipv4(ip: str) -> bool:
    m = _IP_RE.match(str(ip).strip())
    if not m:
        return False
    return all(0 <= int(part) <= 255 for part in m.groups())


def is_private_or_local_ip(ip: str, self_ips: Iterable[str] = ()) -> bool:
    """True for loopback / RFC1918 / link-local / CGNAT / multicast / self.

    Used by the firewall guard: the agent must never lock itself out by banning
    the management IP, localhost, or its own address.
    """
    if not valid_ipv4(ip):
        return True
    if ip in set(self_ips) or ip.startswith("127.") or ip == "0.0.0.0":
        return True
    parts = [int(p) for p in ip.split(".")]
    if parts[0] == 10:
        return True
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    if parts[0] == 192 and parts[1] == 168:
        return True
    if parts[0] == 169 and parts[1] == 254:
        return True
    if parts[0] == 100 and 64 <= parts[1] <= 127:  # CGNAT
        return True
    if 224 <= parts[0] <= 239:  # multicast
        return True
    return False


def local_ips() -> list[str]:
    ips = {"127.0.0.1"}
    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None, socket.AF_INET):
            ips.add(info[4][0])
    except OSError:
        pass
    return sorted(ips)


def tail_lines(path: str, lines: int = 50) -> list[str]:
    """Read the last N lines without loading a multi-GB log into memory."""
    if not os.path.exists(path):
        return []
    with open(path, "rb") as fh:
        fh.seek(0, os.SEEK_END)
        size = fh.tell()
        block = 4096
        data = b""
        while size > 0 and data.count(b"\n") <= lines:
            step = min(block, size)
            size -= step
            fh.seek(size)
            data = fh.read(step) + data
            block = min(block * 2, 1 << 20)
    text = data.decode("utf-8", errors="replace")
    return text.splitlines()[-lines:]


def safe_join(root: str, *parts: str) -> str:
    """Join and guarantee the result stays inside root (path traversal guard)."""
    root_abs = os.path.abspath(root)
    candidate = os.path.abspath(os.path.join(root_abs, *parts))
    if candidate != root_abs and not candidate.startswith(root_abs + os.sep):
        raise ValueError(f"path escapes root: {candidate}")
    return candidate


def is_world_writable(path: str) -> bool:
    try:
        return bool(os.stat(path).st_mode & stat.S_IWOTH)
    except OSError:
        return False


def writable(path: str) -> bool:
    try:
        probe = os.path.join(path, f".write-probe-{uuid.uuid4().hex[:6]}")
        with open(probe, "w") as fh:
            fh.write("ok")
        os.unlink(probe)
        return True
    except OSError:
        return False


def is_posix() -> bool:
    """True where rlimits / process groups / network namespaces exist.

    The daemon is Linux-only, but ``doctor`` and the unit tests are expected
    to be usable on a contributor's Windows or macOS machine as well.
    """
    return os.name == "posix"


def geteuid() -> int:
    """Effective UID, or -1 on platforms without ``os.geteuid`` (Windows)."""
    getter = getattr(os, "geteuid", None)
    return int(getter()) if getter else -1


def is_root() -> bool:
    """Privilege check that never raises on non-POSIX hosts."""
    return geteuid() == 0


def which(name: str) -> Optional[str]:
    """Locate an executable.

    Keep the original POSIX resolution (used by firewall / unshare probes)
    unchanged, and delegate to the stdlib resolver elsewhere so Windows PATH
    separators and PATHEXT are handled correctly.
    """
    if os.name != "posix":
        try:
            return shutil.which(name) or None
        except (TypeError, ValueError, OSError):
            return None
    for base in os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin").split(":"):
        candidate = os.path.join(base, name)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def parse_int(value: Any, default: int = 0, low: Optional[int] = None, high: Optional[int] = None) -> int:
    try:
        out = int(value)
    except (TypeError, ValueError):
        return default
    if low is not None:
        out = max(low, out)
    if high is not None:
        out = min(high, out)
    return out


def parse_float(value: Any, default: float = 0.0, low: Optional[float] = None, high: Optional[float] = None) -> float:
    try:
        out = float(value)
    except (TypeError, ValueError):
        return default
    if low is not None:
        out = max(low, out)
    if high is not None:
        out = min(high, out)
    return out


def parse_bool(value: Any, default: bool = False) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("1", "true", "yes", "on", "y"):
            return True
        if lowered in ("0", "false", "no", "off", "n", ""):
            return False
    return default


def duration_text(seconds: float) -> str:
    seconds = max(0, int(seconds))
    if seconds < 60:
        return f"{seconds}s"
    if seconds < 3600:
        return f"{seconds // 60}m{seconds % 60:02d}s"
    return f"{seconds // 3600}h{(seconds % 3600) // 60:02d}m"


def chunked(iterable: Iterable, size: int) -> Iterator[list]:
    buf: list = []
    for item in iterable:
        buf.append(item)
        if len(buf) >= size:
            yield buf
            buf = []
    if buf:
        yield buf


def cpu_count() -> int:
    try:
        return len(os.sched_getaffinity(0))
    except AttributeError:
        return os.cpu_count() or 1


def _safe_stdout(message: str) -> None:
    """Only used by CLI / one-shot commands. The daemon never writes to stdout."""
    try:
        sys.stdout.write(message + "\n")
        sys.stdout.flush()
    except Exception:
        pass


def banner() -> str:
    from .version import version_string

    return version_string()
