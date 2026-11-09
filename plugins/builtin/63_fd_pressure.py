"""File-descriptor pressure: `EMFILE` shows up as "too many open files" at the worst time."""

PLUGIN = {
    "name": "fd_pressure",
    "version": "1.0.0",
    "description": "Warns when the system-wide file descriptor table is nearly full.",
    "author": "AutonomicOps",
    "permissions": {"exec": False, "network": False},
}

SETTINGS = "plugins.settings.fd_pressure"


def setup(ctx):
    ctx.register_detector("fds", detect, interval=120)
    ctx.register_rule({
        "id": "plugin.fd-pressure-notify",
        "name": "文件描述符紧张 -> 通知",
        "when": {"kind": "fd.high", "min_severity": "high"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "file descriptors at {{value}}%"}},
        "cooldown": 1800,
        "max_attempts": 1,
    })
    ctx.log("info", "fd_pressure armed (interval=120s)")


def parse_file_nr(text):
    parts = (text or "").split()
    if len(parts) < 3:
        return None
    try:
        allocated, maximum = int(parts[0]), int(parts[2])
    except ValueError:
        return None
    if maximum <= 0:
        return None
    return allocated, maximum


def detect(ctx, sample):
    warn = float(ctx.config.get(SETTINGS + ".warn_percent", 80) or 80)
    crit = float(ctx.config.get(SETTINGS + ".critical_percent", 95) or 95)
    try:
        text = ctx.read_text("/proc/sys/fs/file-nr")
    except (PermissionError, OSError):
        return []
    parsed = parse_file_nr(text)
    if not parsed:
        return []
    allocated, maximum = parsed
    pct = 100.0 * allocated / maximum
    if pct < warn:
        return []
    return [{
        "kind": "fd.high",
        "target": "system",
        "value": round(pct, 1),
        "severity": "critical" if pct >= crit else "high",
        "message": "file descriptors at %.1f%% (%d/%d)" % (pct, allocated, maximum),
        "evidence": {"allocated": allocated, "max": maximum, "percent": round(pct, 1)},
    }]
