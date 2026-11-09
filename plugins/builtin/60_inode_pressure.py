"""Inode pressure: a filesystem can report free bytes yet still refuse to create files."""

PLUGIN = {
    "name": "inode_pressure",
    "version": "1.0.0",
    "description": "Warns when a filesystem's inode usage is close to exhaustion.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": False},
}

SETTINGS = "plugins.settings.inode_pressure"
PSEUDO_TYPES = {"tmpfs", "devtmpfs", "udev", "overlay", "squashfs", "proc", "sysfs",
                "cgroup", "cgroup2", "devpts", "mqueue", "shm", "ramfs", "debugfs", "tracefs"}


def setup(ctx):
    ctx.register_detector("inodes", detect, interval=300)
    ctx.register_rule({
        "id": "plugin.inode-pressure-notify",
        "name": "inode 使用率过高 -> 通知",
        "when": {"kind": "inode.high", "min_severity": "high"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "inode usage on {{target}} is {{value}}%"}},
        "cooldown": 1800,
        "max_attempts": 1,
    })
    ctx.log("info", "inode_pressure armed (interval=300s)")


def parse_df(text):
    """Parse `df -PTi` output into [(mount, fs_type, percent)]."""
    rows = []
    for line in (text or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        try:
            pct = float(parts[5].rstrip("%"))
        except ValueError:
            continue
        rows.append((" ".join(parts[6:]), parts[1], pct))
    return rows


def detect(ctx, sample):
    warn = float(ctx.config.get(SETTINGS + ".warn_percent", 90) or 90)
    crit = float(ctx.config.get(SETTINGS + ".critical_percent", 95) or 95)
    try:
        out = ctx.run_command(["df", "-PTi"], timeout=8)
    except PermissionError:
        return []
    if not out.get("ok"):
        return []
    findings = []
    for mount, fs_type, pct in parse_df(out.get("stdout")):
        if fs_type in PSEUDO_TYPES or pct < warn:
            continue
        findings.append({
            "kind": "inode.high",
            "target": mount,
            "value": round(pct, 1),
            "severity": "critical" if pct >= crit else "high",
            "message": "inode usage on %s is %.1f%%" % (mount, pct),
            "evidence": {"mount": mount, "fs_type": fs_type, "percent": round(pct, 1)},
        })
    return findings
