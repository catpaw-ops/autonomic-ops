"""Disk growth projection: warn before a filesystem fills, not after.

The detector keeps the previous sample per mount and projects the time-to-full
from the observed growth rate. It stays silent until it has at least two samples
spaced by MIN_INTERVAL, so a one-off burst does not trigger a false alarm.
"""

import time

PLUGIN = {
    "name": "disk_growth",
    "version": "1.0.0",
    "description": "Projects when a filesystem will fill up from its recent growth rate.",
    "author": "AutonomicOps",
    "permissions": {"exec": False, "network": False},
}

SETTINGS = "plugins.settings.disk_growth"
MIN_INTERVAL = 900  # seconds between comparable samples
_history = {}


def setup(ctx):
    ctx.register_detector("growth", detect, interval=900)
    ctx.register_rule({
        "id": "plugin.disk-growth-notify",
        "name": "磁盘增长过快 -> 通知",
        "when": {"kind": "disk.growth", "min_severity": "medium"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "{{target}} will fill in about {{value}} hours"}},
        "cooldown": 3600,
        "max_attempts": 1,
    })
    ctx.log("info", "disk_growth armed (interval=900s)")


def project(prev_pct, now_pct, prev_ts, now_ts, horizon_hours=24):
    """Return projected hours-to-full, or None if it is not worth reporting."""
    if now_ts <= prev_ts or now_pct <= prev_pct:
        return None
    rate = (now_pct - prev_pct) / (now_ts - prev_ts)  # percent per second
    if rate <= 0:
        return None
    hours = (100.0 - now_pct) / rate / 3600.0
    return hours if 0 <= hours <= horizon_hours else None


def detect(ctx, sample):
    horizon = float(ctx.config.get(SETTINGS + ".horizon_hours", 24) or 24)
    now_ts = time.time()
    findings = []
    for disk in (sample.get("disks") or []):
        mount = disk.get("path") or disk.get("mount")
        pct = disk.get("percent")
        if not mount or pct is None:
            continue
        prev = _history.get(mount)
        _history[mount] = (now_ts, float(pct))
        if not prev:
            continue
        prev_ts, prev_pct = prev
        if now_ts - prev_ts < MIN_INTERVAL:
            continue
        hours = project(prev_pct, float(pct), prev_ts, now_ts, horizon)
        if hours is None:
            continue
        per_hour = (float(pct) - prev_pct) / max(1.0, (now_ts - prev_ts) / 3600.0)
        findings.append({
            "kind": "disk.growth",
            "target": mount,
            "value": round(hours, 1),
            "severity": "high" if hours <= 4 else "medium",
            "message": "%s is growing %.1f%%/h and will fill in about %.1f h" % (mount, per_hour, hours),
            "evidence": {"mount": mount, "percent": pct, "hours_to_full": round(hours, 1)},
        })
    return findings
