"""Built-in plugin: backup freshness watchdog.

A backup system that stops running is worse than none, because it creates false
confidence. This plugin checks the newest snapshot age and raises a finding.
"""

import os
import time

PLUGIN = {
    "name": "backup_freshness",
    "version": "1.0.0",
    "description": "Reports when the newest local snapshot is older than the configured budget.",
    "author": "AutonomicOps",
    "permissions": {"exec": False, "network": False},
}

SETTINGS = "plugins.settings.backup_freshness"


def setup(ctx):
    ctx.register_detector("freshness", detect, interval=1800)


def detect(ctx, sample):
    if not ctx.config.get("backup.enabled", True):
        return []
    max_age_hours = int(ctx.config.get(f"{SETTINGS}.max_age_hours", 48) or 48)
    backup_dir = str(ctx.config.get("backup.dir", ""))
    if not backup_dir or not os.path.isdir(backup_dir):
        return []
    newest = 0.0
    for name in os.listdir(backup_dir):
        full = os.path.join(backup_dir, name)
        if os.path.isdir(full):
            try:
                newest = max(newest, os.path.getmtime(full))
            except OSError:
                continue
    if not newest:
        return [{
            "kind": "backup.stale", "target": backup_dir, "value": "no snapshots",
            "severity": "medium", "message": "no local snapshots exist yet",
        }]
    age_hours = (time.time() - newest) / 3600
    if age_hours >= max_age_hours:
        return [{
            "kind": "backup.stale", "target": backup_dir, "value": round(age_hours, 1),
            "severity": "high" if age_hours >= max_age_hours * 2 else "medium",
            "message": f"newest snapshot is {age_hours:.1f}h old (budget {max_age_hours}h)",
            "evidence": {"backup_dir": backup_dir, "age_hours": round(age_hours, 1)},
        }]
    return []
