"""Clock sync watch: an unsynchronised clock breaks TLS, auth and audit ordering."""

PLUGIN = {
    "name": "time_drift",
    "version": "1.0.0",
    "description": "Warns when the system clock is not NTP-synchronised.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": False},
}

SETTINGS = "plugins.settings.time_drift"


def setup(ctx):
    ctx.register_detector("clock", detect, interval=600)
    ctx.register_rule({
        "id": "plugin.time-unsynced-notify",
        "name": "时钟未同步 -> 通知",
        "when": {"kind": "time.unsynced", "min_severity": "medium"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "system clock is not synchronised"}},
        "cooldown": 3600,
        "max_attempts": 1,
    })
    ctx.log("info", "time_drift armed (interval=600s)")


def detect(ctx, sample):
    try:
        out = ctx.run_command(["timedatectl", "show", "-p", "NTPSynchronized"], timeout=8)
    except PermissionError:
        return []
    if not out.get("ok"):
        return []
    text = (out.get("stdout") or "").strip()
    if "NTPSynchronized=yes" in text:
        return []
    return [{
        "kind": "time.unsynced",
        "target": "clock",
        "value": text or "unknown",
        "severity": "medium",
        "message": "system clock is not NTP-synchronised (%s)" % (text or "no data"),
        "evidence": {"timedatectl": text},
    }]
