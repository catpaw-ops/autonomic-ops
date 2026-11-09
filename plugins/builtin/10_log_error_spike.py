"""Built-in plugin: application log error spike detector.

This is deliberately a plugin rather than core code: log formats differ wildly
between products, and an operator should be able to disable or replace this
without touching the supervisor.
"""

PLUGIN = {
    "name": "log_error_spike",
    "version": "1.0.0",
    "description": "Counts ERROR/CRITICAL lines in a configured log tail window and emits a finding on spikes.",
    "author": "AutonomicOps",
    "permissions": {"exec": False, "network": False},
}

SETTINGS = "plugins.settings.log_error_spike"
_STATE = {"last_count": 0}


def setup(ctx):
    ctx.register_detector("spike", detect, interval=60)
    ctx.log("info", "log_error_spike armed")


def detect(ctx, sample):
    path = str(ctx.config.get(f"{SETTINGS}.path", "") or "")
    if not path:
        return []
    threshold = int(ctx.config.get(f"{SETTINGS}.threshold", 20) or 20)
    window_bytes = int(ctx.config.get(f"{SETTINGS}.window_bytes", 262144) or 262144)
    text = ctx.read_text(path, max_bytes=window_bytes)
    if not text:
        return []
    count = sum(1 for line in text.splitlines() if "ERROR" in line or "CRITICAL" in line)
    previous = _STATE["last_count"]
    _STATE["last_count"] = count
    if count >= threshold:
        return [{
            "kind": "log.error_spike",
            "target": path,
            "value": count,
            "severity": "high" if count >= threshold * 3 else "medium",
            "message": f"{count} error lines in the tail window (threshold {threshold}); previous sample {previous}",
            "evidence": {"path": path, "threshold": threshold},
        }]
    return []
