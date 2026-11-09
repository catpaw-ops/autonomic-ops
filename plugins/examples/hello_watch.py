"""Example plugin: hot-load test + template for operators.

Drop a copy of this file into the user plugin directory and the daemon picks it
up within ``plugins.scan_interval`` seconds - no restart.

    autonomic-ops plugins install /path/to/hello_watch.py
    autonomic-ops plugins list
"""

import os
import time

PLUGIN = {
    "name": "hello_watch",
    "version": "1.0.0",
    "description": "Reference plugin: emits a finding when a marker file is missing.",
    "author": "AutonomicOps examples",
    "permissions": {"exec": False, "network": False},
}


def setup(ctx):
    # a detector that runs on its own cadence, plus a runtime rule and action
    ctx.register_detector("marker", detect, interval=30)
    ctx.register_action("hello.touch", touch)
    ctx.register_rule({
        "id": "hello.missing-marker",
        "name": "hello_watch: marker missing",
        "when": {"kind": "hello.missing", "min_severity": "low"},
        "then": {"action": "notify", "risk": "low", "params": {"message": "hello_watch: {{target}} missing"}},
        "cooldown": 60,
        "max_attempts": 1,
    })
    ctx.log("info", "hello_watch loaded")


def detect(ctx, sample):
    marker = str(ctx.config.get("plugins.settings.hello_watch.marker", "/tmp/autonomic-hello.marker") or "")
    if marker and not os.path.exists(marker):
        return [{
            "kind": "hello.missing",
            "target": marker,
            "value": "absent",
            "severity": "low",
            "message": f"marker file {marker} is missing",
            "evidence": {"marker": marker, "checked_at": time.time()},
        }]
    return []


def touch(ctx, finding, params):
    marker = str(finding.get("target") or params.get("marker") or "/tmp/autonomic-hello.marker")
    with open(marker, "w", encoding="utf-8") as fh:
        fh.write(f"created by hello_watch at {time.time()}\n")
    return True, f"created {marker}"
