"""Built-in plugin: systemd failed-unit watch.

`unit.inactive` only checks the units you explicitly list under
``remediation.units``. This detector catches ANY unit that systemd has parked in
the ``failed`` state - the usual way a crash-looping service goes unnoticed
until someone happens to run ``systemctl --failed``.

It only *notifies* (rule risk=low). Restarting an arbitrary failed unit
automatically is too risky, so that stays a human decision.
"""

PLUGIN = {
    "name": "failed_units",
    "version": "1.0.0",
    "description": "Warns when systemd reports any unit in the failed state.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": False},
}

UNIT_SUFFIXES = (".service", ".timer", ".socket", ".mount", ".path",
                 ".target", ".swap", ".device", ".slice", ".scope")
IGNORE_PREFIXES = ("autonomic-ops",)


def setup(ctx):
    ctx.register_detector("failed", detect, interval=60)
    ctx.register_rule({
        "id": "plugin.failed-units-notify",
        "name": "systemd 单元失败 -> 通知",
        "description": "任意 systemd 单元进入 failed 状态时告警；不自动重启，避免误操作。",
        "when": {"kind": "unit.failed", "min_severity": "high"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "systemd unit {{target}} is failed"}},
        "cooldown": 900,
        "max_attempts": 1,
    })
    ctx.log("info", "failed_units armed (interval=60s)")


def detect(ctx, sample):
    try:
        out = ctx.run_command(["systemctl", "--failed", "--no-legend", "--plain"], timeout=8)
    except PermissionError:
        return []
    if not out.get("ok"):
        return []
    findings = []
    seen = set()
    for line in (out.get("stdout") or "").splitlines():
        parts = line.split()
        unit = next((p for p in parts if p.endswith(UNIT_SUFFIXES)), None)
        if not unit or unit in seen:
            continue
        if any(unit.startswith(prefix) for prefix in IGNORE_PREFIXES):
            continue
        seen.add(unit)
        findings.append({
            "kind": "unit.failed",
            "target": unit,
            "value": "failed",
            "severity": "high",
            "message": "systemd unit %s is in the failed state" % unit,
            "evidence": {"unit": unit, "raw": line.strip()[:200]},
        })
    return findings
