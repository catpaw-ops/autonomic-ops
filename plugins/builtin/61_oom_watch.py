"""OOM killer watch: catch the process kills that silently take a service down."""

PLUGIN = {
    "name": "oom_watch",
    "version": "1.0.0",
    "description": "Reports kernel OOM-killer events from the kernel log.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": False},
}

SETTINGS = "plugins.settings.oom_watch"
_seen = set()
MAX_SEEN = 500


def setup(ctx):
    ctx.register_detector("oom", detect, interval=60)
    ctx.register_rule({
        "id": "plugin.oom-notify",
        "name": "发生 OOM -> 通知",
        "when": {"kind": "oom.event", "min_severity": "high"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "OOM event: {{target}}"}},
        "cooldown": 600,
        "max_attempts": 1,
    })
    ctx.log("info", "oom_watch armed (interval=60s)")


def oom_lines(text):
    out = []
    for line in (text or "").splitlines():
        low = line.lower()
        if "out of memory" in low or "oom-kill" in low or "killed process" in low:
            out.append(line.strip())
    return out


def detect(ctx, sample):
    lines = []
    try:
        out = ctx.run_command(["journalctl", "-k", "--since", "10 min ago", "--no-pager"], timeout=10)
        if out.get("ok"):
            lines = oom_lines(out.get("stdout"))
    except PermissionError:
        return []
    if not lines:
        try:
            out = ctx.run_command(["dmesg", "-T"], timeout=8)
            if out.get("ok"):
                lines = oom_lines(out.get("stdout"))
        except PermissionError:
            return []
    findings = []
    for line in lines:
        key = line[:160]
        if key in _seen:
            continue
        _seen.add(key)
        findings.append({
            "kind": "oom.event",
            "target": "kernel",
            "value": "oom",
            "severity": "high",
            "message": line[:300],
            "evidence": {"line": line[:300]},
        })
    if len(_seen) > MAX_SEEN:
        _seen.clear()
    return findings
