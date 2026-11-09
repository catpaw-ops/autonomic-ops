"""Built-in plugin: HTTP site health watch.

After you deploy a site, list the URLs to watch under
``plugins.settings.site_health.sites`` and this detector reports any endpoint
that stops returning HTTP 200. Read-only: it only issues GET requests, never
writes or restarts anything.

Example config::

    plugins:
      settings:
        site_health:
          sites:
            - https://example.com/
            - http://127.0.0.1:8080/
"""

PLUGIN = {
    "name": "site_health",
    "version": "1.0.0",
    "description": "Checks configured HTTP(S) endpoints and reports non-200 responses.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": True},
}

SETTINGS = "plugins.settings.site_health"


def setup(ctx):
    sites = ctx.config.get(SETTINGS + ".sites", []) or []
    ctx.register_detector("sites", detect, interval=60)
    ctx.register_rule({
        "id": "plugin.site-down-notify",
        "name": "站点不可用 -> 通知",
        "description": "配置的站点返回非 200 时告警；不自动重启任何服务。",
        "when": {"kind": "site.down", "min_severity": "medium"},
        "then": {"action": "notify", "risk": "low",
                 "params": {"message": "site {{target}} returned HTTP {{value}}"}},
        "cooldown": 300,
        "max_attempts": 1,
    })
    ctx.log("info", "site_health armed (%d sites, interval=60s)" % len(sites))


def detect(ctx, sample):
    sites = ctx.config.get(SETTINGS + ".sites", []) or []
    findings = []
    for url in sites:
        url = str(url)
        try:
            out = ctx.run_command(
                ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "6", url],
                timeout=10, allow_network=True,
            )
        except PermissionError:
            return []
        code = (out.get("stdout") or "").strip() or "000"
        if code == "200":
            continue
        findings.append({
            "kind": "site.down",
            "target": url,
            "value": code,
            "severity": "high" if code == "000" else "medium",
            "message": "site %s returned HTTP %s" % (url, code),
            "evidence": {"url": url, "code": code},
        })
    return findings
