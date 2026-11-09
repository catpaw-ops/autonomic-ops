"""Built-in plugin: TLS certificate expiry watch.

Silent until certificate paths are configured. Uses `openssl x509` through the
permissioned sandbox rather than parsing ASN.1 by hand.
"""

import datetime
import os
import re

PLUGIN = {
    "name": "cert_expiry",
    "version": "1.0.0",
    "description": "Warns when configured TLS certificates are close to expiry.",
    "author": "AutonomicOps",
    "permissions": {"exec": True, "network": False},
}

SETTINGS = "plugins.settings.cert_expiry"


def setup(ctx):
    ctx.register_detector("expiry", detect, interval=3600)
    if str(ctx.config.get(f"{SETTINGS}.paths", "") or ""):
        ctx.log("info", "cert_expiry armed")


def detect(ctx, sample):
    paths = ctx.config.get(f"{SETTINGS}.paths", []) or []
    warn_days = int(ctx.config.get(f"{SETTINGS}.warn_days", 14) or 14)
    crit_days = int(ctx.config.get(f"{SETTINGS}.critical_days", 3) or 3)
    findings = []
    for path in paths:
        if not os.path.isfile(str(path)):
            continue
        try:
            out = ctx.run_command(["openssl", "x509", "-in", str(path), "-noout", "-enddate"], timeout=8)
        except PermissionError:
            return []
        if not out.get("ok"):
            continue
        match = re.search(r"notAfter=(.+)", out.get("stdout", ""))
        if not match:
            continue
        try:
            expiry = datetime.datetime.strptime(match.group(1).strip(), "%b %d %H:%M:%S %Y %Z")
        except ValueError:
            continue
        days = (expiry - datetime.datetime.utcnow()).days
        if days <= warn_days:
            findings.append({
                "kind": "cert.expiring",
                "target": str(path),
                "value": days,
                "severity": "critical" if days <= crit_days else "high",
                "message": f"certificate {path} expires in {days} days ({expiry.date()})",
                "evidence": {"path": str(path), "days": days},
            })
    return findings
