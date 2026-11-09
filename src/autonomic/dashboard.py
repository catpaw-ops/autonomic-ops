"""Read-only HTTP dashboard (standard library only).

Design goals:
  * read-only: GET only, no write endpoints. Every value is fetched from the
    daemon's existing IPC control plane, so the dashboard can never bypass the
    policy gate or the approval queue - it is a viewer, not a control surface.
  * zero new dependencies: ``http.server`` + vanilla HTML/CSS/JS, no CDN, works
    fully offline / air-gapped.
  * safe default: binds 127.0.0.1. A non-loopback ``--bind`` is refused unless an
    explicit ``--token`` is supplied (the token is then checked on every request).

Run it as root (the IPC token lives in the 0600 run dir)::

    sudo autonomic-ops serve                      # http://127.0.0.1:8787/
    sudo autonomic-ops serve --bind 0.0.0.0:8787 --token <secret>
"""

from __future__ import annotations

import json
import logging
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Optional
from urllib.parse import parse_qs, urlparse

from .errors import AutonomicError
from .ipc import IPCClient

HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>AutonomicOps</title>
<style>
  :root{--bg:#f6f7f9;--card:#fff;--line:#e5e7eb;--text:#111827;--muted:#6b7280;
        --ok:#16a34a;--warn:#d97706;--err:#dc2626;--accent:#2563eb}
  *{box-sizing:border-box}
  body{margin:0;background:var(--bg);color:var(--text);
       font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}
  .wrap{max-width:1080px;margin:0 auto;padding:24px}
  header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:20px}
  .brand{display:flex;align-items:baseline;gap:10px}
  .brand h1{font-size:20px;margin:0;letter-spacing:-.01em}
  .brand .ver{color:var(--muted);font-size:12px}
  .pill{display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:999px;
        background:#ecfdf5;color:var(--ok);font-size:12px;font-weight:600;border:1px solid #bbf7d0}
  .pill.down{background:#fef2f2;color:var(--err);border-color:#fecaca}
  .dot{width:7px;height:7px;border-radius:50%;background:currentColor}
  .sub{color:var(--muted);font-size:12px;margin-top:3px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin-bottom:20px}
  .card{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
  .card .label{color:var(--muted);font-size:12px}
  .card .value{font-size:24px;font-weight:650;margin-top:4px;font-variant-numeric:tabular-nums}
  .row{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px}
  @media(max-width:760px){.row{grid-template-columns:1fr}}
  .panel{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px}
  .panel h2{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);
            margin:0 0 10px;font-weight:700}
  table{width:100%;border-collapse:collapse;font-size:12.5px}
  th,td{text-align:left;padding:7px 8px;border-bottom:1px solid var(--line);vertical-align:top}
  th{color:var(--muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.04em}
  tr:last-child td{border-bottom:none}
  .mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12px}
  .ok{color:var(--ok)}.warn{color:var(--warn)}.err{color:var(--err)}.muted{color:var(--muted)}
  .tag{display:inline-block;padding:1px 7px;border-radius:999px;font-size:11px;font-weight:600;border:1px solid var(--line)}
  .tag.ok{background:#ecfdf5;border-color:#bbf7d0;color:var(--ok)}
  .tag.warn{background:#fffbeb;border-color:#fde68a;color:var(--warn)}
  .tag.err{background:#fef2f2;border-color:#fecaca;color:var(--err)}
  .tag.gray{background:#f3f4f6;color:var(--muted)}
  .bar{height:6px;background:#eef0f3;border-radius:4px;overflow:hidden;margin-top:8px}
  .bar > span{display:block;height:100%;background:var(--accent)}
  .bar.warn > span{background:var(--warn)}.bar.err > span{background:var(--err)}
  .empty{color:var(--muted);font-size:12.5px;padding:6px 0}
  .kv{display:flex;flex-wrap:wrap;gap:8px 20px;font-size:12.5px}
  .kv div{display:flex;gap:6px}
  footer{color:var(--muted);font-size:11.5px;margin-top:20px;display:flex;
         justify-content:space-between;gap:10px;flex-wrap:wrap}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <div class="brand"><h1>AutonomicOps</h1><span class="ver" id="ver">v&mdash;</span></div>
    <div style="text-align:right">
      <span class="pill" id="pill"><span class="dot"></span><span id="pillText">connecting&hellip;</span></span>
      <div class="sub" id="node">&mdash;</div>
    </div>
  </header>

  <div class="grid" id="metrics"></div>

  <div class="row">
    <div class="panel">
      <h2>Security</h2>
      <div class="kv" id="security"></div>
      <div id="diskWrap" style="display:none">
        <div class="sub" id="diskLabel" style="margin-top:10px"></div>
        <div class="bar" id="diskBar"><span id="diskFill" style="width:0%"></span></div>
      </div>
    </div>
    <div class="panel">
      <h2>Queue</h2>
      <div class="kv" id="queue"></div>
    </div>
  </div>

  <div class="panel" style="margin-bottom:16px">
    <h2>Active bans</h2>
    <table><thead><tr><th>IP</th><th>Reason</th><th>Backend</th><th>Remaining</th></tr></thead>
      <tbody id="bans"></tbody></table>
  </div>

  <div class="row">
    <div class="panel">
      <h2>Recent tasks</h2>
      <table><thead><tr><th>ID</th><th>Kind</th><th>Title</th><th>State</th></tr></thead>
        <tbody id="tasks"></tbody></table>
    </div>
    <div class="panel">
      <h2>Pending approvals</h2>
      <table><thead><tr><th>ID</th><th>Action</th><th>Target</th><th>Risk</th></tr></thead>
        <tbody id="pending"></tbody></table>
    </div>
  </div>

  <footer><span>read-only &middot; auto-refresh 5s</span><span class="mono" id="audit"></span></footer>
</div>

<script>
const $ = id => document.getElementById(id);
const esc = s => String(s==null?"":s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const kv = (k,v) => `<div><span class="muted">${esc(k)}</span> ${v}</div>`;
function uptime(s){s=Math.max(0,Math.floor(s||0));const d=Math.floor(s/86400),h=Math.floor(s%86400/3600),m=Math.floor(s%3600/60);
  return (d?d+"d ":"")+(h?h+"h ":"")+m+"m";}
function remain(s){s=Math.max(0,Math.floor(s||0));return Math.floor(s/60)+"m "+(s%60)+"s";}
function pctClass(p){return p>=90?"err":p>=75?"warn":"ok";}
async function api(path){const r=await fetch(path,{cache:"no-store"});const j=await r.json();
  if(!j.ok) throw new Error(j.error||"request failed");return j.data;}

function card(label,value){return `<div class="card"><div class="label">${esc(label)}</div><div class="value">${esc(value)}</div></div>`;}

async function refresh(){
  try{
    const s = await api("/api/status");
    $("ver").textContent = "v"+(s.version||"\u2014");
    $("node").textContent = (s.node_id||"")+" \u00b7 pid "+(s.pid||"\u2014")+" \u00b7 up "+uptime(s.uptime_seconds);
    $("pill").className="pill"; $("pillText").textContent="running";

    const m = s.metrics||{}; const disks = m.disks||[];
    const root = disks.find(d=>d.path==="/") || disks[0];
    let cards = card("CPU", m.cpu_percent!=null?m.cpu_percent.toFixed(1)+"%":"\u2014")
      + card("Memory", m.mem_percent!=null?m.mem_percent.toFixed(1)+"%":"\u2014")
      + card("Load (1m)", m.load1!=null?Number(m.load1).toFixed(2):"\u2014")
      + card("Connections", m.connections!=null?m.connections:"\u2014")
      + card("SSH failures", m.ssh_failures!=null?m.ssh_failures:"\u2014");
    if(root) cards += card("Disk "+root.path, root.percent!=null?root.percent.toFixed(1)+"%":"\u2014");
    $("metrics").innerHTML = cards;

    const sec = s.security||{}; const fw = sec.firewall||{}; const rules = s.rules||{}; const audit = s.audit||{};
    $("security").innerHTML = kv("Firewall",`<b>${esc(s.firewall_backend||fw.backend||"\u2014")}</b>`)
      + kv("Simulated", fw.simulated?`<span class="tag warn">yes</span>`:`<span class="tag ok">no</span>`)
      + kv("Active bans",`<b>${esc((sec.bans||[]).length)}</b>`)
      + kv("Rules",`<b>${esc(rules.count!=null?rules.count:"\u2014")}</b>`)
      + kv("Audit records",`<b>${esc(audit.records!=null?audit.records:"\u2014")}</b>`);

    const q = s.queue||{}; const w = q.workers||{};
    $("queue").innerHTML = kv("Depth",`<b>${esc(q.queue_depth!=null?q.queue_depth:"\u2014")}</b>`)
      + kv("Running",`<b>${esc(q.running!=null?q.running:"\u2014")}</b>`)
      + kv("Workers",`<b>${esc(w.size!=null?w.size:"\u2014")}</b>`)
      + kv("Pending approval",`<b>${esc(s.pending_approval!=null?s.pending_approval:"\u2014")}</b>`);

    const bans = (await api("/api/bans")).bans||[];
    $("bans").innerHTML = bans.length ? bans.map(x=>`<tr><td class="mono">${esc(x.ip)}</td><td>${esc(x.reason||"")}</td><td>${esc(x.backend||"")}</td><td>${remain(x.remaining)}</td></tr>`).join("")
      : `<tr><td colspan="4" class="empty">No active bans.</td></tr>`;

    const tasks = (await api("/api/tasks")).tasks||[];
    $("tasks").innerHTML = tasks.length ? tasks.slice(0,8).map(t=>{
      const st=t.state||""; const cls=st==="failed"?"err":(st==="done"||st==="succeeded")?"ok":st==="running"?"warn":"gray";
      return `<tr><td class="mono">${esc(t.id)}</td><td>${esc(t.kind||"")}</td><td>${esc((t.title||"").slice(0,38))}</td><td><span class="tag ${cls}">${esc(st)}</span></td></tr>`;
    }).join("") : `<tr><td colspan="4" class="empty">No recent tasks.</td></tr>`;

    const pend = (await api("/api/pending")).pending||[];
    $("pending").innerHTML = pend.length ? pend.slice(0,8).map(p=>{
      const req=p.request||{}, dec=p.decision||{}, risk=dec.risk||"";
      const cls=risk==="high"?"err":risk==="medium"?"warn":"gray";
      return `<tr><td class="mono">${esc(req.id)}</td><td>${esc(req.action||"")}</td><td class="mono">${esc((req.target||"").slice(0,22))}</td><td><span class="tag ${cls}">${esc(risk)}</span></td></tr>`;
    }).join("") : `<tr><td colspan="4" class="empty">Nothing waiting for approval.</td></tr>`;

    $("audit").textContent = "audit "+((audit.records!=null)?audit.records:"\u2014")+" \u00b7 last "+String(audit.last_hash||"").slice(0,12);

    if(root && root.percent!=null){
      $("diskWrap").style.display="block";
      $("diskLabel").textContent = "Disk "+root.path+" \u00b7 "+root.percent.toFixed(1)+"% used";
      $("diskFill").style.width = Math.min(100,root.percent)+"%";
      $("diskBar").className = "bar "+pctClass(root.percent);
    }
  }catch(e){
    $("pill").className="pill down"; $("pillText").textContent="daemon unreachable";
  }
}
refresh(); setInterval(refresh, 5000);
</script>
</body>
</html>
"""


def _num(value):
    if value is None:
        return "0"
    try:
        return str(float(value))
    except (TypeError, ValueError):
        return "0"


def _prometheus(status: dict, bans: dict) -> str:
    """Render the daemon status as Prometheus text exposition format."""
    m = status.get("metrics") or {}
    q = status.get("queue") or {}
    w = q.get("workers") or {}
    sec = status.get("security") or {}
    fw = sec.get("firewall") or {}
    audit = status.get("audit") or {}
    rules = status.get("rules") or {}
    plugins = status.get("plugins") or {}
    lines = [
        "# HELP autonomic_up 1 if the daemon answered this scrape.",
        "# TYPE autonomic_up gauge",
        "autonomic_up 1",
        "# HELP autonomic_cpu_percent CPU usage percent.",
        "# TYPE autonomic_cpu_percent gauge",
        "autonomic_cpu_percent %s" % _num(m.get("cpu_percent")),
        "# HELP autonomic_mem_percent Memory usage percent.",
        "# TYPE autonomic_mem_percent gauge",
        "autonomic_mem_percent %s" % _num(m.get("mem_percent")),
        "# HELP autonomic_load1 1-minute load average.",
        "# TYPE autonomic_load1 gauge",
        "autonomic_load1 %s" % _num(m.get("load1")),
        "# HELP autonomic_ssh_failures Total failed SSH logins seen.",
        "# TYPE autonomic_ssh_failures counter",
        "autonomic_ssh_failures %s" % _num(m.get("ssh_failures")),
        "# HELP autonomic_queue_depth Tasks waiting in the queue.",
        "# TYPE autonomic_queue_depth gauge",
        "autonomic_queue_depth %s" % _num(q.get("queue_depth")),
        "# HELP autonomic_queue_running Tasks currently running.",
        "# TYPE autonomic_queue_running gauge",
        "autonomic_queue_running %s" % _num(q.get("running")),
        "# HELP autonomic_workers Configured worker count.",
        "# TYPE autonomic_workers gauge",
        "autonomic_workers %s" % _num(w.get("size")),
        "# HELP autonomic_pending_approval Actions waiting for approval.",
        "# TYPE autonomic_pending_approval gauge",
        "autonomic_pending_approval %s" % _num(status.get("pending_approval")),
        "# HELP autonomic_bans_active Active firewall bans.",
        "# TYPE autonomic_bans_active gauge",
        "autonomic_bans_active %s" % _num(len(bans.get("bans") or [])),
        "# HELP autonomic_audit_records Audit chain length.",
        "# TYPE autonomic_audit_records counter",
        "autonomic_audit_records %s" % _num(audit.get("records")),
        "# HELP autonomic_rules Loaded rule count.",
        "# TYPE autonomic_rules gauge",
        "autonomic_rules %s" % _num(rules.get("count")),
        "# HELP autonomic_plugins Loaded plugin count.",
        "# TYPE autonomic_plugins gauge",
        "autonomic_plugins %s" % _num(plugins.get("loaded")),
        "# HELP autonomic_uptime_seconds Daemon uptime in seconds.",
        "# TYPE autonomic_uptime_seconds gauge",
        "autonomic_uptime_seconds %s" % _num(status.get("uptime_seconds")),
        "# HELP autonomic_simulated 1 if the firewall backend is simulated.",
        "# TYPE autonomic_simulated gauge",
        "autonomic_simulated %s" % ("1" if fw.get("simulated") else "0"),
    ]
    for disk in (m.get("disks") or []):
        mount = disk.get("path")
        if mount:
            lines.append('autonomic_disk_percent{mount="%s"} %s' % (mount, _num(disk.get("percent"))))
    return "\n".join(lines) + "\n"


def _loopback(host: str) -> bool:
    return host in ("127.0.0.1", "localhost", "::1", "")


def serve(config, bind: str = "127.0.0.1:8787", token: str = "",
          logger: Optional[logging.Logger] = None) -> int:
    host, sep, port_s = bind.rpartition(":")
    if not sep:
        host, port_s = "127.0.0.1", bind
    try:
        port = int(port_s)
    except ValueError:
        raise SystemExit("invalid --bind %r; expected HOST:PORT (e.g. 127.0.0.1:8787)" % bind)
    if not _loopback(host) and not token:
        raise SystemExit("refusing to bind non-loopback %r without --token; "
                         "e.g. --bind 0.0.0.0:8787 --token <secret>" % host)

    client = IPCClient(config, timeout=8)
    log = logger or logging.getLogger("autonomic.dashboard")

    class Handler(BaseHTTPRequestHandler):
        server_version = "AutonomicOpsDashboard/1.0"

        def log_message(self, fmt, *args):  # keep the console clean
            return

        def _send(self, code: int, body, ctype: str = "application/json", extra=None):
            data = body if isinstance(body, (bytes, bytearray)) else str(body).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            try:
                self.wfile.write(data)
            except OSError:
                pass

        def _authorized(self) -> bool:
            if not token:
                return True
            qs = parse_qs(urlparse(self.path).query)
            if qs.get("token", [""])[0] == token:
                return True
            return ("ao_token=" + token) in (self.headers.get("Cookie") or "")

        def do_GET(self):  # noqa: N802 - stdlib naming
            parsed = urlparse(self.path)
            if not self._authorized():
                self._send(401, json.dumps({"ok": False, "error": "unauthorized"}))
                return
            if parsed.path == "/":
                qs = parse_qs(parsed.query)
                if token and qs.get("token", [""])[0] == token:
                    self._send(302, b"", extra={
                        "Location": "/",
                        "Set-Cookie": "ao_token=%s; Path=/; HttpOnly; SameSite=Strict" % token,
                    })
                    return
                self._send(200, HTML, ctype="text/html; charset=utf-8", extra={
                    "Content-Security-Policy":
                        "default-src 'self'; style-src 'unsafe-inline'; "
                        "script-src 'unsafe-inline'; img-src 'self' data:",
                })
                return
            if parsed.path == "/metrics":
                try:
                    text = _prometheus(client.call("status"), client.call("bans"))
                    self._send(200, text, ctype="text/plain; version=0.0.4; charset=utf-8")
                except AutonomicError as exc:
                    self._send(503, "# error: %s\n" % exc.message,
                               ctype="text/plain; charset=utf-8")
                return
            if parsed.path.startswith("/api/"):
                mapping = {
                    "status": ("status", {}),
                    "bans": ("bans", {}),
                    "tasks": ("tasks", {"all": True, "limit": 20}),
                    "pending": ("pending", {"limit": 20}),
                    "rules": ("rules", {"action": "list"}),
                    "audit": ("audit", {"action": "tail", "lines": 25}),
                }
                key = parsed.path[5:]
                if key not in mapping:
                    self._send(404, json.dumps({"ok": False, "error": "not found"}))
                    return
                cmd, args = mapping[key]
                try:
                    data = client.call(cmd, args)
                    self._send(200, json.dumps({"ok": True, "data": data}, ensure_ascii=False))
                except AutonomicError as exc:
                    self._send(503, json.dumps({"ok": False, "error": exc.message}))
                except Exception as exc:  # noqa: BLE001 - never leak tracebacks
                    self._send(500, json.dumps({"ok": False, "error": str(exc)[:200]}))
                return
            self._send(404, json.dumps({"ok": False, "error": "not found"}))

    httpd = ThreadingHTTPServer((host, port), Handler)
    httpd.daemon_threads = True
    url = "http://%s:%d/" % (host, port)
    print("[serve] read-only dashboard on %s" % url)
    if token:
        print("[serve] token required: open %s?token=<your --token> once" % url)
    log.info("dashboard listening on %s", url)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[serve] stopped")
    finally:
        httpd.server_close()
    return 0
