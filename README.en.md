# AutonomicOps

> A self-hosted, offline-capable, rollback-safe single-node operations agent.

AutonomicOps is a long-running operations agent for a single Linux host. It periodically collects system metrics, uses built-in detectors and pluggable plugins to surface anomalies, and performs **bounded remediation** (restart a service, clean stale files, ban a suspicious IP, send an alert, …) according to declarative rules and policy. Every file-changing action is snapshotted first and can be rolled back with one command; the entire run is recorded in a hash-chained audit log.

Design principles:

- **Self-hosted** — everything runs on your own machine; no external cloud service is required.
- **Offline-first** — the core runs with **zero outbound network, zero API keys, zero model dependencies**. The optional Webhook alert is a one-way outbound notification you enable explicitly.
- **Rollback-safe** — every file-changing action is snapshotted before it executes; mistakes can be undone.
- **Bounded execution** — actions are constrained by a whitelist, risk tiers, approval, forbidden paths, and a sandbox; core code cannot modify itself.

---

## What it solves

Traditional "monitoring + alerting" pages you at 3 a.m. but the fix is still manual. AutonomicOps automates the common, already-declared remediation steps: bring a crashed service back up, clean stale files when disk runs high, ban a source IP after SSH brute-force, and surface status on a read-only dashboard.

It is **not** a general AI agent and will not perform undeclared high-risk operations. Every automated action must be on the policy whitelist and under the configured risk ceiling; anything beyond that becomes a pending proposal awaiting human approval.

---

## Core capabilities

| Area | Highlights |
| --- | --- |
| Metrics | CPU, load, memory, disk (per mount), port liveness, processes, systemd units, connections, SSH, traffic |
| Built-in detectors | high load, memory pressure, disk pressure, closed port, inactive/failed unit, SSH brute-force, connection flood, traffic spike |
| Plugin detectors | log error spike, certificate expiry, backup freshness, failed units, site health, inode pressure, OOM watch, time drift, fd pressure, disk-growth forecast |
| Rule engine | YAML `kind + threshold → action`, with priority scheduling, debounce, dedupe, rate limiting, retries |
| Remediation | restart process/service, clean disk/cache, rotate logs, webhook alert, ban/unban IP, delete file, modify config, apply patch, install package, limited shell, diagnose, template-generate, remote-deploy |
| Security | whitelist, risk tiers, human approval, forbidden paths, shell allowlist, core self-modify guard, ProtectSystem/PrivateTmp/sandbox |
| Rollback & audit | content-addressed snapshots, byte-level rollback, hash-chained audit log, core integrity manifest |
| Observability | read-only web dashboard (GET-only, bound to 127.0.0.1 by default), Prometheus `/metrics`, structured logs |
| Plugins | hot reload, capability gate, error circuit-breaker; drop a `.py` following the naming convention |

---

## Quick start

### Requirements

- Linux (systemd 235+; systemd 245+ recommended for the nftables backend)
- Python 3.9+

### Install

```bash
bash scripts/install.sh --prefix /opt/autonomic-ops --non-interactive
```

The installer lays down the library, CLI, config template, rules, plugins, and unit files under `--prefix` and registers `autonomic-ops.service` for boot. After install, edit `/opt/autonomic-ops/config/config.yaml` for your host, then:

```bash
sudo systemctl restart autonomic-ops
```

### Verify

```bash
/opt/autonomic-ops/bin/autonomic-ops status
/opt/autonomic-ops/bin/autonomic-ops doctor
/opt/autonomic-ops/bin/autonomic-ops metrics
python3 -m unittest discover tests -v
bash tests/selftest.sh
```

### Read-only dashboard

```bash
/opt/autonomic-ops/bin/autonomic-ops serve --port 8081 --bind 127.0.0.1
```

Open `http://127.0.0.1:8081/` for status, metrics, bans, tasks, pending approvals, and the audit tail; `/metrics` exposes Prometheus-format metrics. The dashboard only reads state — it offers no write path.

---

## Configuration

Primary config: `config/config.example.yaml` (copy to `config.yaml` after install). Key sections: `agent`, `scheduler`, `policy`, `metrics`, `security`, `backup`/`audit`, `plugins`, `chat`/`codegen`.

**Important constraint**: if the systemd unit uses `PrivateTmp=yes` (default), the agent sees its own private `/tmp` and `/var/tmp` namespaces and cannot see the host's real files there. Point `policy.cleanup_paths` at real, visible, writable directories such as `/var/log` and `/var/cache` — **not** `/tmp` or `/var/tmp`.

See [docs/USAGE.md](docs/USAGE.md) and [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## License

MIT — see [LICENSE](LICENSE).

## Disclaimer

AutonomicOps is an operations aid and **does not replace human judgment or change review**. Automated remediation can misfire and cause outages or data loss. Validate thoroughly in a test environment before enabling it, and keep human approval for critical actions. See [DISCLAIMER.md](DISCLAIMER.md).
