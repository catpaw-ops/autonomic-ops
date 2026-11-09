# AutonomicOps 架构说明

版本 `1.0.0` / 代号 `aegis`。本文描述真实实现（对应 `src/autonomic/` 下 32 个模块），不是设计草案。

---

## 1. 设计目标与约束

| 目标 | 架构上的落点 |
|---|---|
| 无人值守 | `Daemon` 拉起后自行采样 → 检测 → 规则 → 策略 → 执行，全程无需人 |
| 不抢占终端 | 主进程默认双 fork，stdout/stderr 重定向到 `logs/console.log`；日志只进文件；交互只走 `cli.py` |
| 任务不互相踩 | 调度器 + 有界队列 + Worker 池 + 每任务 timeout/CPU/内存上限 + 进程组 kill |
| 对话不粗暴打断 | 新意图进入 `Scheduler.submit()`，由优先级、aging、抢占阈值统一裁决；抢占是"安全取消 + 重新入队" |
| 变更可回滚 | `ActionCoordinator` 对高危动作先 `BackupManager.snapshot()`，审计记 `rollback_point` |
| 能力不足不撒谎 | 启动即探测 root / nft / iptables / netns / systemd，降级写进响应字段与日志 notes |
| 可扩展不重启 | `PluginManager` 周期扫描插件目录，import → `setup(ctx)` → 注册 detector/action/rule |
| 核心不可自改 | `CoreIntegrity` 哈希清单 + `policy.core_self_modify=false` + `codegen` 目标路径守卫 |

非目标：多机共识、容器编排、图形界面、替代专业 SIEM。它是**单机自治运维进程**，远程部署只是把同一套东西装到另一台机器。

---

## 2. 进程与线程模型

```text
                       ┌──────────────────────────── Daemon (PID 1 个) ───────────────────────────┐
                       │                                                                          │
  systemd / supervisor │  MainThread: 启动装配 → IPC accept 循环 → 信号处理 → 有序停机            │
                       │                                                                          │
                       │  sub-bus-*        Bus 每个订阅一个线程（有界队列，慢订阅者不拖垮发布者） │
                       │  sub-metrics      MetricsSampler: 定时 sample() → bus.publish("metrics")  │
                       │  sub-detector     DetectorEngine: 消费 metrics / 安全事件 → Finding       │
                       │  sub-rule-feed    RuleEngine: Finding → ActionRequest                     │
                       │  sub-scheduler    Scheduler.tick(): 每 0.5s 派发 / 抢占 / 收敛           │
                       │  worker-1..N      Worker: 取任务 → Executor / Sandbox → 回报 on_done      │
                       │  sub-plugin-scan  PluginManager: 每 5s 扫描目录，热加载/卸载               │
                       │  sub-watchdog     Watchdog: 心跳、RSS/fd 上限、核心 hash 校验               │
                       └──────────────────────────────────────────────────────────────────────────┘
```

- 所有跨线程状态用 `threading.RLock` 保护；队列有界（`scheduler.queue_max`、Bus 每订阅队列上限）。
- 日志写入用 `RotatingFileHandler`，11 个通道各自独立文件，互不阻塞。
- 停机顺序：停 IPC → 停 sampler/plugins/watchdog → `scheduler.stop()`（给 Worker 宽限）→ `pool.stop()` → flush 日志 → 写 `daemon.stop` 审计 → 删 pidfile。

---

## 3. 模块划分

| 模块 | 职责 | 关键类型 / 函数 |
|---|---|---|
| `version.py` | 版本常量 | `VERSION`, `CODENAME`, `PRODUCT` |
| `errors.py` | 统一错误码 | `AutonomicError(code=...)` 及子类 |
| `util.py` | 零依赖工具 | `atomic_write`, `redact`, `valid_ipv4`, `safe_join`, `sha256_file`, `tail_lines` |
| `yamlmini.py` | 无 PyYAML 时的 YAML 子集解析 | `safe_load()`；制表符、锚点等不支持时显式报错 |
| `config.py` | 默认值 + 加载 + 校验 + 热重载 | `DEFAULTS`, `load_config()`, `Config.check_dirs()` |
| `logs.py` | 11 通道日志、轮转、密钥脱敏 | `LogManager.channel()`, `tail()`, `sizes()` |
| `bus.py` | 进程内发布/订阅 | `Bus.publish/subscribe`，每订阅独立线程与有界队列 |
| `models.py` | 数据契约 | `Task`, `Finding`, `ActionRequest`, `PolicyDecision`, `Decision`, `ExecResult` |
| `audit.py` | 哈希链审计 | `AuditLog.record/tail/query/verify` |
| `backup.py` | 内容寻址快照与回滚 | `BackupManager.snapshot/restore/prune` |
| `policy.py` | 权限模型 | `PolicyEngine.decide()`, `check_shell()`, `check_restart_command()`, `RateLimiter`, `CoreIntegrity`, `PendingStore` |
| `sandbox.py` | 受限执行 | `Sandbox.run()`：rlimit + timeout + 可选 netns + 进程组 kill |
| `metrics.py` | 指标采集 | CPU/负载/内存/磁盘/端口/进程/unit/连接/SSH |
| `detect.py` | 检测引擎 | 9 个内置检测器 + `_Sustained` 连续样本门槛 |
| `rules.py` | 规则引擎 | YAML 规则、模板渲染、冷却/最大尝试、运行时规则 |
| `executor.py` | 动作执行 | 15 个 handler + `ActionCoordinator`（快照/审批/审计） |
| `security.py` | 防火墙、封禁策略、配置审计 | `Firewall`, `BanPolicy`, `ConfigAuditor` |
| `codegen.py` | 生成 + 校验 + 应用 | `CodeGenerator.generate/validate/apply` |
| `workers.py` | Worker 与池 | `Worker._run_with_deadline()`, `WorkerPool.resize()` |
| `scheduler.py` | 队列、优先级、抢占、恢复 | `Scheduler.submit/_dispatch/_pick_preemption_victim/recover` |
| `plugins.py` | 插件加载器 | `PluginManager.scan/_load_plugin/invoke_action` |
| `chat.py` | 对话意图解析 | `ChatService.handle()` → `Scheduler.submit()` |
| `ipc.py` | Unix socket RPC | `IPCServer`, `IPCClient`，token 常量时间比较 |
| `daemon.py` | 总装与命令路由 | `Daemon.handle_ipc()`（30 个命令） |
| `main.py` | 入口 | `--foreground`, `--check-config`, `--doctor`, `--daemonize` |
| `cli.py` | 运维 CLI | 全部子命令；`logs -f` 直接 tail 文件 |
| `selfcheck.py` | 19 项 doctor | 分级 `ok/warning/info/error`，只有 `error` 计 failed |
| `bootstrap.py` | 远程部署 | `Deployer.plan/_simulate/_remote`，7 步 |
| `watchdog.py` | 存活与资源看门狗 | heartbeat、RSS/fd、核心 hash、`emergency_exit(99)` |

---

## 4. 消息总线

`Bus` 是进程内的轻量事件总线，不做持久化：

- `publish(topic, payload)`：按前缀匹配订阅（`metrics`、`finding`、`task.*`），投递到每个订阅的有界队列；队列满时丢弃最旧事件并计数，保证发布者不被慢消费者拖死。
- `subscribe(pattern, handler)`：每个订阅一个 daemon 线程，串行消费；异常被捕获并写 `error.log`，不终止订阅。
- 主要 topic：
  - `metrics` — 一次完整样本（dict）
  - `finding` — `Finding.to_dict()`
  - `action.request` — 规则产生的动作请求
  - `task.state` — 任务状态变化（供 UI/审计/插件观察）
  - `security.event` — 登录失败、连接异常等
  - `plugin.loaded` / `plugin.unloaded`

为什么不用消息队列中间件：单机产品，零外部依赖是硬要求；进程内总线足够，且崩溃后状态由 `tasks.jsonl` / `audit.log` / `bans.json` 恢复。

---

## 5. 调度逻辑

### 5.1 数据结构

- `waiting`：按有效优先级排序的等待队列（`heapq` 或排序列表）
- `running`：`task_id -> Task`
- `journal_path = data/tasks.jsonl`：每次状态变化追加一行，用于重启恢复与事后追溯
- `decisions`：最近 15 条 `Decision`，`status` 里可直接看到"为什么排队/为什么抢占"

### 5.2 有效优先级（防饿死）

```text
effective = min(priority + aging_rate * waited_seconds, priority + aging_cap)
```

默认 `aging_rate=0.25`、`aging_cap=25`。低优先级任务等 100 秒约 +25 分，不会被无限插队。

优先级档位：`BACKGROUND 10 / ROUTINE 30 / SECURITY 55 / REMOTE 60 / USER 70 / CRITICAL 90 / EMERGENCY 99`。对话默认 70；消息里带"紧急/立刻/马上/urgent"升到 90。

### 5.3 派发（每 tick 0.5s）

1. 取出有效优先级最高的等待任务。
2. 找一个空闲 Worker；有 → `assign()`，`Decision(kind="submit")`。
3. 无空闲：
   - 若新任务可抢占、且 `新有效优先级 - 受害者优先级 > preempt_threshold(15)`、受害者 `preemptible=true`：
     - 选**优先级最低、运行时间最短**的受害者；
     - 置 `task.cancel_event`，Worker 在 0.2s 内轮询到并 kill 进程组；
     - 受害者 `attempt += 1`；未超过 `preempt_requeue_limit(2)` 则重新入队，否则标记 `failed(preempted too many times)`；
     - `Decision(kind="preempt", compared_with=victim_id)`；
   - 否则 `Decision(kind="queue", queue_position=n)`，任务留在队列。
4. 去重：同 `kind + target` 在 `dedupe_window(30s)` 内只保留一个，避免检测器抖动导致任务风暴。
5. 限流：`max_actions_per_minute` 限制自动动作提交速率。

### 5.4 重启恢复

`Scheduler.recover()` 在 `start()` 之前执行：读 `tasks.jsonl` 尾部，把状态为 `queued/running` 且 `source in (user, remote)`、`kind != action` 的任务重新入队（`attempt+1`）。自动动作不重放，避免重启后重复处置。

### 5.5 Worker

- 每个 Worker 一个线程 + 一个 `queue.Queue(maxsize=1)`。
- `assign()` 成功后立即把 `task` 写入 `self.current` 预留，避免同一 tick 把第二个任务塞进同一个 Worker。
- `_run_with_deadline()`：0.2s 轮询 `cancel_event`；超时或取消 → `sandbox` kill 进程组（`os.killpg`），返回 `cancelled=True`。
- 任务失败 / 超时 / 取消都写 `task.log` 与审计，`on_done` 回调让调度器继续派发。

---

## 6. 权限模型（Policy Engine）

`PolicyEngine.decide(request)` 的判定顺序（短路）：

1. `dry_run` → `deny(dry-run)`，只记录不执行。
2. 目标路径命中 `policy.forbidden_paths`（前缀匹配，解析真实路径后比较）→ `deny(forbidden-path)`。
3. `action` 不在 `policy.whitelist` → `pending_approval`（除非调用方已带 `approved_by`）。
4. `action` 在 `approval_required` → 需要人工批准；`critical_always_approval` 时 `risk >= critical` 一律批准制。
5. `risk > max_auto_risk` → `pending_approval`。
6. 速率限制 `RateLimiter`（`max_actions_per_minute`）→ 超限 `deny(rate-limited)`。
7. 通过 → `allow`，审计 `policy.decide`，然后交给 `ActionCoordinator`。

风险等级默认表：`noop/notify/diagnostic=low`；`process.restart/service.restart/disk.cleanup/log.rotate/cache.cleanup=medium`；`firewall.ban_ip/file.delete/system.config.modify/plugin.install/code.patch=high`；`sudo.modify=critical`。

核心完整性：`CoreIntegrity` 在安装时生成 `data/core-manifest.json`（`src/autonomic/*.py` 的 sha256）。`is_core_path()` 命中即拒绝 `code.patch`；`verify()` 在 watchdog 中周期执行，发现漂移写 `error.log` 并计入 doctor。

待批准存储：`data/pending/<request_id>.json`，`cli pending` 列出，`approve` 后重新走 `PolicyEngine`（带 `approved_by`）再执行，`reject` 只记录。

配置中的重启配方（`remediation.processes.<name>.command`）是管理员自己写的命令，天然需要重定向与后台化，因此**不适用**只读 shell 白名单；但执行前会经过 `PolicyEngine.check_restart_command()`：拒绝命中危险模式、含控制字符或超长的命令，避免被篡改的配置演变成以 root 权限执行任意命令。

---

## 7. 沙箱隔离方案

`sandbox.run(argv, timeout, cpu_seconds, memory_mb, cancel_event, allow_network)`：

| 层 | 手段 | 失败时 |
|---|---|---|
| 进程隔离 | `start_new_session=True`，独立进程组 | 始终可用 |
| 资源限制 | `sh -c 'ulimit -t <cpu>; ulimit -v <mem_kb>; exec "$@"'` | `ulimit` 不可用时记录 note，仍靠 timeout |
| 时间限制 | 主线程 `deadline` 轮询 + `killpg` | 始终可用 |
| 网络隔离 | `unshare -n`（需 CAP_SYS_ADMIN / userns） | 不可用 → `degraded_isolation=True`，notes 明确"网络未隔离" |
| 文件隔离 | 每次运行独立 `run-<rand>/`，`HOME`/`TMPDIR` 指向其中；结束后删除 | 始终可用 |
| 环境变量 | 只传 `PATH/LANG/LC_ALL/HOME/TMPDIR` 白名单；`*KEY*/*TOKEN*/*SECRET*/*PASSWORD*` 一律不传 | 始终可用 |

自测环境（非 root、`unshare` 被拒）下，`doctor` 与 `ExecResult.notes` 会明确写 `degraded isolation: rlimits+timeout only`。这不是缺陷，是**能力探测后的显式降级**。

> 注意：这不是容器级隔离。不可信代码仍应只在一次性 VM / 容器里跑；本沙箱的目标是防"手滑脚本"和"死循环"，不是防定向逃逸。

**非 POSIX 开发机**：`os.name != "posix"`（Windows）时没有 `rlimit`、进程组与 netns，`Sandbox.run()` 直接启动子进程，并**强制**在结果里写入 `degraded_isolation=True` 与说明性 notes；`capabilities()` 同步返回 `posix: false`、`netns: false`、`ulimit: false`。这条路径只服务于单元测试与 `doctor` 的跨机可用性，**生产隔离仍然只在 Linux 上成立**。

---

## 8. 检测与规则

### 8.1 采集

`MetricsCollector.sample()` 一次产出：

- `cpu.percent`（`/proc/stat` 差分）、`cores`
- `load.load1/5/15`、`per_core`
- `memory.total/available/percent`
- `disks[]`：`path/total/used/free/percent`（`shutil.disk_usage`）
- `ports[]`：TCP connect 探测，记录 `latency_ms/open/error`
- `processes[]`：`/proc/*/cmdline` 匹配
- `units[]`：`systemctl is-active`（无 systemd 时 `offline`）
- `connections`：`/proc/net/tcp*` 状态统计
- `ssh`：从 `security.ssh_log_paths`（默认 `/var/log/auth.log`、`/var/log/secure`、`journalctl`）尾部窗口解析 `Failed password` / `Invalid user` / `Accepted`

### 8.2 内置检测器（9 个）

`load`、`memory`、`disk`、`port`、`process`、`unit`、`ssh`、`conn`、`traffic`。

- 负载 / 内存 / 磁盘 / 端口连续 `metrics.sustained_samples(3)` 个样本越线才报，抑制瞬时抖动。
- SSH 暴破：窗口 `ssh_fail_threshold(5)` 次失败即报，target=源 IP，severity=high。
- 连接洪泛：单 IP 连接数 / 半开连接超阈值。
- 流量突增：`/proc/net/dev` 差分，超过 `traffic` 阈值报 `traffic.spike`。

### 8.3 规则

`config/rules/*.yaml`，字段：

```yaml
- id: sec.ssh-bruteforce-ban
  when: {kind: ssh.bruteforce, min_severity: high}
  then: {action: firewall.ban_ip, risk: high, params: {duration: 3600}}
  cooldown: 600
  max_attempts: 2
```

`target_regex` 可选；`params` 支持 `{{target}} {{value}} {{severity}} {{host}} {{evidence.xxx}}` 模板。规则冷却窗口内超过 `max_attempts` 即抑制并写 `decision.log`。插件可注册运行时规则，`rules reload` 不丢运行时规则。

---

## 9. 执行器与回滚链路

`ActionExecutor` 注册 15 个 handler：`noop / notify / diagnostic / process.restart / service.restart / disk.cleanup / cache.cleanup / log.rotate / firewall.ban_ip / firewall.unban_ip / file.delete / shell.exec / plugin.install / plugin.action / code.patch / system.config.modify`。

`ActionCoordinator.execute(request)`：

1. 再走一次 `PolicyEngine`（防止调用方绕过）。
2. 调 handler。变更类 handler（`disk.cleanup` / `file.delete` / `code.patch` / `system.config.modify`）在真正写入或删除之前调用 `BackupManager.snapshot()`，把快照 id 放进 `ActionResult.rollback_point`。
3. handler 返回 `ActionResult(ok, detail, changed_files, rollback_point, verified)`；只读 handler（`notify` / `diagnostic` / `noop`）不建快照。
4. 写 `audit.record(actor, trigger, action, target, params, result, files_changed, rollback_point)`。
5. 失败也写审计；`rollback_point` 为空时明确标注"无快照"。

备份格式：

```text
backups/<snapshot_id>/
├── manifest.json      # 文件列表、sha256、大小、原始路径、创建时间
└── files/<sha256>     # 内容寻址，重复内容只存一份
```

`restore()` 先为"当前状态"再拍一个 `pre-rollback` 快照（可选），再按 manifest 还原；支持 `max_snapshots` / `retention` / `max_file_bytes` / `max_total` 限制。

磁盘清理（`_h_disk_cleanup`）：

- 只在 `policy.cleanup_paths` 范围内；
- 只删 `mtime` 超过 `cleanup_min_age_hours` 的普通文件；
- 不跟随目录符号链接；只处理普通文件（非符号链接）、`size > 0`、`mtime` 早于 cutoff 的文件；根目录必须落在 `policy.cleanup_paths` 内；
- 先快照再删，返回 `snapshot=... complete=True failed=0`。

---

## 10. 安全防护

### 10.1 防火墙后端探测

`Firewall.__init__` 顺序探测：

1. `nft` 存在且 `nft list tables` 可执行 → `nft`
2. `iptables` 存在且 `iptables -L` 可执行 → `iptables`
3. 否则 → `recorder`

`recorder` 语义：**只记录意图，不改主机防火墙**。`ban()` 返回 `simulated: true`，`command` 写成 `SIMULATED: iptables -I INPUT ...`，并落 `data/security/firewall-intents.jsonl`。API / CLI / 审计三处都带 `simulated`，不会出现"以为封了其实没封"。

### 10.2 封禁策略

- `guard_ip()`：拒绝非法 IPv4、本机地址、私网/保留地址（`allow_private` 可放开），防误封自己。
- `BanPolicy.can_auto_ban()`：`security.auto_ban` 与 `ban_requires_approval` 双开关；`max_bans_per_hour` 限速。
- 封禁记录 `data/security/bans.json`：`ip/reason/created_at/expires_at/duration/backend/command/simulated/verified`。
- `sweep()` 周期清理到期封禁；`unban` 生成反向命令并写意图流水。
- 配置审计 `ConfigAuditor`：检查 agent 配置权限（group/other 可读即告警）、SSH 关键项、危险 sudo 规则等。

### 10.3 入侵与流量

- SSH 暴破（见上）+ 成功登录来自新 IP 可作为 `ssh.new_source` 观察项。
- 连接洪泛：`conn.flood`，按源 IP 聚合。
- 流量突增：`traffic.spike`，按接口差分，超过阈值报。
- 所有 finding 进同一规则引擎，处置仍受白名单约束。

---

## 11. 代码生成与校验

`CodeGenerator`：

- **后端**：内置确定性模板；生成后强制走校验链。
- **模板**：`systemd_unit / shell_healthcheck / nginx_site / python_probe / logrotate_conf / config_fragment`。
- **校验链**（任一失败即 `rejected`）：
  1. `encoding`：UTF-8、无 NUL、大小上限
  2. `static-risk-scan`：19 条危险模式（`rm -rf /`、`mkfs`、`dd of=/dev/`、`chmod 777 /`、反弹 shell、`curl|sh` 等）
  3. 语法：Python `compile()`；shell `sh -n`；systemd 必需 `[Unit]/[Service]`；nginx 基本块配对；YAML 可解析
  4. `sandbox-prerun`：可执行脚本在沙箱里跑（默认 10s / 10s CPU / 256MB）
  5. `policy`：目标路径禁止清单、核心路径保护、`code.patch` 审批要求
- **应用**：先快照目标（存在则备份，不存在则记录"新建"），`atomic_write`（临时文件 + fsync + rename），审计 `code.patch` + `rollback_point`。目标路径命中 `/etc/passwd` 等直接 `rejected`，不落盘。

---

## 12. 插件体系

- 目录：`plugins.dirs`（生产模板默认 `<prefix>/plugins/builtin`，见 `config/config.example.yaml`；可按需追加 `data/plugins`、`plugins/user` 等）。仓库内插件清单见 `docs/PLUGIN_DEV.md` 第 0 节。
- 扫描：`scan_interval=5s`；文件签名（mtime+size+sha256）不变不重复加载；被拒插件缓存签名，避免每轮刷错误日志。
- 校验：大小 ≤ `max_plugin_bytes`；禁止 `os.system`、`eval`、`exec`、`__import__`、`ctypes`、直接 `socket` 等；`PLUGIN` 字典必须含 `name/version/permissions`。
- 生命周期：`import → setup(ctx) → 注册 → 运行 → unload（调用清理）`。
- 权限：`exec` 才可 `ctx.run_command()`；`network` 才可联网；`ctx.read_text()` 只允许 `/proc /sys /var/log /etc /tmp` 前缀。
- 错误熔断：同一插件连续 `error_disable_threshold(5)` 次异常自动卸载并写 `plugin.log`。
- 详见 [`PLUGIN_DEV.md`](PLUGIN_DEV.md)。

---

## 13. IPC 与 CLI

- Unix domain socket：`run_dir/agent.sock`，权限 `0600`；token 存 `run_dir/ipc.token`，权限 `0600`。
- 协议：一行一个 JSON 请求 `{"cmd": "...", "token": "...", ...}`，一行一个 JSON 响应；`_constant_time_equals` 比较 token。
- 未授权统一返回 `{"ok": false, "error": {"code": "ipc.unauthorized"}}`，不泄露命令是否存在。
- 30 个命令：`ping/status/metrics/tasks/task.get/task.cancel/task.submit/chat/chat.history/logs/pending/approve/reject/rollback/snapshots/plugins/rules/bans/unban/audit/workers/config/codegen/doctor/deploy/version/stop`。
- CLI 是**纯客户端**：不 import daemon，不共享内存；`logs -f` 直接 tail 文件，不经过 socket，避免大日志拖垮 RPC。

---

## 14. 日志与审计

| 通道 | 文件 | 内容 |
|---|---|---|
| runtime | `runtime.log` | 生命周期、调度、Worker、插件、配置 |
| error | `error.log` | 异常与失败（含 traceback 摘要） |
| task | `task.log` | 任务开始/结束/超时/取消/重排 |
| decision | `decision.log` | 规则命中、策略判定、排队/抢占原因 |
| security | `security.log` | 封禁、解封、配置审计、登录异常 |
| plugin | `plugin.log` | 加载/卸载/拒绝/熔断 |
| metrics | `metrics.log` | 采样摘要 |
| codegen | `codegen.log` | 生成、校验、应用 |
| chat | `chat.log` | 对话原文与回复 |
| backup | `backup.log` | 快照、回滚、清理 |
| audit | `audit.log` | 哈希链审计（JSONL） |

审计记录字段：`seq / ts / epoch / actor / trigger / action / target / params / files_changed / result / rollback_point / extra / prev_hash / hash`。

`hash = sha256(prev_hash + canonical_json(record_without_hash))`，创世 `prev_hash = "0"*64`。`audit verify` 逐行重算，任何改动都会暴露 `hash mismatch` 或 `prev_hash mismatch`。

---

## 15. 远程部署（bootstrap）

`Deployer.deploy(host, token, apply)` 七步：

1. `authorize`：校验 `bootstrap.authorization_token` 非空且匹配；校验 host 合法、非私网（`allow_private` 可放开）
2. `package`：打包 `src/ plugins/ config/ scripts/ systemd/` 为 tar.gz
3. `upload`：`scp` 到远端临时路径
4. `install`：`ssh` 执行 `mkdir -p <root> && tar xzf ... --strip-components=1 && bash scripts/install.sh --prefix <root> --non-interactive --bootstrap-token <token>`
5. `verify`：检查 `<root>/lib/autonomic/main.py`、`<root>/bin/autonomic-ops`、`<root>/config/rules/default_rules.yaml`
6. `start`：`systemctl enable --now autonomic-ops`（无 systemd 则 supervisor）
7. `report`：返回每步状态、耗时、远端路径

`--simulate` 走 `_simulate()`：在 `bootstrap.simulate_root` 下建假根、复制文件、执行真实 `install.sh --simulate`，验证安装契约，不触网、不改系统。自测即用此模式。

---

## 16. 看门狗与故障自愈

`Watchdog` 线程每 `interval=10s`：

- 写 `run_dir/heartbeat.json`（`ts/pid/rss_mb/fd/workers/queue`）。
- RSS > `max_rss_mb` 或 fd > `max_fd` → `_log.critical` + `emergency_exit(99)`（systemd `Restart=on-failure` 拉起）。
- 整机兜底：`systemd/autonomic-ops.service` 另设 `LimitNOFILE` / `LimitNPROC` / `MemoryMax` / `TasksMax`，与每任务 rlimit 互补，防 fork 失控或内存泄漏拖垮宿主机。`MemoryMax` 必须大于 `watchdog.max_rss_mb`，否则看门狗会反复触发重启。
- 每 `core_integrity_interval=60s` 校验核心 hash，漂移只告警不自杀（避免被误判为攻击面）。
- 外部 `scripts/watchdog.sh` 可选：heartbeat 超过 90s 未更新 → `systemctl restart autonomic-ops`（应对主线程死锁）。对应的 `autonomic-ops-watchdog.service` 通过 `Requires=` + `After=` 依赖主 unit，**与主服务同时运行**；主 unit 不得对它声明 `Conflicts=`，否则 systemd 会生成互相矛盾的 stop/start 事务，外部看门狗永远无法启用。

---

## 17. 能力探测与降级矩阵

| 能力 | 探测方式 | 不可用时行为 | 对外字段 |
|---|---|---|---|
| root | `os.geteuid()==0` | 不能改系统文件 / 防火墙；doctor 记 warning | `doctor.root` |
| nft | `nft list tables` | 回落 iptables | `security.firewall.backend` |
| iptables | `iptables -L` | 回落 recorder，只记意图 | `simulated: true` |
| netns | `unshare -n true` | 沙箱标降级，仅 rlimit+timeout | `ExecResult.degraded_isolation`, `notes` |
| systemd | `systemctl is-system-running` | pidfile supervisor，`service` 子命令走文件锁 | `doctor.systemd` |
| PyYAML | `import yaml` | `yamlmini` 子集解析 | `doctor.yaml` |

原则：**任何降级都写进返回值、日志和 doctor，绝不静默**。

---

## 18. 已知边界

- 单机单实例（pidfile + socket 双重互斥）；不做集群选主。
- 审计链防篡改但不防"有 root 的攻击者整链重写"；需要外部日志服务器时请转发 `audit.log`。
- `recorder` 后端不提供真实封禁能力，只提供意图与可执行命令。
- 沙箱不是安全容器；不可信代码请放到一次性 VM。
- SSH 统计基于日志尾部窗口，日志轮转/采集中断会影响计数，`evidence.note` 已标注。
- `codegen` 的所有输出都必须过校验链，校验失败即拒绝，不"尽力修复后硬写"。
