# 使用手册（USAGE）

本文档覆盖命令行、配置字段、规则编写、动作清单与插件开发入门。安装与 systemd 集成见 [DEPLOYMENT.md](DEPLOYMENT.md)。

---

## 1. 命令行（CLI）

CLI 入口：`autonomic-ops --config /path/to/config.yaml <subcommand>`。常用子命令：

| 命令 | 作用 |
| --- | --- |
| `status` | 守护进程、调度器、Worker 池、运行时状态 |
| `metrics` | 最近一次指标样本（CPU/负载/内存/磁盘/端口/单元/连接） |
| `doctor` | 环境与配置诊断，输出 `failed=0` 表示通过 |
| `tasks` / `task <id>` | 列出/查看任务 |
| `cancel <id>` | 取消任务 |
| `pending` | 列出待人工审批的提案 |
| `approve <id>` / `reject <id>` | 批准/拒绝提案 |
| `rollback --snapshot <id>` | 回滚到某个快照 |
| `snapshots` | 列出快照 |
| `bans` / `unban <ip>` | 查看封禁 / 解封 |
| `audit` | 审计日志（尾/校验/查询） |
| `plugins` / `plugin-push` | 插件管理 / 推送插件到远端节点 |
| `rules` | 规则查看 / 热加载 |
| `workers <n>` | 调整 Worker 池大小 |
| `config get|validate|reload` | 配置读取 / 校验 / 热加载 |
| `codegen` | 模板生成并校验配置/脚本/补丁 |
| `deploy` | 远程初始化一台服务器（含一次性授权令牌） |
| `service start|stop|restart|status` | systemd / pidfile 服务控制 |
| `serve` | 启动只读 Web 面板（默认绑 `127.0.0.1`） |
| `chat "<text>"` | 通过确定性关键词路由发送控制指令（如 `chat "restart demoapp"`） |

---

## 2. 配置字段速查

完整说明以 `config/config.example.yaml` 内联注释为准。下面列出最关键的分段与字段。

### `agent`
- `name`：节点显示名。
- `data_dir` / `log_dir` / `run_dir`：数据、日志、运行目录（安装到自定义前缀时自动改写）。
- `log_level`：日志级别（`DEBUG`/`INFO`/`WARNING`/`ERROR`）。

### `scheduler`
- `workers` / `max_workers`：Worker 池大小。
- `tick_interval`：调度节拍（秒）。
- `default_task_timeout`：单任务默认超时。
- `aging_rate` / `aging_cap`：任务优先级老化参数。
- `preemption`：是否允许高优先级任务抢占。

### `policy`
- `auto_remediate`：是否自动处置（关闭则所有动作转人工）。
- `max_auto_risk`：自动执行允许的最高风险（`low`/`medium`/`high`/`critical`）。
- `critical_always_approval`：critical 风险动作是否必须人工确认。
- `whitelist`：自动执行的动作白名单。
- `approval_required`：必须人工确认的动作清单。
- `forbidden_paths`：硬禁止写入的目标路径。
- `cleanup_paths`：磁盘清理只允许在此范围内删除文件（**避开 `/tmp`、`/var/tmp`**）。
- `cleanup_min_age_hours` / `cleanup_max_files` / `cleanup_max_bytes`：清理的保留时长与体积上限。
- `shell_allowlist` / `shell_forbidden_patterns`：受限 shell 的允许前缀与禁止正则。
- `core_self_modify`：是否允许代理修改自身核心代码（默认 `false`）。

### `metrics`
- `interval`：采集间隔（秒）。
- `disk_paths`：需要监视的磁盘挂载点。
- `watch_ports` / `watch_processes` / `watch_units`：端口、进程、systemd 单元监视列表。
- `disk_warn_percent` / `disk_critical_percent`：磁盘阈值。
- `load_warn` / `load_critical`、`mem_warn_percent` / `mem_critical_percent`：负载与内存阈值。
- `ssh_log_paths`、`ssh_fail_threshold`、`ssh_fail_window`：SSH 暴破检测参数。
- `sustained_samples`：连续样本数（防抖）。

### `security`
- `ids_enabled`：入侵检测开关。
- `auto_ban`：是否自动封禁（默认 `false`，需审批）。
- `ban_requires_approval`：封禁是否需审批。
- `firewall_backend`：`nft` / `iptables` / `recorder`（recorder 仅记录意图不实际改防火墙）。
- `protect_private_ips`：保护私有/保留/回环 IP 不被误封。
- `expose_check_ports`：对外暴露端口检查（22/3306/6379/27017 等）。

### `backup` / `audit`
- `enabled`：快照 / 审计开关。
- `max_snapshots` / `retention_days` / `max_total_bytes`：保留策略。
- `auto_rollback_on_failure`：动作执行失败时自动回滚。
- `chain`：审计哈希链开关。

### `plugins`
- `enabled`：插件系统开关。
- `dirs`：插件目录列表（热加载）。
- `error_disable_threshold`：单插件错误超过阈值即熔断。

---

## 3. 规则编写

规则位于 `config/rules/*.yaml`，每条规则把"发现"映射到"动作"。结构示例：

```yaml
- id: core.disk-cleanup-critical
  name: 磁盘使用率 critical -> 清理过期文件
  when:
    kind: disk.high
    min_severity: critical
  then:
    action: disk.cleanup
    risk: medium
    params:
      min_age_hours: 48
      max_files: 500
      max_bytes: 2147483648
  cooldown: 1800
  max_attempts: 2
```

- `when.kind`：匹配的发现类型（如 `disk.high`、`unit.inactive`、`port.closed`、`ssh.blast`）。
- `when.min_severity`：最低严重级别（`low`/`medium`/`high`/`critical`）。
- `then.action`：要执行的动作（须在 `policy.whitelist` 内，且风险不超过 `max_auto_risk`）。
- `then.risk`：动作声明风险；最终风险取声明与默认风险中的较高者。
- `cooldown`：同目标两次触发的最小间隔（秒）。
- `max_attempts`：窗口内最多尝试次数（超过后抑制，避免无效循环）。

可用的发现类型（节选）：`load.high`、`memory.high`、`disk.high`、`port.closed`、`process.missing`、`unit.inactive`、`ssh.blast`、`conn.flood`、`traffic.spike`，以及插件产生的 `log.errorspike`、`cert.expiry`、`backup.stale`、`site.unhealthy`、`inode.pressure`、`oom.watch`、`time.drift`、`fd.pressure`、`disk.growth`。

---

## 4. 动作清单（含默认风险）

| 动作 | 默认风险 | 说明 |
| --- | --- | --- |
| `process.restart` | medium | 重启进程 |
| `service.restart` | medium | 重启 systemd 单元 |
| `disk.cleanup` | medium | 在 `cleanup_paths` 内删除超龄文件（先快照后删，可回滚） |
| `cache.cleanup` | medium | 清理缓存目录 |
| `log.rotate` | medium | 轮转日志 |
| `notify.webhook` | low | 向 `notify.webhook_url` POST 事件 |
| `firewall.ban_ip` | high | 封禁 IP（默认需审批） |
| `firewall.unban_ip` | medium | 解封 IP |
| `diagnostic` | low | 采集现场诊断信息 |
| `file.delete` | high | 删除指定文件（需审批） |
| `system.config.modify` | high | 修改系统配置（需审批） |
| `sudo.modify` | critical | 修改 sudoers（需审批） |
| `plugin.install` | high | 安装插件（需审批） |
| `code.patch` | high | 应用补丁（需审批） |
| `package.install` | high | 安装软件包（需审批） |
| `shell.exec` | high | 受限 shell（需审批，受 allowlist 约束） |
| `codegen` | — | 模板生成配置/脚本（沙箱内） |
| `deploy` | — | 远程初始化（需一次性授权令牌） |
| `plugin.action` | medium | 插件自定义动作 |

---

## 5. 插件开发入门

插件是放在 `plugins.dirs`（默认 `plugins/builtin`）下的 `.py` 文件，文件名以数字开头以保证加载顺序。最小骨架：

```python
PLUGIN = {
    "name": "my_detector",
    "version": "1.0.0",
    "description": "示例检测插件",
}

def setup(ctx):
    # 注册自定义动作（可选）
    pass

def detect(ctx, sample):
    # sample 为最近一次指标样本；返回发现列表或 None
    return []
```

- `detect(ctx, sample)` 应返回发现对象（与内置检测器相同结构），或空列表。
- 插件在 `error_disable_threshold` 次错误后会被熔断，避免坏插件拖垮主循环。
- 插件热加载：修改后由 `plugins reload` 或定时扫描自动生效。
- 更多见仓库内 `plugins/builtin/*.py` 与 `plugins/examples/`。

---

## 6. 常见操作示例

```bash
# 查看当前磁盘与端口状态
autonomic-ops metrics

# 手动提交一次诊断任务
autonomic-ops submit --kind diagnostic --params '{"reason":"manual"}'

# 审批一条待处理的封禁提案
autonomic-ops pending
autonomic-ops approve <id>

# 误删文件后回滚
autonomic-ops snapshots
autonomic-ops rollback --snapshot <id>

# 校验配置是否合法
autonomic-ops config validate
autonomic-ops config reload
```
