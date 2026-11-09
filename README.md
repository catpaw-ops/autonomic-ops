# AutonomicOps

> 自托管、可离线、可回滚的单机运维代理。

AutonomicOps 是一个运行在单台 Linux 主机上的常驻运维代理。它周期性采集系统指标，用内置检测器与可插拔插件发现异常，按声明式规则与策略做出**有界处置**（重启服务、清理过期文件、封禁可疑 IP、发送告警等），并在每次改动前做快照、改动后可一键回滚，全程写入哈希链审计日志。

设计目标：

- **自托管**：全部组件跑在你自己的机器上，不依赖任何外部云服务。
- **可离线**：核心运行**零对外联网、零 API Key、零模型依赖**。可选的 Webhook 告警是你主动开启的单向出站通知。
- **可回滚**：任何会改动文件的动作都先快照、后执行；出错或误判可一键恢复。
- **有界执行**：动作受白名单、风险分级、审批、禁止路径与沙箱约束，核心代码禁止自改。

---

## 它解决什么问题

传统的"监控 + 告警"在半夜把你叫醒，但修复仍要人来做。AutonomicOps 把常见的、已声明过的处置动作自动化：服务挂了自动拉起、磁盘快满自动清理过期文件、发现 SSH 暴破自动封禁来源 IP，并在一个只读面板上让你随时查看状态。

它**不是**一个通用 AI 代理，也不会替你做未经声明的高风险操作。所有自动动作都必须落在策略白名单内，且风险不超过配置上限；超出范围的动作只会生成一条待审批提案，等待人工确认。

---

## 核心能力

| 类别 | 内容 |
| --- | --- |
| 指标采集 | CPU、负载、内存、磁盘（按挂载点）、端口存活、进程、systemd 单元、连接数、SSH、流量 |
| 内置检测器 | 高负载、内存压力、磁盘高占用、端口关闭、单元失活/失败、SSH 暴破、连接洪泛、流量突增 |
| 插件检测器 | 日志错误突增、证书过期、备份新鲜度、失败单元、站点健康、inode 压力、OOM 观察、时间漂移、fd 压力、磁盘增长预测 |
| 规则引擎 | YAML 声明式规则：`kind + 阈值 → 动作`，含优先级调度、防抖、去重、限流、重试 |
| 处置动作 | 重启进程/服务、清理磁盘/缓存、轮转日志、Webhook 告警、封禁/解封 IP、文件删除、配置修改、补丁、包安装、受限 shell、诊断、模板生成、远程部署 |
| 安全模型 | 白名单、风险分级、人工审批、禁止路径、shell 命令白名单、核心代码禁自改、`ProtectSystem`/`PrivateTmp`/沙箱 |
| 回滚与审计 | 内容寻址快照、字节级回滚、哈希链审计日志、核心完整性清单 |
| 可观测性 | 只读 Web 面板（GET-only，默认绑 `127.0.0.1`）、Prometheus `/metrics` 端点、结构化日志 |
| 插件系统 | 热加载、能力门、错误熔断；按命名约定放置 `.py` 即可生效 |

---

## 快速开始

### 环境要求

- Linux（systemd 235+；推荐 systemd 245+ 以使用 nftables 后端）
- Python 3.9+

### 安装

```bash
bash scripts/install.sh --prefix /opt/autonomic-ops --non-interactive
```

安装器会把库文件、CLI、配置模板、规则、插件、单元文件放到 `--prefix` 下，并把 `autonomic-ops.service` 注册为开机自启。安装完成后编辑 `/opt/autonomic-ops/config/config.yaml` 适配你的主机（见下文"配置"），然后：

```bash
sudo systemctl restart autonomic-ops
```

> 想先看效果再决定是否常驻？安装器支持 `--no-service` 与 `--simulate`（假根校验），也可直接用 `autonomic-ops serve` 启动只读面板预览。

### 验证

```bash
/opt/autonomic-ops/bin/autonomic-ops status          # 守护进程状态
/opt/autonomic-ops/bin/autonomic-ops doctor          # 环境与配置诊断
/opt/autonomic-ops/bin/autonomic-ops metrics         # 最近一次指标样本
python3 -m unittest discover tests -v                # 单元/端到端自测
bash tests/selftest.sh                               # 50 项端到端断言
```

### 只读面板

```bash
/opt/autonomic-ops/bin/autonomic-ops serve --port 8081 --bind 127.0.0.1
```

浏览器打开 `http://127.0.0.1:8081/` 查看状态、指标、封禁、任务、待审批与审计尾；`/metrics` 暴露 Prometheus 格式指标。面板只读取数据，不提供任何写操作。

---

## 配置

主配置文件：`config/config.example.yaml`（安装后复制为 `config.yaml` 并按需修改）。关键段落：

- `agent`：进程名、数据/日志/运行目录、日志轮转。
- `scheduler`：Worker 池、队列、任务超时、老化与抢占。
- `policy`：白名单、审批清单、禁止路径、shell 白名单、`max_auto_risk`、`critical_always_approval`、`cleanup_paths`。
- `metrics`：采集间隔、监控的磁盘挂载点、端口/进程/单元监视列表、各阈值。
- `security`：入侵检测开关、封禁后端（nft / iptables / recorder）、降级行为。
- `backup` / `audit`：快照与审计开关、保留策略。
- `plugins`：插件目录、热加载、错误熔断阈值。
- `chat` / `codegen`：命令接口与模板生成（均为确定性、本地执行，无外部模型）。

**重要约束**：若 systemd 单元启用了 `PrivateTmp=yes`（默认开启），代理进程看到的 `/tmp` 与 `/var/tmp` 是独立的私有命名空间，看不到宿主机上的真实文件。因此 `policy.cleanup_paths` 应指向真实可见且可写的业务缓存/日志目录（如 `/var/log`、`/var/cache`），**不要**配置 `/tmp` 或 `/var/tmp`。

完整说明见 [`docs/USAGE.md`](docs/USAGE.md) 与 [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md)。

---

## 架构概览

```
指标采集 ─▶ 检测器（内置 + 插件）─▶ 发现（finding）
                                        │
                                        ▼
规则引擎（YAML：kind+阈值 → 动作）──▶ 策略门控（白名单/审批/禁止路径/风险上限）
                                        │
                                        ▼
执行器（有界动作）──▶ 快照 ─▶ 执行 ─▶ 哈希链审计
                                        │
                                        ▼
                              回滚点（一键恢复）
```

各组件职责、数据流与控制面/数据面分离详见 [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)。

---

## 安全模型

- **默认最小处置**：只有落在 `policy.whitelist` 且风险不超过 `policy.max_auto_risk` 的动作才会自动执行；其余生成待审批提案。
- **核心禁自改**：代理不能修改自己的核心代码与单元文件（`core_self_modify: false`，且核心哈希清单在启动时校验）。
- **硬禁止路径**：`/boot`、`/etc/sudoers`、`/etc/systemd/system` 等被列为禁止写入目标，任何尝试都会被拒绝。
- **shell 受控**：`shell.exec` 仅在 `shell_allowlist` 与 `shell_forbidden_patterns` 双重约束下执行，且默认在沙箱（rlimit / 可选 netns）中运行。
- **系统级加固**：systemd 单元使用 `ProtectSystem=full`、`PrivateTmp=true`、`ReadWritePaths` 限定，沙箱限制每任务的 CPU/内存/文件描述符。

---

## 文档

| 文档 | 内容 |
| --- | --- |
| [docs/USAGE.md](docs/USAGE.md) | 命令参考、配置字段、规则编写、动作清单 |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | 组件、数据流、控制面/数据面、调度 |
| [docs/DASHBOARD.md](docs/DASHBOARD.md) | 只读面板与 `/metrics` 端点 |
| [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) | 安装、systemd、远程部署、升级 |
| [docs/SELFTEST_REPORT.md](docs/SELFTEST_REPORT.md) | 端到端自测环境与断言清单 |
| [DISCLAIMER.md](DISCLAIMER.md) | 责任边界与免责声明 |
| [CONTRIBUTING.md](CONTRIBUTING.md) | 如何参与 |
| [CHANGELOG.md](CHANGELOG.md) | 变更记录 |

---

## 许可证

参见 [`LICENSE`](LICENSE)（MIT）。

## 免责声明

AutonomicOps 是运维辅助工具，**不能替代人工判断与变更评审**。自动处置可能误判并造成服务中断或数据丢失；启用前请在测试环境充分验证，并为关键动作保留人工审批。详见 [`DISCLAIMER.md`](DISCLAIMER.md)。
