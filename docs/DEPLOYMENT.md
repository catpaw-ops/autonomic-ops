# 部署手册 / Deployment

> 这一页假设你在一台可以随便重装的 Linux 机器上完成首次演练。第一次部署请以「演练 + 观察」为主，不要直接开启全自动处置。

## 1. 环境要求

| 项 | 要求 |
|---|---|
| 操作系统 | Linux（依赖 `/proc`、`/sys`、Unix domain socket）；容器里可以跑自测，但部分能力会降级 |
| Python | 3.9+，推荐 3.12 |
| 第三方依赖 | **无**。PyYAML 可选，缺失时由 `yamlmini.py` 解析配置子集 |
| 自检工具 | `jq`、`curl`、`tar`（仅 `tests/selftest.sh` 需要） |
| systemd | 可选；缺失时退化为 pidfile supervisor |
| 防火墙 | `nft` 或 `iptables` 可选；都不可用会降级为 `recorder`（只记意图） |
| 权限 | 生产建议 root（或具备精确 sudo 授权）；自测不需要 root |

**Windows / macOS 不能运行守护进程**，只能做静态检查与单元测试（沙箱在这些平台上会显式标记为 `degraded_isolation`，不具备隔离能力）。所有功能验证请在 Linux 上完成。

## 2. 三种运行形态

| 形态 | 适用 | 启动方式 |
|---|---|---|
| systemd 服务 | 生产 | `sudo bash scripts/install.sh` → `systemctl enable --now autonomic-ops` |
| pidfile supervisor | 无 systemd 的 VPS / 容器 | 安装脚本自动降级，或 `autonomic-ops service start` |
| 前台开发 | 调试 / 自测 | `export PYTHONPATH=src; python3 -m autonomic.main -c config/config.selftest.yaml --foreground` |

主进程默认双 fork，stdout/stderr 重定向到日志文件，日志按 11 个通道分流，**不会占用或刷屏终端**。

## 3. 生产安装

```bash
git clone <your-repo-url> && cd autonomic-ops
sudo bash scripts/install.sh \
  --prefix /opt/autonomic-ops \
  --bootstrap-token "$(openssl rand -hex 24)"
sudo systemctl enable --now autonomic-ops
sudo /opt/autonomic-ops/bin/autonomic-ops status
sudo /opt/autonomic-ops/bin/autonomic-ops doctor
```

| 参数 | 说明 |
|---|---|
| `--prefix DIR` | 安装根，默认 `/opt/autonomic-ops`。自定义时会同步改写配置里的 `plugins.dirs` 与 `bootstrap.install_root`；不能含空白、`#`、`&` |
| `--config FILE` | 指定要安装为 `config/config.yaml` 的配置模板 |
| `--bootstrap-token T` | 一次性远程部署授权令牌，写入权限 `0600` 的配置文件 |
| `--non-interactive` | 不提示（远程 bootstrap 需要） |
| `--no-service` | 不安装 / 启动 systemd 单元 |
| `--simulate` | 假根安装，不改系统；隐含 `--no-service` |
| `--force` | 覆盖已存在的 `config.yaml` |

安装器产出：`<prefix>/lib/autonomic/*.py`、`bin/autonomic-ops`、`bin/autonomic-ops-daemon`、`config/rules/default_rules.yaml`、`scripts/`、`systemd/`，并调用 `build_manifest.py` 生成核心哈希清单。

`sandbox` 之外还有 systemd 整机上限：`LimitNOFILE=65536`、`LimitNPROC=512`、`MemoryMax=2G`、`TasksMax=256`。注意 `MemoryMax` 应大于 `watchdog.max_rss_mb`（默认 1024MB），否则看门狗会不断触发重启。

## 4. 目录与权限

| 路径 | 用途 | 建议权限 |
|---|---|---|
| `<prefix>/lib/autonomic` | 核心源码（禁止自修改） | root 所有，只读 |
| `<prefix>/config/config.yaml` | 生效配置（可能含令牌） | `0600` |
| `/run/autonomic-ops` | pidfile、`agent.sock`、`ipc.token` | `0700`，socket `0600` |
| `/var/log/autonomic-ops` | 11 通道日志 + `audit.log` | `0750` |
| `/var/lib/autonomic-ops` | 任务流水、快照、封禁状态、待审批提案 | `0750` |

IPC 采用 Unix socket + 随机 token + `SO_PEERCRED`，未授权请求统一返回 `ipc.unauthorized`，不泄露命令是否存在。

## 5. 上线前检查清单

按顺序做完再考虑放开自动处置：

- [ ] 已读 `README.md`、`DISCLAIMER.md`、`SECURITY.md`
- [ ] 在一台**可随时重装**的 Linux 机器跑过 `bash tests/selftest.sh`，50 项断言全 PASS
- [ ] `autonomic-ops doctor` 无 `error`，并看懂了每一条 `warning`（降级项）
- [ ] 确认防火墙后端：`status` 里是 `nft` / `iptables` 而不是 `recorder`；若是 `recorder`，不要以为封禁生效
- [ ] `bootstrap.authorization_token` 已设为随机值，且没有写进任何会被提交的文件
- [ ] `policy.dry_run: true` 已开启，跑满至少一个巡检周期并读完 `decision.log`
- [ ] `policy.whitelist` 已按这台机器上真实存在的服务收紧，删掉用不到的动作
- [ ] `policy.cleanup_paths` 与 `cleanup_min_age_hours` 已确认，避免清理到业务数据
- [ ] `security.auto_ban` 保持默认 `false`；如要开启，先确认 `protect_private_ips: true` 与 `ban_requires_approval`
- [ ] 备份目录有独立空间，并**实际演练过一次** `snapshots` → `rollback`
- [ ] `audit verify` 通过，且重要环境把 `audit.log` 实时转发到独立日志服务器
- [ ] 远程管控不暴露到公网；若必须远程，置于受控网络 / 反代 + TLS 之后
- [ ] 有人能收到告警并人工介入，本项目不是唯一安全措施

## 6. 首次放开的推荐顺序

1. `dry_run: true` + `auto_remediate: true`：只产生决策日志，不执行任何动作。
2. 观察 24 小时 `decision.log`，修正误报规则与阈值。
3. `dry_run: false`，但只保留低风险白名单（`notify`、`diagnostic`、`log.rotate`）。
4. 逐步加入 `service.restart` / `process.restart`，每次只加一项，并确认重启风暴保护（`remediation.max_restarts_per_hour`）生效。
5. 最后才评估 `security.auto_ban`。**永远不要**把 `file.delete`、`system.config.modify`、`shell.exec` 放进自动白名单。

每一步都可以在不重启主进程的情况下用 `autonomic-ops config reload` 生效；出问题就回到上一步并查 `audit.log`。

## 7. 远程部署

`deploy` 有七步：授权校验 → 打包 → 上传 → 安装 → 校验 → 启动 → 报告。`--simulate` 在 `bootstrap.simulate_root` 下建假根、执行真实安装脚本的 `--simulate` 并验证安装契约，不触网、不改系统，自测即用此模式。

- 必须对目标机器有明确授权；`bootstrap.authorization_token` 为空时远程部署会被拒绝。
- `strict_host_key: true` 是默认值，不要为了图方便关掉。
- `allow_private: false` 是默认值；要部署到内网机器时再显式放开。

## 8. 卸载

```bash
sudo systemctl disable --now autonomic-ops
sudo bash scripts/uninstall.sh --prefix /opt/autonomic-ops
# --purge 会额外删除 data / logs / backups，执行前务必确认
```

## 9. 排障速查

| 现象 | 先查 |
|---|---|
| CLI 连不上 daemon | `status` → socket 与 pidfile 是否存在；`logs error -f`；`doctor` |
| 封禁"成功"但 IP 仍可访问 | 看响应是否带 `simulated: true`；`status` 里的 firewall backend 是否为 `recorder` |
| 动作没执行 | `decision.log`（策略判定）、`pending`（待审批）、`audit query`（结果） |
| 服务反复重启 | `watchdog` 的 `max_rss_mb` 与 systemd `MemoryMax` 是否冲突；`heartbeat.json` 是否更新 |
| 插件没加载 | `logs plugin -f`；源码是否命中禁用表；文件签名是否变化 |
| 自测失败 | 确认 `jq` / `curl` / `tar` 已安装，且 `/tmp/autonomic-selftest` 可写；不要在 Windows 上跑端到端自测 |

## 10. 自测为什么不放进 CI

`tests/selftest.sh` 会真实拉起 daemon、绑定 Unix socket、读 `/proc`、调用 `systemctl`、写 `/tmp`、造故障并做回滚，还依赖防火墙工具链。CI 容器里这些能力要么缺失要么被隔离，跑出来的"通过"没有参考价值。CI 只负责静态检查、配置校验、单元测试（有 / 无 PyYAML 两条路径）与可安装性；端到端验证请在一台一次性 Linux VM / VPS 上手动完成。
