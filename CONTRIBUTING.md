# 参与贡献 / Contributing

AutonomicOps 的定位是**单机、自托管、默认保守的运维代理**，而非功能堆砌的平台。参与改动时请守住四条设计约束：**默认保守、行为可解释、降级不撒谎、变更可回滚**。

## 0. 项目定位与范围

- 目标：**单机** Linux 运维 Agent（不做集群选主、不做容器编排、不做 Web UI）。
- 语言：Python 3.9+，**运行时零第三方依赖**。PyYAML 是可选加速，缺失时 `yamlmini.py` 必须仍能解析所有随仓库发布的配置。
- 平台：依赖 `/proc`、`/sys`、Unix socket、`systemctl`、`nft`/`iptables`，**只能在 Linux 运行**。Windows / macOS 可以跑静态检查与完整单元测试（沙箱在这些平台上显式标记 `degraded_isolation`），但端到端自测与功能验证必须在 Linux 完成。
- 许可：MIT。贡献即表示你同意以 MIT 发布你的改动。

## 1. 准备环境

需要一台 Linux 机器（虚拟机或一次性 VPS 都可以，不要直接上生产机）：

```bash
git clone <your-fork-url>
cd autonomic-ops
python3 -V                    # 需要 3.9+
make check                    # 语法 / shell / 包导入，任意 OS 都能跑
make test                     # 单元测试
make test-no-yaml             # 强制不走 PyYAML，验证零依赖路径
bash tests/selftest.sh        # 端到端自测，LINUX ONLY，会拉起真实 daemon
```

端到端自测需要 `jq`、`curl`、`tar`、可写的 `/tmp`，且会造故障、删文件再回滚、写入 `/tmp/autonomic-selftest`。**不要在有重要数据的机器上跑**；输出的 50 项断言结果请贴进 PR。

只改文档时，至少跑 `make check`。

## 2. 目录地图

| 路径 | 作用 |
|---|---|
| `src/autonomic/` | 核心包（32 个模块），**禁止运行时自修改** |
| `config/config.example.yaml` | 生产配置模板，带完整中文注释 |
| `config/config.selftest.yaml` | 自测配置，所有路径都在 `/tmp` |
| `config/rules/default_rules.yaml` | 默认规则库 |
| `plugins/builtin/`、`plugins/examples/` | 内置插件与示例插件 |
| `scripts/` | 安装 / 卸载 / 看门狗 / 构建完整性清单 |
| `systemd/` | 服务单元与 tmpfiles |
| `tests/` | 单元测试 + 端到端自测脚本 |
| `docs/` | 架构、用法、部署、插件开发、发布、真实自测报告与环境差异 |

新增能力优先做成**插件或规则**，而不是往核心里加分支。插件契约见 [`docs/PLUGIN_DEV.md`](docs/PLUGIN_DEV.md)。

## 3. 代码约定

1. **显式降级，绝不谎报成功**。没有权限 / 后端缺失时，必须在返回值、日志和 `doctor` 里标注 `simulated` / `degraded_isolation` / notes。禁止用 `ok: True` 冒充成功。
2. **所有变更动作过策略引擎**。`ActionCoordinator` 会二次调用 `PolicyEngine`；新增 handler 不要绕过它。
3. **高危动作先快照**。写 / 删 / 改之前调 `BackupManager.snapshot()`，把 `rollback_point` 写进 `ActionResult` 与审计记录。
4. **全量审计**。谁触发（auto/user/cli/system）、动作、目标、参数、结果、回滚点都要进哈希链。
5. **核心完整性**。改了 `src/autonomic/*.py` 就要考虑 `scripts/build_manifest.py` 生成的清单；`code.patch` 命中核心路径必须被拒绝。
6. **标准库优先**。新增第三方依赖需要非常充分的理由，并同时保证无该依赖时仍能启动。
7. 类型注解、清晰的错误码（`errors.py`）、`except` 不要静默吞掉异常，至少写 `error.log`。
8. Shell 脚本保持 LF 行尾（`.gitattributes` 已强制），并用 `bash -n` 校验。

## 4. 提交 PR

- 分支名随意，PR 描述请填写 `.github/pull_request_template.md` 的清单。
- 一个 PR 只做一件事；重构与行为改动分开。
- 涉及配置字段时，**同时**更新 `config/config.example.yaml`、`docs/USAGE.md`、`docs/ARCHITECTURE.md`。
- 涉及安全边界时，同时更新 `DISCLAIMER.md` 与 `SECURITY.md`。
- 在 `CHANGELOG.md` 记一笔（新版本发布前先记入 `Unreleased` 段落）。
- CI 会在 Python 3.9 / 3.12 上跑语法、shell、配置校验与两条单元测试路径；端到端自测请自己跑并贴结果。

## 5. 哪些改动会被谨慎对待

- 放宽 `policy.whitelist`、`approval_required`、`forbidden_paths`；
- 修改 `PolicyEngine.decide()` 的短路判定顺序；
- 让生成内容跳过校验链或审批；
- 弱化 IPC 鉴权、远程部署授权、沙箱隔离；
- 引入 `shell=True` 拼接外部输入、或新的静默 `except: pass`。

这些不一定会被拒绝，但需要在 PR 里写清威胁模型、默认开关、回滚与审计方案。

## 6. 报告问题

用 `.github/ISSUE_TEMPLATE/bug_report.md`，记得脱敏。安全漏洞请走 `SECURITY.md` 的私有渠道。
