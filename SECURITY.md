# 安全政策 / Security policy

## 为什么这个文件很重要

AutonomicOps 是一个**会以你授予的权限自动修改服务器**的程序：重启服务、删除文件、改配置、下发防火墙规则、通过 SSH 在远端安装软件。安全边界不只是"代码有没有漏洞"，还包括"默认配置是否保守、降级是否被如实告知、变更是否可回滚"。因此我们把它写进策略文件、写进 README、也写在这里。

请先阅读 [`DISCLAIMER.md`](DISCLAIMER.md) 和 README 的「安全模型」一节。

## 如何报告漏洞

**请不要在公开 issue 里贴出可复现的利用细节或 PoC。** 优先使用 GitHub 的私有漏洞报告：仓库页面 → `Security` → `Report a vulnerability`。如果尚未开启该功能，可以先开一个**不含细节**的 issue 询问私下联系方式。

一份有用的报告应包含：

- 受影响的版本 / commit；
- 触发条件（是否 root、是否开启自动处置、防火墙后端、沙箱是否降级）；
- 最小复现步骤与预期 / 实际行为；
- 影响面：能否绕过 `PolicyEngine`、能否越权执行、能否读到令牌、能否写到禁止路径；
- 脱敏后的日志片段（**不要**附 API Key、`ipc.token`、真实公网 IP、`audit.log` 全文）。

我们会在 48 小时内确认收到，7 天内给出初步判断；确认为漏洞后，修复与披露时间会与报告者协商。修复发布时会在 `CHANGELOG.md` 与 Release Notes 中致谢（除非你希望匿名）。

## 支持范围

| 版本 | 是否提供安全修复 |
|---|---|
| `1.0.x` | 是 |
| `< 1.0` | 否（尚未发布） |

当前稳定版为 `1.0.x`，维护节奏见 `CHANGELOG.md`。

## 已知边界（这些不是漏洞，请勿当成绕过上报）

- **防火墙 `recorder` 后端**：没有 `nft` / `iptables` 写权限时只记录封禁意图，返回 `simulated: true`，**不提供真实防护**。这是设计行为，响应字段与审计里都会标明。
- **沙箱不是容器**：`unshare -n` 不可用时降级为 `rlimit + timeout`，`ExecResult.degraded_isolation` 会写明网络未隔离。不要用本项目运行不可信代码。
- **非 POSIX 开发机没有隔离**：Windows 上 `Sandbox.run()` 只启动一个普通子进程（无 rlimit / 进程组 / netns），并**强制**标记 `degraded_isolation: true`。这条路径仅为单元测试与 `doctor` 的可移植性存在，不要在任何非 Linux 机器上依赖沙箱执行生成代码或插件。
- **审计哈希链**可发现篡改，但无法阻止拥有 root 的攻击者重写整条链；需要强证据请把 `audit.log` 实时转发到独立日志服务器。
- **入侵检测是启发式**：基于本机日志与 `/proc` 统计，会漏报、误报，不防 DDoS / 0day。
- **核心完整性清单**是防自改与防误改，不是防入侵的加密签名机制。

## 上线前自查（使用者侧）

- [ ] 已在一次性测试机跑过 `bash tests/selftest.sh`
- [ ] `bootstrap.authorization_token` 已设置为随机值，未写入任何会被提交的文件
- [ ] `policy.dry_run: true` 先演练，观察 `decision.log` 后再关闭
- [ ] `security.auto_ban` 默认关闭，开启前确认防火墙后端真实可用
- [ ] IPC token 文件权限为 `0600`，run 目录仅服务用户可读；不要把 `/run/autonomic-ops` 暴露给其他用户
- [ ] 备份目录有独立磁盘空间，且验证过一次 `rollback`
- [ ] 已配置人工兜底（本项目的 `notify` 只写日志，不会自动打电话/发短信），不要把本项目当作唯一安全措施

## Security contact

私有漏洞报告入口见仓库 `Security` 标签页。请勿把敏感信息发到公开讨论区。
