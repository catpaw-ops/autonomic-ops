# AutonomicOps 自测报告

> 本报告记录在一次性 **x86_64 Ubuntu 24.04 + systemd** 虚拟机上实际执行的端到端验证结果，不是手工填写。
> 复现入口：`bash tests/selftest.sh`。

## 0. 结论摘要

| 项目 | 结果 |
|---|---|
| 单元测试（PyYAML 路径） | **14/14 通过** |
| 单元测试（零依赖 `yamlmini` 路径） | **14/14 通过** |
| 端到端 `tests/selftest.sh` | **PASS=50 FAIL=0** |
| 真实安装到 `/opt/autonomic-ops` + systemd unit | 成功（32 模块、CLI 可执行） |
| systemd 重启后自动拉起 | 通过 |
| `kill -9` 后 `Restart=on-failure` | 通过（5s 内新 PID） |
| 真实 nftables 封禁 / 解封 | 通过（`simulated=false`、`verified=true`） |
| 外部看门狗与主服务共存 | 通过（两者同时 `active`） |
| `doctor` | 19 项：17 OK；2 项为环境所致（根盘 <1GiB、热补后核心哈希不符） |

## 1. 测试环境（实测）

| 项 | 实测值 |
|---|---|
| 架构 / 内核 | `x86_64` / `Linux 6.8.0-147-generic`（Ubuntu 标准内核） |
| 发行版 | Ubuntu 24.04.5 LTS |
| init | systemd 255，`systemctl is-system-running` = `running`，PID 1 = systemd |
| Python | 3.12.3（`/usr/bin/python3`）；PyYAML 6.0.1 |
| 防火墙 | nftables 1.0.9 + iptables 1.8.10 (nf_tables) |
| 权限 | root + 免密 sudo |
| 资源 | 2 vCPU / 1.9 GiB RAM / 2.4 GiB 根盘 |
| 虚拟化 | QEMU 11.1.0，TCG（软件模拟） |

## 2. 验证项

- **静态与单元测试**：`compileall src`、`bash -n scripts/*.sh tests/*.sh`、包可导入；单元测试在 PyYAML 与零依赖两条路径下各 14/14。
- **端到端**：`tests/selftest.sh` 拉起真实 daemon，覆盖任务下发/排队/抢占、磁盘清理与快照回滚、codegen 校验与禁止路径拒绝、插件热加载、审计哈希链、IPC 鉴权、远程部署模拟、安装器契约、干净停机，共 50 项断言全部通过。
- **真实安装**：`install.sh --prefix /opt/autonomic-ops` 复制 32 个模块、安装并启动 systemd unit、CLI 可执行。
- **systemd 行为**：`reboot` 后服务自动 `active`，`/run/autonomic-ops` 由 systemd 重建；`kill -9` 主进程后 `Restart=on-failure` 于 5s 内拉起。
- **真实封禁**：`firewall_backend=auto` 检测为 `nft`，`nft add rule inet filter input ... drop` 真实生效，`simulated=false`、`verified=true`；解封按 rule handle 删除。
- **看门狗**：`autonomic-ops-watchdog.service` 与主服务同时运行。

## 3. 发现并修复的问题（仅真实系统暴露）

| # | 现象 | 根因 | 修复 |
|---|---|---|---|
| 1 | 重启后服务死循环，`status=226/NAMESPACE` | unit 的 `ReadWritePaths=` 引用了安装器未创建的 `/var/log/autonomic-ops` 与重启即清空的 `/run/autonomic-ops` | unit 增加 `StateDirectory` / `LogsDirectory` / `RuntimeDirectory=autonomic-ops`，由 systemd 自动创建 |
| 2 | 真实封禁失败 `No such file or directory` | nft 后端假设 `inet filter` 表已存在，全新系统没有 | 加规则前幂等创建表与 `input` 基链 |
| 3 | `verified` 恒为 false | `_verify` 用了非法语法 `nft list inet filter` | 改为 `nft list table inet filter` |
| 4 | 解封失败 `expecting handle` | nft 不能按表达式删规则 | 先 `nft -a list` 查 handle，再按 handle 删除 |
| 5 | 看门狗无法启用 | `install.sh` 从不安装 `autonomic-ops-watchdog.service` | 安装该 unit（默认不启用，按需 `enable`） |

## 4. 结论

在标准 x86_64 Ubuntu 24.04 + systemd + 真实 nftables 上，单元测试、端到端自测、真实安装、重启自启、故障恢复、真实封禁/解封、看门狗共存全部通过。仍建议在带快照的一次性 VPS 上补 ≥24h 长稳观测（RSS / fd / 日志滚动 / 审计链），再用于有数据的生产机。

## 5. 复现方式

```bash
git clone <repo>
cd autonomic-ops
make check && make test && make test-no-yaml
sudo bash tests/selftest.sh
```
