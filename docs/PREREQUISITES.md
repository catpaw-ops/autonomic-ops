# 前置知识与命令速查

> 这个项目**不是 Linux 入门教程**。它是给**已经能管理一台 Linux 服务器**的人用的工具。
> 本文告诉你三件事：用之前需要会什么、软件会碰哪些系统命令、遇到不会的去看哪里。

## 1. 你需要会的最小集合

| 领域 | 你需要会 | 为什么 |
|---|---|---|
| 服务管理 | `systemctl status/start/restart/enable`、`journalctl -u` | 软件会重启服务、检测 `failed` 单元 |
| 防火墙 | `nft list ruleset`、`iptables -S` | 真实封禁需要你看得懂规则 |
| 日志 | `journalctl`、`tail -f`、`/var/log` | 排障靠日志 |
| 磁盘 | `df -h`、`du -sh`、`find -mtime` | 磁盘清理是核心动作之一 |
| 权限 | `chmod/chown`、`sudo`、`/etc/sudoers` | 以 root 运行 = root 级破坏力 |
| 进程 | `ps`、`kill`、`/proc` | 进程检测与重启 |
| 网络 | `ss -ltnp`、`ip route` | 端口 / 连接检测 |
| SSH | `ssh`、`authorized_keys`、`sshd_config` | 远程部署与安全审计 |

## 2. 软件会执行哪些系统命令（风险边界）

> 完整清单见 `src/autonomic/executor.py` 与 `src/autonomic/security.py`。常见的有：

- `systemctl restart/stop/start <unit>`
- `nft add/delete rule inet filter input ...` 或 `iptables -I/-D INPUT ...`
- `find <policy.cleanup_paths 内> -mtime +N -delete`
- `openssl x509 ...`（证书检测）
- 只读采集：`ps`、`ss`、`df`、`/proc/*`、`/var/log/*`
- 远程：`ssh` 到目标机执行安装脚本（`deploy`）

**这些命令都以运行用户的权限执行**；以 root 运行，就拥有 root 级的破坏力。这是为什么默认 `policy.dry_run: true`、`auto_remediate: true` 但白名单很小。

## 3. 不会怎么办（外部资源）

- systemd：`man systemd.service`、`man systemctl`、`man journalctl`
- nftables：<https://wiki.nftables.org/>
- Linux 性能与排障：Brendan Gregg 的 Linux 性能工具图
- 文件与查找：`man find`、`man df`、`man du`

## 4. 通用排障顺序

1. `autonomic-ops doctor` —— 环境 / 配置 / 权限自检
2. `autonomic-ops status` 或只读面板 —— 现在是什么状态
3. `autonomic-ops logs runtime -n 100` —— 发生了什么
4. `autonomic-ops logs decision -n 50` —— 为什么执行 / 为什么没执行
5. `autonomic-ops audit tail -n 30` —— 到底改了哪些文件

## 5. 一句话

**软件负责「按规则自动做」，你负责「看懂它在做什么，并能回滚」。**
如果你看不懂它准备执行的动作，就不要批准它。
