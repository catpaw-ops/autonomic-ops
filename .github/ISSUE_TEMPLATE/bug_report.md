---
name: 问题报告 / Bug report
about: 报告一个可以复现的问题
title: "[Bug] "
labels: bug
assignees: ''
---

> **提交前请先脱敏**：不要粘贴 API Key、远程令牌、`ipc.token`、`audit.log` 原文或真实公网 IP。日志请截取相关行并替换敏感值。

## 环境

- 操作系统 / 发行版：
- 内核：`uname -a` 输出：
- Python 版本：`python3 -V`：
- 安装方式：`install.sh` / `pip install -e .` / 手工运行源码：
- 版本号：`autonomic-ops --version`：
- 是否以 root 运行：是 / 否
- 是否开启 `policy.auto_remediate` 与 `security.auto_ban`：是 / 否

## 问题描述

简明说明发生了什么、你期望发生什么。

## 复现步骤

1.
2.
3.

## 诊断输出

请附上 `autonomic-ops doctor` 的输出（可脱敏），以及相关的 `decision.log` / `error.log` 片段：

```text

```

## 是否已确认降级

本项目在缺少权限时会显式降级（防火墙 `recorder` 后端、沙箱 `degraded_isolation`、无 systemd 时用 pidfile supervisor）。响应字段里是否出现 `simulated: true` 或 `degraded_isolation: true`？

- [ ] 已检查，无降级
- [ ] 出现降级（请在上面贴出具体字段）
- [ ] 不确定

## 其他

如果问题涉及自动处置造成了实际变更，请说明是否使用了快照回滚（`autonomic-ops snapshots` / `rollback`）。
