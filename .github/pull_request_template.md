## 这次改了什么

<!-- 一两句话说明动机与结果 -->

## 关联 issue

Closes #

## 检查清单

- [ ] 已跑过 `make check`、`make test` 与 `make test-no-yaml`（前三者任意 OS 均可）；涉及运行时行为的改动另在 Linux 上验证
- [ ] 变更涉及守护进程行为时，跑过 `bash tests/selftest.sh` 并附上结果
- [ ] 没有把任何本机绝对路径、令牌、API Key 或日志写进仓库
- [ ] 配置模板 `config/config.example.yaml` 与 `docs/USAGE.md` 已同步更新
- [ ] 架构 / 安全模型有变化时，`docs/ARCHITECTURE.md` 与 `DISCLAIMER.md` 已同步更新
- [ ] 新增/修改了 `src/autonomic/*.py`，已考虑 `scripts/build_manifest.py` 生成的核心哈希清单
- [ ] `CHANGELOG.md` 的 Unreleased 段落已更新

## 安全红线（触及任一项请在 PR 描述里特别说明）

- [ ] 放宽了 `policy.whitelist` / `approval_required` / `forbidden_paths`
- [ ] 修改了 `PolicyEngine.decide()` 的判定顺序
- [ ] 修改了 `check_shell` / 重启配方校验 / 沙箱隔离
- [ ] 修改了 IPC 鉴权或远程部署授权
- [ ] 修改了快照 / 回滚 / 审计链逻辑

## 测试结果

```text
粘贴测试输出摘要（脱敏后）
```
