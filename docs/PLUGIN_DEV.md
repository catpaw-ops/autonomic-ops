# 插件开发指南

插件是 AutonomicOps 唯一的官方扩展方式。核心调度代码禁止自修改，所有新能力通过插件进入：新的检测器、新的处置动作、新的规则、事件订阅。

- 插件是**单文件 Python**（`.py`），不需要包结构。
- 放入 `plugins.dirs` 中任一目录。生产模板 `config/config.example.yaml` 默认只配置了 `<prefix>/plugins/builtin`；需要更多目录（例如 `data/plugins`、`plugins/user`）请自行追加到 `plugins.dirs`。
- 主程序的扫描线程每 `plugins.scan_interval` 秒检查一次，文件签名变化即热加载，**不重启**。

---

## 0. 仓库内插件目录

| 文件 | 插件名 | 作用 | 权限 |
|---|---|---|---|
| `plugins/builtin/10_log_error_spike.py` | `log_error_spike` | 统计配置指定日志尾部窗口内的 ERROR / CRITICAL 行数，突增时产生 finding | `exec: false`, `network: false` |
| `plugins/builtin/20_cert_expiry.py` | `cert_expiry` | 检查配置的 TLS 证书是否临近过期 | `exec: true`, `network: false` |
| `plugins/builtin/30_backup_freshness.py` | `backup_freshness` | 最新本地快照超过时间预算时告警 | `exec: false`, `network: false` |
| `plugins/examples/hello_watch.py` | `hello_watch` | 最小参考实现；端到端自测用它验证「不重启主程序即可热加载插件并触发规则」 | `exec: false`, `network: false` |

文件名的数字前缀只控制加载顺序，不是版本号。每个插件用 `PLUGIN` 字典声明 `name` / `version` / `description` / `author` / `permissions`（见第 2 节）。

- 生产：`scripts/install.sh` 会把 `plugins/builtin/` 整体复制到 `<prefix>/plugins/builtin`。
- 自测：`tests/selftest.sh` 把 `plugins/builtin/` 与 `config/rules/` 复制到 `/tmp/autonomic-selftest` 下，配置里不含任何开发者本机路径。
- **不要把密钥、令牌或含真实 IP 的日志放进这个目录**：安装器与远程部署会复制整个目录。

安全限制见第 6 节，热加载机制见第 7 节。

---

## 1. 最小可用插件

```python
PLUGIN = {
    "name": "my_watch",
    "version": "1.0.0",
    "description": "检测某个文件是否缺失",
    "author": "you",
    "permissions": {"exec": False, "network": False},
}

def setup(ctx):
    ctx.register_detector("marker", detect, interval=30)
    ctx.log("info", "my_watch ready")

def detect(ctx, sample):
    path = "/tmp/my.marker"
    import os
    if not os.path.exists(path):
        return [{
            "kind": "my.marker_missing",
            "target": path,
            "value": "absent",
            "severity": "low",
            "message": f"{path} is missing",
            "evidence": {"checked": True},
        }]
    return []
```

放进插件目录后：

```bash
autonomic-ops plugins list
autonomic-ops logs plugin -n 20
```

---

## 2. 元数据契约

`PLUGIN` 必须是模块级 dict：

| 字段 | 必填 | 说明 |
|---|---|---|
| `name` | 是 | 唯一标识，`[a-zA-Z_][a-zA-Z0-9_-]*`；重名会被拒绝 |
| `version` | 是 | 字符串，便于审计 |
| `description` | 否 | 人类可读说明 |
| `author` | 否 | 作者/来源 |
| `permissions` | 否 | `{"exec": bool, "network": bool}`，默认全 False |

加载流程：

1. 读源码，检查大小 ≤ `plugins.max_plugin_bytes`（默认 512 KiB）。
2. 正则扫描禁用构造（见 §6），命中直接拒绝，不执行任何代码。
3. `import` 模块，检查 `PLUGIN`。
4. 构造 `PluginContext`，调用 `setup(ctx)`。
5. 注册到 `_plugins`，写 `plugin.load` 审计与 `plugin.log`。
6. 运行期异常累计到 `error_disable_threshold`（默认 5）次 → 自动卸载并记 `plugin.log`。

`teardown(ctx)` 可选；卸载/热重载前调用。`ctx` 注册的 detector / action / rule / subscription 会自动清理，不需要手工反注册。

---

## 3. 生命周期钩子

### 3.1 `setup(ctx)`

插件入口，只调用一次（每次加载）。在这里注册能力。**不要**在这里做长耗时阻塞操作；需要周期任务请用 `register_detector(..., interval=N)`。

### 3.2 检测器 `detect(ctx, sample)`

- `sample`：最近一次指标样本 dict（`cpu/load/memory/disks/ports/processes/units/connections/ssh`）。
- 返回：`None`、单个 dict、或 dict 列表；每个 dict 字段：
  - `kind`（必填，字符串，如 `my.disk_hot`）
  - `target`（必填，字符串，规则按它匹配/去重）
  - `value`（任意 JSON 值）
  - `severity`：`info|low|medium|high|critical`，默认 `medium`
  - `message`：人类可读
  - `evidence`：dict，写进审计与日志
- 检测器抛异常会被捕获，计入该插件错误数，不影响其他插件。
- `interval` 秒：两次执行的最小间隔；`0` 表示每个采样周期都跑。

### 3.3 动作 `action(ctx, finding, params)`

- `finding`：触发它的 finding dict（可能为空，例如人工直接调用）。
- `params`：规则 `then.params` 渲染后的 dict。
- 返回：`(ok: bool, detail: str)` 或 `bool`。
- 动作名注册为 `<plugin_name>.<action_name>`；在规则里写全名。
- 动作仍受策略引擎约束：不在 `policy.whitelist` 的动作不会自动执行；要自动执行需在配置里显式加入白名单。

### 3.4 事件订阅 `ctx.subscribe(pattern, handler)`

`pattern` 是 topic 前缀，例如 `"task.state"`、`"finding"`。`handler(payload)` 在总线订阅线程里执行，**必须快速返回**；阻塞会拖慢该订阅（不影响其他订阅，但有界队列会丢事件）。

---

## 4. PluginContext API

| 方法 | 签名 | 说明 |
|---|---|---|
| `ctx.register_detector` | `(name, fn, interval=0) -> str` | 注册检测器，返回内部 key |
| `ctx.register_action` | `(name, fn) -> str` | 注册动作，自动加 `<plugin>.` 前缀 |
| `ctx.register_rule` | `(rule: dict) -> str \| None` | 注册运行时规则（不落盘，重启后由 `setup` 重建） |
| `ctx.subscribe` | `(pattern, handler)` | 订阅总线事件 |
| `ctx.emit_finding` | `(kind, target, value=None, severity="medium", message="", evidence=None)` | 主动发 finding（适合事件驱动检测） |
| `ctx.run_command` | `(argv: list, timeout=10, allow_network=False) -> dict` | 需要 `permissions.exec`；走沙箱，返回 `ExecResult.to_dict()` |
| `ctx.read_text` | `(path, max_bytes=262144) -> str` | 只允许 `/proc/ /sys/ /var/log/ /etc/ /tmp/` 前缀，按 realpath 判断 |
| `ctx.log` | `(level, message)` | 写 `plugin.log`，自动脱敏与截断 |
| `ctx.config` | `Config` | 只读配置访问：`ctx.config.get("plugins.settings.my_watch.xxx")` |
| `ctx.bus` / `ctx.audit` / `ctx.sandbox` | 对象 | 高级用法；普通插件不建议直接操作 |
| `ctx.name` / `ctx.permissions` | 属性 | 当前插件标识与权限 |

插件专属配置建议放在：

```yaml
plugins:
  settings:
    my_watch:
      marker: /var/run/my.marker
      threshold: 10
```

读取：`ctx.config.get("plugins.settings.my_watch.threshold", 10)`。

---

## 5. 运行时规则

`ctx.register_rule()` 接受与 YAML 规则相同的 dict：

```python
ctx.register_rule({
    "id": "my.marker-missing-notify",
    "name": "my_watch: marker missing",
    "when": {"kind": "my.marker_missing", "min_severity": "low"},
    "then": {
        "action": "notify",
        "risk": "low",
        "params": {"message": "my_watch: {{target}} missing"},
    },
    "cooldown": 300,
    "max_attempts": 1,
})
```

- `when.kind` 必填；`min_severity` 可选；`target_regex` 可选。
- `then.action` 可以是内置动作（`notify/diagnostic/process.restart/...`）或插件动作（`my_watch.touch`）。
- `params` 支持 `{{target}} {{value}} {{severity}} {{host}} {{finding_id}} {{evidence.xxx}}`。
- `cooldown` 秒 + `max_attempts` 次：窗口内超过次数即抑制，写 `decision.log`。
- 规则 id 冲突时自动加 `.1`、`.2` 后缀。

---

## 6. 安全限制

源码中出现以下构造会被**静态拒绝**（不导入、不执行）：

| 构造 | 原因 |
|---|---|
| `os.system(` | 绕过插件沙箱 |
| `eval(` | 动态代码执行 |
| `exec(` | 动态代码执行 |
| `__import__(` | 动态导入 |
| `ctypes.` | 原生内存访问 |
| `socket.socket(` | 直连网络；联网能力应走受控通道 |
| `subprocess.*` | 直接起进程；请用 `ctx.run_command`（受 rlimit/timeout 约束） |

其他约束：

- 单文件 ≤ `plugins.max_plugin_bytes`。
- `ctx.read_text` 只能读白名单前缀；不要试图 `open()` 任意路径。
- 插件动作仍受 `policy.whitelist` / `approval_required` / `forbidden_paths` 约束，不能借插件绕过。
- 插件不得修改 `src/autonomic/**`（核心完整性守卫与 `code.patch` 策略都会拒绝）。
- 插件不做持久化写盘；需要状态请写 `agent.data_dir` 下的自有子目录，并在 `teardown` 里清理。

> 说明：插件在 daemon 进程内执行，不是独立进程。静态扫描 + 权限门 + 沙箱命令是"防手滑/防误用"，不是防定向恶意代码的强隔离。只加载你信任的插件。

---

## 7. 热加载与调试

```bash
# 编辑插件后保存，5s 内自动重载
autonomic-ops logs plugin -f

# 强制重载全部
autonomic-ops plugins reload

# 卸载
autonomic-ops plugins unload my_watch
```

签名基于 `mtime + size`；如果改了内容但大小与 mtime 都没变（极少见），用 `plugins reload` 强制。

拒绝原因示例（`plugin.log`）：

```text
plugin rejected path=.../bad.py reason=forbidden construct: os.system bypasses the plugin sandbox
plugin load failed path=.../bad.py: duplicate plugin name: my_watch
```

---

## 8. 测试插件

1. 用自测配置（所有路径在 `/tmp/autonomic-selftest`）：

```bash
cp my_plugin.py /tmp/autonomic-selftest/plugins/user/
PYTHONPATH=src python3 -m autonomic.cli -c config/config.selftest.yaml plugins list
```

2. 看 `plugin.log` 与 `data/notifications.jsonl`（`notify` 动作的落点）。
3. 若要验证动作，先在 `config.selftest.yaml` 的 `policy.whitelist` 加动作名，或走 `pending → approve`。
4. 单测：把纯函数（解析、判定）抽出来，用 `tests/test_core.py` 的模式直接 import 测，不必起 daemon。

---

## 9. 发布清单

- [ ] `PLUGIN.name` 唯一、语义清晰
- [ ] `permissions` 最小化（不需要 exec 就不要开）
- [ ] 检测器有 `interval`，不阻塞
- [ ] 动作返回 `(ok, detail)`
- [ ] 规则有 `cooldown` / `max_attempts`，避免风暴
- [ ] 不在源码里出现禁用构造
- [ ] `teardown` 清理自建资源
- [ ] 在 selftest 配置下验证过热加载、检测、处置、审计四条链路
