# 首次发布到 GitHub

> 这份文档写给**第一次在 GitHub 上发项目**的维护者，尽量不省略步骤。命令中的 `<用户名>`、`<仓库名>` 需要换成你自己的。

## 0. 当前仓库状态

- 仓库根就是这个目录（纯 ASCII 目录名）：源码、配置、文档、`.github/` 都直接位于根下，没有多余的目录壳。**本地开发缓存、日志与临时产物不进入仓库。**
- 已执行 `git init -b main`，**69 个文件已暂存**（`git add .`），全部为 LF 行尾；**尚未创建首次提交**，**未关联远端**，**未推送**。
- 首次提交由维护者本人完成：Git 提交需要作者名与邮箱，仓库链接需要用户名，这些应由维护者确定。
- 本机（Windows）已完成的验证：38 个 Python 文件语法检查、`bash -n scripts/*.sh tests/*.sh`、`git diff --cached --check`、全部 YAML 可解析、`pyproject.toml` 可解析、包内 31 个模块可导入、Markdown 相对链接无失效、**14 项单元测试在「有 PyYAML」和「强制无 PyYAML」两条路径下均通过**。
- 真实 Linux 验证也已完成（2026-11-06）：端到端自测 `PASS=50 FAIL=0`，零依赖与 PyYAML 两条解析路径各一次；单元测试 14/14；`doctor` `failed=0`；安装器真机假根校验通过。完整输出与环境差异见 `docs/SELFTEST_REPORT.md`。
- **补测状态**：已在标准 x86_64 Ubuntu 24.04 + systemd 上完成真实 nftables 封禁/解封、重启自启、`kill -9` 恢复、看门狗共存验证（见 `docs/SELFTEST_REPORT.md`）。仍需补：≥24h 长稳观测、非 root 运行路径。

随时可以用 `git status` 与 `git diff --cached --stat` 查看当前暂存了什么。

### 0.1 标准 Linux VM 补测清单

给下一台测试机的建议规格，**一次配好**，避免又遇到精简 rootfs 或缺工具链：

| 项 | 建议 |
|---|---|
| 架构 / 系统 | `x86_64`，Debian 12 或 Ubuntu 22.04/24.04，**标准发行版内核**（非容器、非定制内核） |
| 权限 | 普通用户 + `sudo`；另备 root 用于防火墙与 systemd 测试 |
| 网络 | 有默认路由与外网（可 `apt install`），NTP/chrony 时间同步正常 |
| init | `systemd` 为 PID 1，`systemctl is-system-running` = `running` |
| 预装 | `python3` ≥3.9、`python3-yaml`、`jq`、`curl`、`tar`、`git`、`nftables`（或 `iptables`）、`openssh-server`、`sudo` |
| 隔离 | 一次性 VM / 快照，测完可整体丢弃 |

环境到手后按序执行：

```bash
# 0. 环境确认
uname -m; cat /etc/os-release; timedatectl; ip route show default
systemctl is-system-running; python3 -V; jq --version; nft --version || iptables -V

# 1. 静态与单元测试（两条配置解析路径）
make check && make test && make test-no-yaml

# 2. 端到端自测跑两次：默认零依赖路径 / 装上 PyYAML 后
bash tests/selftest.sh
sudo apt-get install -y python3-yaml && bash tests/selftest.sh

# 3. doctor 与真实安装
python3 -m autonomic.main -c config/config.selftest.yaml --doctor
sudo bash scripts/install.sh --prefix /opt/autonomic-ops \
  --bootstrap-token "$(openssl rand -hex 24)"
sudo systemctl enable --now autonomic-ops
sudo /opt/autonomic-ops/bin/autonomic-ops doctor

# 4. 真实系统未覆盖的项（逐项记录实际输出）
#  - 真实封禁：firewall_backend=auto，触发 SSH 暴破，确认 nft/iptables 真有规则、simulated=false
#  - systemd：reboot 后自动拉起；kill -9 主进程后 Restart=on-failure 生效
#  - 外部看门狗：enable autonomic-ops-watchdog.service，确认与主服务共存
#  - 非 root：专用用户 + 精细 sudo 授权，确认降级路径不谎报成功
#  - 长稳：至少 24h，观察 RSS / fd / 日志滚动 / 审计链
```

跑完把真实输出补进 `docs/SELFTEST_REPORT.md`，并更新 README 顶部的状态声明。

## 1. 发布前必做

### 1.1 替换占位符

全仓搜一遍：

```bash
grep -rn "YOUR_GITHUB_USERNAME\|<your-repo-url>\|<用户名>\|<仓库名>" \
  --exclude-dir=.git --exclude-dir=.workbuddy-ai .
```

需要替换的位置：

| 文件 | 内容 |
|---|---|
| `CHANGELOG.md` 底部 | 两个版本比较 / Release 链接里的 `YOUR_GITHUB_USERNAME` |
| `README.md` / `README.en.md` | 快速开始里的 `<your-repo-url>` |
| `docs/DEPLOYMENT.md` | 第 32 行 `git clone <your-repo-url>` |
| `docs/RELEASING.md` | 本文示例命令里的 `<用户名>` / `<仓库名>`（可选） |
| `LICENSE` | 版权人目前是 `AutonomicOps contributors`，想写自己名字可改 |
| `pyproject.toml` | `authors` 目前是 `AutonomicOps contributors`，同上（可选） |

一次性替换用户名（Git Bash / Linux / macOS）：

```bash
grep -rl "YOUR_GITHUB_USERNAME" --exclude-dir=.git . \
  | xargs sed -i "s/YOUR_GITHUB_USERNAME/<你的用户名>/g"
```

`<your-repo-url>` 换成 `https://github.com/<用户名>/<仓库名>.git`。

### 1.2 检查清单

- [ ] `git status` 里没有 `*.pyc`、`__pycache__/`、`*.log`、`*.pid`、`*.token`、`config/config.yaml`、`.env`，也没有本地缓存或临时工作目录
- [ ] `git diff --cached --stat` 的文件数量与预期一致（当前为 **69 个文件**，不含缓存）
- [ ] `grep -rni "api.key\|token" config/` 里没有真实密钥
- [ ] `bash -n scripts/*.sh tests/*.sh` 通过
- [ ] `make check` 通过
- [ ] README 顶部状态声明与 1.0.0 发布一致
- [ ] `CHANGELOG.md` 的 1.0.0 描述准确
- [ ] `LICENSE` 与 `DISCLAIMER.md` 都在仓库里
- [x] 在真实 Linux 上跑过端到端自测（2026-11-06，50/50，双配置解析路径，见 `docs/SELFTEST_REPORT.md`）
- [ ] 在标准 x86_64 服务器 / VPS 上补测未覆盖项（真实防火墙、systemd 自启、非 root、长稳运行）

### 1.3 提交前最后一次安全扫描

```bash
git diff --cached | grep -iE "api[_-]?key|secret|password|BEGIN .*PRIVATE KEY|token:" || true
```

任何命中都先人工确认是占位符还是真实值。**一旦真实密钥被推送到公开仓库，即使后来删除也算泄漏，必须立刻轮换。**

## 2. 首次发布：网页 + 命令行

### 第 1 步：在 GitHub 建空仓库

1. 登录 GitHub，右上角 `+` → `New repository`。
2. `Repository name` 填 `autonomic-ops`（或你喜欢的名字）；`Description` 可填 "An unattended, policy-gated self-healing ops agent for single Linux hosts"。
3. 选 `Public`；**不要勾选** `Add a README file`、`Add .gitignore`、`Choose a license`——本地已经有了，勾了会和首次推送冲突。
4. 点 `Create repository`，复制页面上的 HTTPS 地址（`https://github.com/<用户名>/<仓库名>.git`）。

### 第 2 步：本地提交并推送

```bash
cd <你的仓库目录>             # 例如 ~/autonomic-ops；用相对写法，不要在公开文档里写本机路径

git config user.name "你的名字"
git config user.email "你的邮箱"       # 建议用 GitHub 账号绑定的邮箱

git add .
git status                             # 再确认一次暂存内容
git commit -m "Initial release: AutonomicOps 1.0.0"
git branch -M main
git remote add origin https://github.com/<用户名>/<仓库名>.git
git push -u origin main
```

### 第 3 步：认证

GitHub **不接受账号密码**推送，二选一：

- **Personal Access Token（最简单）**：GitHub → `Settings` → `Developer settings` → `Personal access tokens` → `Fine-grained tokens` → 生成，给目标仓库 `Contents: Read and write` 权限；推送时用户名填 GitHub 用户名，密码栏粘贴 token。Windows 上 Git Credential Manager 会帮你缓存。
- **SSH key**：`ssh-keygen -t ed25519 -C "你的邮箱"`，把 `~/.ssh/id_ed25519.pub` 加到 GitHub 的 `SSH and GPG keys`，然后把远端地址改成 `git@github.com:<用户名>/<仓库名>.git`。

### 第 4 步：确认发布成功

刷新仓库页面，检查：

- README 正常渲染，中文与英文链接都能点开；
- `LICENSE` 被 GitHub 识别为 MIT；
- `.gitignore` 生效（仓库里看不到 `__pycache__`、日志文件）；
- `Actions` 标签页里 CI 跑起来了（Python 3.9 / 3.12 两个任务）；
- `Insights` → `Network` 里只有一条 `main` 初始提交。

## 3. 常见坑

| 坑 | 处理 |
|---|---|
| 推送被拒：远端已有 README | 建仓库时勾了自带文件。先 `git pull --rebase origin main`，或删掉仓库重建空仓库 |
| Linux 上脚本报 `bad interpreter: ^M` | 行尾是 CRLF。`.gitattributes` 已强制 LF；若仍出现，执行 `git add --renormalize .` |
| 把 `__pycache__` 传上去了 | `.gitignore` 已覆盖；用 `git rm -r --cached __pycache__` 移除后重新提交 |
| 误提交密钥 | 立刻轮换密钥，然后清理历史（`git filter-repo`），不要只删文件 |
| 中文路径 / 文件名乱码 | 仓库内文件名全部使用 ASCII；本地工作目录含中文不影响 Git |
| CI 红灯 | 先看日志：最常见是 Python 3.9 上用了 3.10+ 语法，或配置校验失败 |

## 4. 发布之后

```bash
git tag -a v1.0.0 -m "AutonomicOps 1.0.0 (aegis)"
git push origin v1.0.0
```

然后在 GitHub `Releases` → `Create a new release`，选 `v1.0.0`，把 `CHANGELOG.md` 中 1.0.0 段落贴进去。

建议顺手做的仓库设置：

- `About` 填简介与 Topics：`linux`、`ops`、`monitoring`、`self-healing`、`python`、`agent`；
- `Settings` → `Security` 打开 `Private vulnerability reporting`（配合 `SECURITY.md`）；
- `Settings` → `Branches` 给 `main` 加保护：要求 PR + CI 通过后再合并；
- 开启 `Issues`，`Discussions` 可视需要开启。

## 5. 长期维护节奏

1. 每个改动走分支 + PR，填 `.github/pull_request_template.md` 的清单。
2. 行为变更同步更新 `config/config.example.yaml`、`docs/` 与 `CHANGELOG.md`（新版本发布前记入 `Unreleased` 段落）。
3. 版本号遵循语义化版本：修 bug → 补丁，新能力 → 次版本，破坏性变更 → 主版本。
4. 发版时把 Unreleased 改成版本号 + 日期，打 tag，写 Release Notes。
5. 每次涉及策略 / 权限 / 沙箱 / 审计的改动，重新读一遍 `SECURITY.md` 的红线。
6. 定期在 Linux 复跑 `tests/selftest.sh`，别只信 CI 的绿灯。

## 6. 绝对不要提交的东西

`config/config.yaml`（生效配置）、`*.token`、`ipc.token`、`.env`、任何 `*.log` / `*.pid`、`__pycache__/` 与 `*.pyc`、备份快照、包含真实 IP 的审计日志、任何 API Key 或私钥。`.gitignore` 已覆盖大部分，但**提交前人工看一眼**永远不亏。
