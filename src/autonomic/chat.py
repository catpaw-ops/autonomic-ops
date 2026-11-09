"""Human conversation channel.

The user can talk to the agent at any time; the scheduler - not the chat layer -
decides whether the resulting task runs now, waits, or safely preempts a
running routine task. Chat only classifies intent and submits work with a
priority; it never kills anything itself.

Intent parsing is rule-based and fully offline: deterministic, auditable, and it
can only map a message to a known intent. It never invents a shell command and
never bypasses the policy gate.
"""

from __future__ import annotations

import logging
import os
import re
from typing import Callable, Optional

from . import util
from .config import Config
from .models import ActionRequest, Priority, Task, TaskKind

INTENTS = {
    "status", "restart", "diagnose", "ban", "unban", "cleanup", "codegen",
    "rollback", "plugins", "logs", "shell", "deploy", "unknown",
}

_RESTART_RE = re.compile(r"(?:重启|restart|拉起|恢复)\s*([A-Za-z0-9_.@\-]+)?", re.I)
_BAN_RE = re.compile(r"(?:封禁|拉黑|ban)\s*(?:ip)?\s*[:：]?\s*([0-9a-fA-F:.]+)", re.I)
_UNBAN_RE = re.compile(r"(?:解封|unban|解除封禁)\s*(?:ip)?\s*[:：]?\s*([0-9a-fA-F:.]+)", re.I)
_ROLLBACK_RE = re.compile(r"(?:回滚|rollback)\s*([A-Za-z0-9_\-]+)", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URGENT_RE = re.compile(r"(紧急|立刻|马上|立即|优先|urgent|asap|now)", re.I)


class ChatService:
    def __init__(self, config: Config, scheduler, coordinator, codegen, plugins, metrics,
                 status_provider: Optional[Callable[[], dict]] = None,
                 rollback_fn: Optional[Callable[[str], dict]] = None,
                 deploy_fn: Optional[Callable[[dict], dict]] = None,
                 audit=None, logger: Optional[logging.Logger] = None):
        self.config = config
        self.scheduler = scheduler
        self.coordinator = coordinator
        self.codegen = codegen
        self.plugins = plugins
        self.metrics = metrics
        self.status_provider = status_provider
        self.rollback_fn = rollback_fn
        self.deploy_fn = deploy_fn
        self.audit = audit
        self._log = logger or logging.getLogger("autonomic.chat")
        self.session_file = config.get("chat.session_file")
        util.ensure_dir(os.path.dirname(self.session_file), 0o750)
        self.max_message = int(config.get("chat.max_message_bytes", 16384))
        self.default_priority = int(config.get("chat.default_priority", 70))

    # --------------------------------------------------------------- history
    def _append(self, role: str, text: str, extra: Optional[dict] = None) -> None:
        record = {"ts": util.iso(), "role": role, "text": util.redact(text)[:4000], "extra": extra or {}}
        try:
            with open(self.session_file, "a", encoding="utf-8") as fh:
                fh.write(util.json_dumps(record) + "\n")
        except OSError:
            pass

    def history(self, limit: int = 20) -> list[dict]:
        rows = []
        for line in util.tail_lines(self.session_file, max(limit, 1) * 2):
            record = util.json_loads(line, {})
            if record:
                rows.append(record)
        return rows[-limit:]

    # ---------------------------------------------------------------- handle
    def handle(self, message: str, actor: str = "user") -> dict:
        text = str(message or "").strip()
        if not text:
            return {"ok": False, "error": "empty message"}
        if len(text.encode("utf-8")) > self.max_message:
            return {"ok": False, "error": f"message exceeds {self.max_message} bytes"}
        self._append("user", text)
        intent, args = self._classify(text)
        priority = self._priority(text)
        try:
            result = self._dispatch(intent, args, text, priority, actor)
        except Exception as exc:  # noqa: BLE001 - chat must always answer
            self._log.error("chat dispatch failed: %s", exc, exc_info=True)
            result = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
        reply = self._format_reply(intent, args, result, priority)
        result["reply"] = reply
        result["intent"] = intent
        result["args"] = args
        self._append("agent", reply, {"intent": intent, "result_status": result.get("status"),
                                      "decision": result.get("decision")})
        self._log.info("chat intent=%s actor=%s priority=%d status=%s", intent, actor, priority,
                       result.get("status") or result.get("ok"))
        if self.audit:
            self.audit.record(actor="user", trigger="chat", action="chat.intent", target=intent,
                              params={"message": text[:400], "priority": priority},
                              result=util.json_dumps({"status": result.get("status"), "ok": result.get("ok")})[:1000])
        return result

    # ------------------------------------------------------------- classify
    def _classify(self, text: str) -> tuple[str, dict]:
        lowered = text.lower()
        if re.search(r"(状态|status|怎么样|健康|还好吗)", lowered) and len(text) <= 40:
            return "status", {}
        match = _UNBAN_RE.search(text)
        if match:
            return "unban", {"ip": match.group(1)}
        match = _BAN_RE.search(text)
        if match:
            return "ban", {"ip": match.group(1)}
        match = _ROLLBACK_RE.search(text)
        if match:
            return "rollback", {"snapshot": match.group(1)}
        match = _RESTART_RE.search(text)
        if match and match.group(1):
            return "restart", {"service": match.group(1)}
        if re.search(r"(清理|cleanup|磁盘满|空间不足|disk full)", lowered):
            return "cleanup", {"paths": re.findall(r"(/[A-Za-z0-9_./\-]+)", text)}
        if re.search(r"(生成|写一个|配置|nginx|systemd|unit|脚本|codegen|patch)", lowered):
            target = ""
            mt = re.search(r"(/[A-Za-z0-9_./\-]+)", text)
            if mt:
                target = mt.group(1)
            purpose = "systemd_unit" if "systemd" in lowered or "unit" in lowered else \
                      "nginx_site" if "nginx" in lowered else \
                      "shell_healthcheck" if "脚本" in text or "shell" in lowered else "config_fragment"
            return "codegen", {"target": target or self._default_target(purpose), "purpose": purpose,
                               "requirements": text}
        if re.search(r"(插件|plugin)", lowered):
            if re.search(r"(安装|install|push|下发)", lowered):
                path = ""
                mt = re.search(r"(/[A-Za-z0-9_./\-]+\.py)", text)
                path = mt.group(1) if mt else ""
                return "plugins", {"action": "install", "path": path}
            if re.search(r"(重载|reload)", lowered):
                return "plugins", {"action": "reload"}
            return "plugins", {"action": "list"}
        if re.search(r"(部署|deploy|接入|初始化)", lowered):
            ip = _IP_RE.search(text)
            return "deploy", {"host": ip.group(1) if ip else ""}
        if re.search(r"(日志|logs)", lowered):
            return "logs", {}
        if re.search(r"(诊断|检查|排查|diagnose|check|体检)", lowered):
            return "diagnose", {}
        if text.startswith(("$", "run ", "执行命令")) or re.match(r"^(df|free|uptime|ss|systemctl status)\b", text):
            command = text[1:].strip() if text.startswith("$") else \
                      text[4:].strip() if text.startswith("run ") else text.replace("执行命令", "").strip()
            return "shell", {"command": command}
        return "unknown", {}

    def _default_target(self, purpose: str) -> str:
        base = str(self.config.get("agent.data_dir"))
        mapping = {"systemd_unit": os.path.join(base, "artifacts", "generated.service"),
                   "nginx_site": os.path.join(base, "artifacts", "generated-site.conf"),
                   "shell_healthcheck": os.path.join(base, "artifacts", "healthcheck.sh"),
                   "config_fragment": os.path.join(base, "artifacts", "fragment.conf")}
        target = mapping.get(purpose, os.path.join(base, "artifacts", "generated.conf"))
        util.ensure_dir(os.path.dirname(target), 0o750)
        return target

    def _priority(self, text: str) -> int:
        if _URGENT_RE.search(text):
            return int(Priority.CRITICAL)
        return self.default_priority

    # ------------------------------------------------------------- dispatch
    def _dispatch(self, intent: str, args: dict, text: str, priority: int, actor: str) -> dict:
        if intent == "status":
            return {"ok": True, "status": "answered", "data": self.status_provider() if self.status_provider else {}}
        if intent == "logs":
            return {"ok": True, "status": "answered",
                    "data": {"hint": "使用 CLI: autonomic-ops logs runtime -n 40 / logs audit -f",
                             "recent": self._recent_log()}}
        if intent == "restart":
            service = args.get("service") or ""
            if not service:
                return {"ok": False, "error": "未识别到服务名，请给出明确名称，例如：重启 nginx"}
            request = ActionRequest(action="process.restart", target=service, params={"service": service},
                                    source="user", reason=f"chat: {text[:120]}")
            return self.coordinator.handle(request)
        if intent == "ban":
            ip = str(args.get("ip") or "")
            if not util.valid_ipv4(ip):
                return {"ok": False, "error": f"无效 IPv4: {ip}"}
            request = ActionRequest(action="firewall.ban_ip", target=ip, params={"ip": ip},
                                    source="user", reason=f"chat: {text[:120]}")
            return self.coordinator.handle(request)
        if intent == "unban":
            ip = str(args.get("ip") or "")
            request = ActionRequest(action="firewall.unban_ip", target=ip, params={"ip": ip},
                                    source="user", reason=f"chat: {text[:120]}")
            return self.coordinator.handle(request)
        if intent == "cleanup":
            routes = [p for p in (args.get("paths") or []) if p]
            request = ActionRequest(action="disk.cleanup", target=",".join(routes) or "policy-defaults",
                                    params={"paths": routes} if routes else {}, source="user",
                                    reason=f"chat: {text[:120]}")
            return self.coordinator.handle(request)
        if intent == "codegen":
            spec = {"target_path": args.get("target"), "purpose": args.get("purpose"),
                    "requirements": args.get("requirements") or text}
            task = Task(kind=TaskKind.CODEGEN.value, payload={"spec": spec, "approved": False},
                        priority=priority, source="user", title=f"codegen: {args.get('purpose')}",
                        timeout=180, preemptible=True)
            decision = self.scheduler.submit(task)
            return {"ok": True, "status": decision.kind, "task_id": task.id, "decision": decision.to_dict(),
                    "note": "代码生成走校验+沙箱预跑+审批，不会直接写入系统"}
        if intent == "rollback":
            if not self.rollback_fn:
                return {"ok": False, "error": "rollback handler unavailable"}
            data = self.rollback_fn(str(args.get("snapshot")))
            return {"ok": bool(data.get("ok")), "status": "answered", "data": data}
        if intent == "plugins":
            action = str(args.get("action") or "list")
            if action == "list":
                return {"ok": True, "status": "answered", "data": {"plugins": self.plugins.list(),
                                                                   "stats": self.plugins.stats()}}
            if action == "reload":
                return {"ok": True, "status": "answered", "data": self.plugins.scan(notify=True)}
            if action == "install":
                path = str(args.get("path") or "")
                if not path:
                    return {"ok": False, "error": "请给出插件文件的绝对路径"}
                return {"ok": True, "status": "answered", "data": self.plugins.install(path)}
        if intent == "shell":
            command = str(args.get("command") or "")
            check = self.coordinator.policy.check_shell(command)
            if not check.allowed:
                return {"ok": False, "status": "denied", "error": check.reason,
                        "note": "只读命令白名单之外的 shell 需要 CLI 审批"}
            task = Task(kind=TaskKind.SHELL.value, payload={"command": command, "policy": check.to_dict()},
                        priority=priority, source="user", title=f"shell: {command[:60]}",
                        timeout=60, preemptible=True)
            decision = self.scheduler.submit(task)
            return {"ok": True, "status": decision.kind, "task_id": task.id, "decision": decision.to_dict()}
        if intent == "deploy":
            if not self.deploy_fn:
                return {"ok": False, "error": "deploy handler unavailable"}
            host = str(args.get("host") or "")
            if not host:
                return {"ok": False, "error": "请提供目标公网 IP，并通过 CLI 提供授权凭据"}
            return {"ok": True, "status": "answered", "data": self.deploy_fn({"host": host, "plan_only": True})}
        if intent == "diagnose":
            task = Task(kind=TaskKind.DIAGNOSTIC.value, payload={"reason": "chat request"},
                        priority=priority, source="user", title="human-requested diagnostic",
                        timeout=60, preemptible=True)
            decision = self.scheduler.submit(task)
            return {"ok": True, "status": decision.kind, "task_id": task.id, "decision": decision.to_dict()}
        # unknown: never silently do nothing - queue a low-priority investigation
        task = Task(kind=TaskKind.DIAGNOSTIC.value,
                    payload={"reason": "unclassified message", "message": text[:400]},
                    priority=int(Priority.BACKGROUND), source="user",
                    title="investigate unclassified request", timeout=60, preemptible=True)
        decision = self.scheduler.submit(task)
        return {"ok": True, "status": "needs_clarification", "task_id": task.id,
                "decision": decision.to_dict(),
                "note": "已排队低优先级排查任务；如需执行变更请用明确指令，例如：重启 nginx / 生成 nginx 配置"}

    def _recent_log(self) -> list[str]:
        log_dir = self.config.get("agent.log_dir")
        return util.tail_lines(os.path.join(log_dir, "runtime.log"), 10)

    # --------------------------------------------------------------- replies
    def _format_reply(self, intent: str, args: dict, result: dict, priority: int) -> str:
        status = str(result.get("status") or "")
        decision = result.get("decision") or {}
        head = ""
        if status == "submitted":
            head = f"已受理（优先级 {priority}）：任务 {result.get('task_id')} 已进入 Worker 执行。"
        elif status == "queue":
            head = (f"已受理（优先级 {priority}）：当前 Worker 忙，任务 {result.get('task_id')} "
                    f"排队第 {decision.get('queue_position', '?')} 位，不会打断正在执行的任务。")
        elif status == "preempt":
            head = (f"已受理（优先级 {priority}）：已安全终止低优先级任务 "
                    f"{decision.get('compared_with')}，为你让出 Worker；被终止任务会自动回到队列。")
        elif status == "pending_approval":
            head = (f"该动作属于受控范围，未直接执行。提案 {result.get('request_id')} 已入库，"
                    f"请用 CLI 审核：autonomic-ops pending / approve {result.get('request_id')}")
        elif status == "denied":
            head = f"动作被策略拒绝：{result.get('error') or (decision.get('reason') if decision else '')}"
        elif status == "answered":
            head = "已处理。"
        elif status == "needs_clarification":
            head = "这条消息没有匹配到可执行意图，已建立低优先级排查任务。"
        else:
            head = "已处理。" if result.get("ok") else f"未执行：{result.get('error', '未知错误')}"

        if intent == "status" and result.get("data"):
            data = result["data"]
            head += (f"\n状态：{data.get('state', '?')} | 队列 {data.get('queue', {}).get('queue_depth', 0)} "
                     f"| Worker {data.get('queue', {}).get('workers', {}).get('busy', 0)}/"
                     f"{data.get('queue', {}).get('workers', {}).get('size', 0)} "
                     f"| 待审批 {data.get('pending_approval', 0)}")
        if status == "pending_approval" and result.get("decision"):
            head += f"\n原因：{result['decision'].get('reason')}"
        return head
