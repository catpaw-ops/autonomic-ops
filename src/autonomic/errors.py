"""Typed exceptions used across the agent.

Every subsystem raises a narrow exception type so the scheduler / IPC layer can
map failures to stable error codes instead of leaking stack traces to clients.
"""

from typing import Optional


class AutonomicError(Exception):
    """Base error. `code` is stable and safe to expose over the IPC socket."""

    code = "autonomic.error"
    http_hint = 500

    def __init__(self, message: str, code: Optional[str] = None, **context):
        super().__init__(message)
        self.message = message
        self.context = context
        if code:
            self.code = code

    def to_dict(self) -> dict:
        return {"code": self.code, "message": self.message, "context": self.context}


class ConfigError(AutonomicError):
    code = "config.invalid"


class PolicyDenied(AutonomicError):
    code = "policy.denied"


class ApprovalRequired(AutonomicError):
    code = "policy.approval_required"


class SandboxError(AutonomicError):
    code = "sandbox.failed"


class SandboxTimeout(SandboxError):
    code = "sandbox.timeout"


class ValidationError(AutonomicError):
    code = "validation.failed"


class BackupError(AutonomicError):
    code = "backup.failed"


class PluginError(AutonomicError):
    code = "plugin.error"


class IPCError(AutonomicError):
    code = "ipc.error"


class TaskError(AutonomicError):
    code = "task.error"


class CapabilityMissing(AutonomicError):
    code = "capability.missing"
