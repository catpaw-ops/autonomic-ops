"""Version and identity constants for AutonomicOps."""

VERSION = "1.0.0"
CODENAME = "aegis"
PRODUCT = "AutonomicOps"
PRODUCT_CN = "自治无人值守运维 Agent"
DEFAULT_PREFIX = "/opt/autonomic-ops"
SERVICE_NAME = "autonomic-ops"


def version_string() -> str:
    return f"{PRODUCT} {VERSION} ({CODENAME})"
