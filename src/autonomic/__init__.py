"""AutonomicOps - an unattended, self-healing operations agent.

Public package. The daemon entry point is ``autonomic.main``; the operator
entry point is ``autonomic.cli``. Keep both import-light: importing this package
must not start threads or touch the filesystem.
"""

from .version import VERSION, PRODUCT, version_string  # noqa: F401

__all__ = ["VERSION", "PRODUCT", "version_string"]
