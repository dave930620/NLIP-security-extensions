"""TrustBridge: keep provenance and authority intact across agent and tool boundaries."""

from .authorizer import TASKS, issue_grant
from .extension import TrustBridgeExtension
from .gate import check, claude_hooks
from .runtime import RUNTIME, link_outbound
from .tokens import GRANT_TOKEN, PROVENANCE_TOKEN

__all__ = [
    "GRANT_TOKEN",
    "PROVENANCE_TOKEN",
    "RUNTIME",
    "TASKS",
    "TrustBridgeExtension",
    "check",
    "claude_hooks",
    "issue_grant",
    "link_outbound",
]
