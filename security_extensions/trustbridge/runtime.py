"""Per-process TrustBridge state shared by the NLIP extension and the tool gate.

The NLIP extension sees messages at the agent boundary; the tool gate runs inside the
agent framework. This module is the bridge between them: the extension stores the
verified grant and provenance for a session here, and the gate reads them back.
State is process-local, like the SDK's own session store.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field, fields
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .tokens import DEV_SECRET


@dataclass
class TrustContext:
    """What one session is allowed to do and whether it has seen untrusted content."""

    grant: dict | None = None
    grant_token: str | None = None
    tainted: bool = False
    sources: list[str] = field(default_factory=list)

    def taint(self, source: str) -> None:
        self.tainted = True
        if source not in self.sources:
            self.sources.append(source)


@dataclass
class Settings:
    secret: str = DEV_SECRET
    # Ablation switches; all True is the full design.
    verify_signature: bool = True
    check_expiry: bool = True
    use_provenance: bool = True
    require_grant: bool = True
    # A grant serves one conversation per entity; reuse from another session is replay.
    single_use_grants: bool = True
    # Tools each peer can use. When set, a delegated grant is narrowed to the
    # destination's tools (child = parent ∩ capabilities[peer]). Unset = pass through.
    capabilities: dict[str, list[str]] | None = None
    # Tools whose results are attacker-controllable.
    untrusted_tools: tuple[str, ...] = ("read_document",)
    # Delegation itself is not gated; the grant travels with it instead.
    ungated_tools: tuple[str, ...] = ("send_nlip_message",)
    # Arguments that decide where an action goes. If the session has seen untrusted
    # content, their values must have been pinned by the user in the grant.
    control_args: dict[str, tuple[str, ...]] = field(
        default_factory=lambda: {"send_email": ("to", "cc")}
    )
    decision_log: str | None = None


class TrustRuntime:
    def __init__(self) -> None:
        self.enabled = False
        self.settings = Settings()
        self._contexts: dict[str, TrustContext] = {}
        # Outbound client session id -> inbound session id it acts for.
        self._parents: dict[str, str] = {}
        # (entity, task_id) -> (session id that first used the grant, grant expiry).
        self._bound_tasks: dict[tuple[str, str], tuple[str, float]] = {}

    def configure(self, **options: Any) -> None:
        known = {f.name for f in fields(Settings)}
        unknown = set(options) - known
        if unknown:
            raise ValueError(f"Unknown TrustBridge option(s): {', '.join(sorted(unknown))}")
        for key in ("untrusted_tools", "ungated_tools"):
            if key in options:
                options[key] = tuple(options[key])
        if "control_args" in options:
            options["control_args"] = {k: tuple(v) for k, v in options["control_args"].items()}
        self.settings = Settings(**options)
        self.enabled = True

    def link(self, child_session_id: str, parent_session_id: str) -> None:
        """Record that an outbound conversation acts on behalf of an inbound session."""
        self._parents[child_session_id] = parent_session_id

    def context(self, session_id: str) -> TrustContext:
        session_id = self._parents.get(session_id, session_id)
        return self._contexts.setdefault(session_id, TrustContext())

    def bind_task(self, entity: str, task_id: str, session_id: str, expires: float) -> bool:
        """Bind a grant to its first session at this entity. False if another owns it.

        Each agent on the delegation path uses the same task once, in one conversation.

        Bindings outlive evicted sessions until the grant expires, so an old grant
        cannot be replayed into a fresh conversation.
        """
        now = time.time()
        for task, (_, exp) in list(self._bound_tasks.items()):
            if exp < now:
                del self._bound_tasks[task]
        owner = self._bound_tasks.setdefault((entity, task_id), (session_id, expires))[0]
        return owner == session_id

    def forget(self, session_id: str) -> None:
        self._contexts.pop(session_id, None)
        for child in [c for c, p in self._parents.items() if p == session_id]:
            del self._parents[child]

    def log(self, record: dict[str, Any]) -> None:
        if not self.settings.decision_log:
            return
        path = Path(self.settings.decision_log)
        path.parent.mkdir(parents=True, exist_ok=True)
        record = {"time": datetime.now(timezone.utc).isoformat(), **record}
        with path.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")


RUNTIME = TrustRuntime()


def link_outbound(child_session_id: str, parent_session_id: str) -> None:
    """Call before an agent delegates over NLIP, so the grant follows the request."""
    RUNTIME.link(child_session_id, parent_session_id)
