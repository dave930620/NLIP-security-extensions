"""Turn a user's chosen task into a signed grant.

The grant is built only from trusted inputs: the authenticated user, the task they
picked, and values they typed themselves. No model and no document content is
involved, so injected text cannot widen it.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Mapping, Sequence

from .tokens import DEV_SECRET, sign

# Task templates. ``pinned`` lists control arguments whose values must come from the
# user (e.g. the email recipient) and are fixed in the grant.
TASKS: dict[str, dict] = {
    "save_only": {"allow": ["read_document", "save_summary"]},
    "email_manager": {
        "allow": ["read_document", "send_email"],
        "pinned": {"send_email": ["to"]},
    },
}


def issue_grant(
    user: str,
    task: str,
    params: Mapping[str, Sequence[str]] | None = None,
    *,
    secret: str = DEV_SECRET,
    ttl_s: float = 900.0,
) -> str:
    """Return a signed grant token. ``params`` maps ``"tool.arg"`` to user-given values."""
    template = TASKS[task]
    params = params or {}
    constraints: dict[str, dict[str, list[str]]] = {}
    for tool, args in template.get("pinned", {}).items():
        for arg in args:
            key = f"{tool}.{arg}"
            if key not in params:
                raise ValueError(f"Task {task!r} needs a user-provided value for {key}.")
            constraints.setdefault(tool, {})[arg] = [
                str(value).strip().casefold() for value in params[key]
            ]
    payload = {
        "type": "grant",
        "task_id": uuid.uuid4().hex,
        "task": task,
        "user": user,
        "allow": list(template["allow"]),
        "constraints": constraints,
        "exp": time.time() + ttl_s,
    }
    return sign(payload, secret)
