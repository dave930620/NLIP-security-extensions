"""Observation-only extension that records NLIP traffic for evaluation.

It always allows the message. Evaluation scripts read ``runtime/nlip_log.jsonl`` to
check whether an injected instruction actually crossed an agent boundary.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from nlip_sdk.nlip_security_extensions import (
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
)

from ._config import RUNTIME_DIR

NLIP_LOG = RUNTIME_DIR / "nlip_log.jsonl"


class MessageLogExtension(SecurityExtension):
    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        record = {
            "time": datetime.now(timezone.utc).isoformat(),
            "entity": event.local_entity,
            "point": event.point.value,
            "component": event.component,
            "peer": event.peer,
            "text": event.message.extract_text(language=None),
        }
        with NLIP_LOG.open("a", encoding="utf-8") as log:
            log.write(json.dumps(record, ensure_ascii=False) + "\n")
        return SecurityDecision.allow()


def read_nlip_log() -> list[dict]:
    if not NLIP_LOG.exists():
        return []
    return [json.loads(line) for line in NLIP_LOG.read_text().splitlines() if line]
