"""TrustBridge NLIP security extension: carry and verify grant and provenance.

Enable it at both ingress and egress of every agent:

- Ingress (server): verify the request's grant, block if missing or invalid, and
  record any incoming provenance. This is where an agent learns what the user allowed.
- Ingress (client): record provenance on responses from agents it delegated to.
- Egress (client): attach the grant and this session's provenance to a delegated
  request, so the restrictions and the taint survive the agent boundary.
- Egress (server): attach provenance to the response.

The decision on tool calls is made by the tool gate in ``gate.py``.
"""

from __future__ import annotations

from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityDecision,
    SecurityEvent,
    SecurityExtension,
)

from .runtime import RUNTIME, TrustContext
from .tokens import (
    GRANT_TOKEN,
    PROVENANCE_TOKEN,
    decode,
    decode_grant,
    provenance_token,
)


class TrustBridgeExtension(SecurityExtension):
    def __init__(self, **options: object) -> None:
        RUNTIME.configure(**options)

    async def evaluate(self, event: SecurityEvent) -> SecurityDecision:
        context = RUNTIME.context(event.session.id)
        if event.point is EnforcementPoint.INGRESS:
            return self._ingress(event, context)
        return self._egress(event, context)

    def _ingress(self, event: SecurityEvent, context: TrustContext) -> SecurityDecision:
        settings = RUNTIME.settings
        for token in event.message.token_submessages():
            if token.subformat.casefold() != PROVENANCE_TOKEN:
                continue
            provenance = decode(
                token.content, settings.secret, check_signature=settings.verify_signature
            )
            if provenance is None:
                # Unverifiable provenance is treated as untrusted, never as clean.
                context.taint(f"unverified provenance from {event.peer or 'peer'}")
            elif provenance.get("tainted"):
                for source in provenance.get("sources") or ["upstream"]:
                    context.taint(str(source))

        if event.component != "server":
            return SecurityDecision.allow()

        token = event.message.extract_token(GRANT_TOKEN)
        grant = decode_grant(
            token,
            settings.secret,
            check_signature=settings.verify_signature,
            check_expiry=settings.check_expiry,
        )
        if grant is None:
            if settings.require_grant:
                reason = "missing grant" if token is None else "invalid or expired grant"
                self._log(event, "block", reason)
                return SecurityDecision.block(f"TrustBridge: {reason}")
            return SecurityDecision.allow()
        if context.grant is not None and context.grant["task_id"] != grant["task_id"]:
            self._log(event, "block", "grant belongs to a different task")
            return SecurityDecision.block("TrustBridge: grant belongs to a different task")
        context.grant, context.grant_token = grant, str(token)
        return SecurityDecision.allow()

    def _egress(self, event: SecurityEvent, context: TrustContext) -> SecurityDecision:
        settings = RUNTIME.settings
        message = event.message.model_copy(deep=True)
        if event.component == "client" and context.grant_token is not None:
            # Pass the grant through unchanged: a delegate never gets more than this.
            message.add_token(context.grant_token, GRANT_TOKEN)
        message.add_token(
            provenance_token(
                context.tainted, context.sources, event.local_entity, settings.secret
            ),
            PROVENANCE_TOKEN,
        )
        return SecurityDecision.replace(message, "attached TrustBridge context")

    @staticmethod
    def _log(event: SecurityEvent, decision: str, reason: str) -> None:
        RUNTIME.log(
            {
                "event": f"nlip_{event.point.value}",
                "entity": event.local_entity,
                "session": event.session.id,
                "decision": decision,
                "reason": reason,
            }
        )
