"""TrustBridge NLIP security extension: carry and verify grant and provenance.

Enable it at both ingress and egress of every agent:

- Ingress (server): verify the request's grant, block if missing or invalid, and
  record any incoming provenance. This is where an agent learns what the user allowed.
- Ingress (client): record provenance on responses from agents it delegated to.
- Egress (client): attach a grant narrowed to the destination's tools, plus this
  session's provenance, so the restrictions and the taint survive the agent boundary.
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
    derive_grant,
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
        if settings.single_use_grants and not RUNTIME.bind_task(
            event.local_entity, grant["task_id"], event.session.id, float(grant["exp"])
        ):
            self._log(event, "block", "grant already used by another session (replay)")
            return SecurityDecision.block("TrustBridge: grant already used by another session")
        context.grant, context.grant_token = grant, str(token)
        return SecurityDecision.allow()

    def _egress(self, event: SecurityEvent, context: TrustContext) -> SecurityDecision:
        settings = RUNTIME.settings
        message = event.message.model_copy(deep=True)
        if event.component == "client" and context.grant_token is not None:
            message.add_token(self._delegated_grant(event, context), GRANT_TOKEN)
        message.add_token(
            provenance_token(
                context.tainted, context.sources, event.local_entity, settings.secret
            ),
            PROVENANCE_TOKEN,
        )
        return SecurityDecision.replace(message, "attached TrustBridge context")

    @staticmethod
    def _delegated_grant(event: SecurityEvent, context: TrustContext) -> str:
        """Grant for the destination: narrowed to its tools, never wider than ours."""
        settings = RUNTIME.settings
        if settings.capabilities is None:
            return str(context.grant_token)
        allow = settings.capabilities.get(event.peer or "", [])
        return derive_grant(
            str(context.grant_token), context.grant, allow, event.local_entity, settings.secret
        )

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
