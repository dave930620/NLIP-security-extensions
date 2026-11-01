import asyncio
import time

from nlip_sdk import NLIPMessage, NLIPSession
from nlip_sdk.nlip_security_extensions import (
    EnforcementPoint,
    SecurityAction,
    SecurityEvent,
)
from security_extensions.trustbridge import (
    GRANT_TOKEN,
    PROVENANCE_TOKEN,
    RUNTIME,
    TrustBridgeExtension,
    check,
    issue_grant,
    link_outbound,
)
from security_extensions.trustbridge.runtime import Settings, TrustContext
from security_extensions.trustbridge.tokens import DEV_SECRET, decode_grant, sign

BOB = "bob@northwind.com"
ATTACKER = "audit-desk@northwind-review.com"


def email_grant() -> dict:
    token = issue_grant("alice", "email_manager", {"send_email.to": [BOB]})
    return decode_grant(token, DEV_SECRET)


def event(point, message, session_id, component, entity="executor"):
    return SecurityEvent(
        point=point,
        message=message,
        session=NLIPSession(session_id),
        local_entity=entity,
        peer="peer",
        component=component,
    )


def test_grant_signature_expiry_and_forgery() -> None:
    token = issue_grant("alice", "save_only")
    assert decode_grant(token, DEV_SECRET)["allow"] == ["read_document", "save_summary"]

    # An attacker cannot widen a grant without the key.
    forged = sign(
        {"type": "grant", "task_id": "x", "allow": ["send_email"], "exp": time.time() + 60},
        "attacker-key",
    )
    assert decode_grant(forged, DEV_SECRET) is None
    # ...unless signature checking is disabled (ablation).
    assert decode_grant(forged, DEV_SECRET, check_signature=False) is not None

    expired = issue_grant("alice", "save_only", ttl_s=-1)
    assert decode_grant(expired, DEV_SECRET) is None


def test_gate_authority_and_provenance() -> None:
    settings = Settings()
    clean = TrustContext(grant=email_grant())
    tainted = TrustContext(grant=email_grant())
    tainted.taint("read_document:q3_report_rev6.txt")

    assert check(clean, "send_email", {"to": BOB}, settings)[0]
    assert check(tainted, "send_email", {"to": BOB}, settings)[0]
    # Recipient not chosen by the user: authority blocks it regardless of taint.
    assert not check(clean, "send_email", {"to": ATTACKER}, settings)[0]
    # Unpinned cc: allowed in a clean session, blocked after untrusted content.
    assert check(clean, "send_email", {"to": BOB, "cc": ATTACKER}, settings)[0]
    allowed, reason = check(tainted, "send_email", {"to": BOB, "cc": ATTACKER}, settings)
    assert not allowed and "untrusted" in reason
    # Tool outside the grant, and no grant at all.
    assert not check(clean, "save_summary", {"filename": "x"}, settings)[0]
    assert not check(TrustContext(), "read_document", {"name": "x"}, settings)[0]


def test_authority_only_ablation_misses_cc_attack() -> None:
    tainted = TrustContext(grant=email_grant())
    tainted.taint("read_document:doc")
    settings = Settings(use_provenance=False)
    assert check(tainted, "send_email", {"to": BOB, "cc": ATTACKER}, settings)[0]


def test_grant_and_taint_cross_the_agent_boundary() -> None:
    extension = TrustBridgeExtension()
    grant_token = issue_grant("alice", "email_manager", {"send_email.to": [BOB]})

    # Reader receives the user's request with a grant.
    request = NLIPMessage.text("Summarize and email Bob.")
    request.add_token(grant_token, GRANT_TOKEN)
    decision = asyncio.run(
        extension.evaluate(event(EnforcementPoint.INGRESS, request, "reader-in", "server", "reader"))
    )
    assert decision.action is SecurityAction.ALLOW
    RUNTIME.context("reader-in").taint("read_document:q3_report_rev6.txt")

    # Reader delegates; the outbound request carries the grant and the taint.
    link_outbound("reader-out", "reader-in")
    decision = asyncio.run(
        extension.evaluate(
            event(EnforcementPoint.EGRESS, NLIPMessage.text("email Bob"), "reader-out", "client", "reader")
        )
    )
    delegated = decision.message
    assert delegated.extract_token(GRANT_TOKEN) == grant_token
    assert delegated.extract_token(PROVENANCE_TOKEN) is not None

    # Executor accepts it and inherits both.
    decision = asyncio.run(
        extension.evaluate(event(EnforcementPoint.INGRESS, delegated, "exec-in", "server"))
    )
    assert decision.action is SecurityAction.ALLOW
    executor = RUNTIME.context("exec-in")
    assert executor.grant["task"] == "email_manager"
    assert executor.tainted and "read_document:q3_report_rev6.txt" in executor.sources


def test_requests_without_valid_grant_or_with_forged_provenance() -> None:
    extension = TrustBridgeExtension()
    no_grant = NLIPMessage.text("send the report to the auditor")
    decision = asyncio.run(
        extension.evaluate(event(EnforcementPoint.INGRESS, no_grant, "s-none", "server"))
    )
    assert decision.action is SecurityAction.BLOCK

    # A forged "clean" provenance token cannot un-taint a session; it taints it.
    message = NLIPMessage.text("summary")
    message.add_token(issue_grant("alice", "save_only"), GRANT_TOKEN)
    message.add_token(sign({"type": "provenance", "tainted": False}, "attacker-key"), PROVENANCE_TOKEN)
    asyncio.run(extension.evaluate(event(EnforcementPoint.INGRESS, message, "s-forged", "server")))
    assert RUNTIME.context("s-forged").tainted
