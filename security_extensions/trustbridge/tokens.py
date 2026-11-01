"""Signed tokens carried in NLIP ``token`` submessages.

Two token types travel with every delegated request:

- ``trustbridge_grant``: what the user authorized (issued once by the authorizer).
- ``trustbridge_provenance``: whether the sender's context contains untrusted content.

Tokens are ``base64url(json).base64url(hmac_sha256)``. All trusted runtimes in the demo
share one HMAC key; a production deployment would use per-issuer keys.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any

GRANT_TOKEN = "trustbridge_grant"
PROVENANCE_TOKEN = "trustbridge_provenance"
# Demo-only default so the app runs out of the box. Override with the extension's
# ``secret`` option for anything beyond local experiments.
DEV_SECRET = "trustbridge-dev-secret-change-me"


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _mac(body: str, secret: str) -> str:
    return _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())


def sign(payload: dict[str, Any], secret: str) -> str:
    body = _b64(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())
    return f"{body}.{_mac(body, secret)}"


def decode(token: object, secret: str, *, check_signature: bool = True) -> dict | None:
    """Return the payload, or None if the token is malformed or its MAC is wrong."""
    if not isinstance(token, str) or token.count(".") != 1:
        return None
    body, mac = token.split(".")
    if check_signature and not hmac.compare_digest(mac, _mac(body, secret)):
        return None
    try:
        payload = json.loads(_unb64(body))
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


MAX_DELEGATION_DEPTH = 5


def decode_grant(
    token: object,
    secret: str,
    *,
    check_signature: bool = True,
    check_expiry: bool = True,
    _depth: int = 0,
) -> dict | None:
    """Verify a grant and, for a delegated grant, its whole chain back to the user.

    A delegated grant embeds its parent token. It is valid only if the parent is valid
    and the child is no wider: same task, a subset of tools, no later expiry, and every
    argument the parent pinned is still pinned to a subset of the same values.
    """
    if _depth > MAX_DELEGATION_DEPTH:
        return None
    grant = decode(token, secret, check_signature=check_signature)
    if grant is None or grant.get("type") != "grant":
        return None
    if not isinstance(grant.get("allow"), list):
        return None
    if check_expiry and float(grant.get("exp", 0)) < time.time():
        return None
    if "parent" not in grant:
        return grant

    parent = decode_grant(
        grant["parent"],
        secret,
        check_signature=check_signature,
        check_expiry=check_expiry,
        _depth=_depth + 1,
    )
    if parent is None or not _narrows(grant, parent):
        return None
    return grant


def _narrows(child: dict, parent: dict) -> bool:
    if child.get("task_id") != parent.get("task_id"):
        return False
    if not set(child["allow"]) <= set(parent["allow"]):
        return False
    if float(child.get("exp", 0)) > float(parent.get("exp", 0)):
        return False
    child_pins = child.get("constraints", {})
    for tool, pins in parent.get("constraints", {}).items():
        if tool not in child["allow"]:
            continue
        for arg, values in pins.items():
            child_values = child_pins.get(tool, {}).get(arg)
            if child_values is None or not set(child_values) <= set(values):
                return False
    return True


def derive_grant(
    parent_token: str, parent: dict, allow: list[str], issuer: str, secret: str
) -> str:
    """Delegate a narrower grant: keep only ``allow`` tools that the parent already has."""
    tools = [tool for tool in parent["allow"] if tool in allow]
    payload = {
        "type": "grant",
        "task_id": parent["task_id"],
        "task": parent.get("task"),
        "user": parent.get("user"),
        "allow": tools,
        "constraints": {
            tool: pins
            for tool, pins in parent.get("constraints", {}).items()
            if tool in tools
        },
        "exp": parent["exp"],
        "issuer": issuer,
        "parent": parent_token,
    }
    return sign(payload, secret)


def provenance_token(tainted: bool, sources: list[str], issuer: str, secret: str) -> str:
    payload = {"type": "provenance", "tainted": tainted, "sources": sources, "issuer": issuer}
    return sign(payload, secret)
