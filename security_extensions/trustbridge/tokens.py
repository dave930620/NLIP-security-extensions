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


def decode_grant(
    token: object,
    secret: str,
    *,
    check_signature: bool = True,
    check_expiry: bool = True,
) -> dict | None:
    grant = decode(token, secret, check_signature=check_signature)
    if grant is None or grant.get("type") != "grant":
        return None
    if not isinstance(grant.get("allow"), list):
        return None
    if check_expiry and float(grant.get("exp", 0)) < time.time():
        return None
    return grant


def provenance_token(tainted: bool, sources: list[str], issuer: str, secret: str) -> str:
    payload = {"type": "provenance", "tainted": tainted, "sources": sources, "issuer": issuer}
    return sign(payload, secret)
