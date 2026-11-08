"""Signed session tokens and backend identity assertions (HMAC-SHA256, compact and URL-safe).

Format: base64url(json payload) "." base64url(signature). The signature covers the encoded payload, so changing any
byte of either part fails verification. Comparison is constant time.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets


class TokenError(ValueError):
    pass


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (ValueError, TypeError) as e:
        raise TokenError("malformed token") from e


def signing_key() -> bytes:
    """The shared key from ZTGATE_SIGNING_KEY. Without one, each process gets a random key, which is fine for tests
    and the single-process demo stack but means separate processes cannot verify each other's tokens."""
    key = os.environ.get("ZTGATE_SIGNING_KEY")
    return key.encode() if key else secrets.token_bytes(32)


def sign(payload: dict, key: bytes, purpose: str = "session") -> str:
    body = _b64(json.dumps({**payload, "typ": purpose}, separators=(",", ":"), sort_keys=True).encode())
    mac = hmac.new(key, f"{purpose}.{body}".encode(), hashlib.sha256).digest()
    return f"{body}.{_b64(mac)}"


def verify(token: str, key: bytes, now: float, purpose: str = "session") -> dict:
    """Return the payload of a valid, unexpired token or raise TokenError with the reason."""
    if not isinstance(token, str) or token.count(".") != 1:
        raise TokenError("malformed token")
    body, sig = token.split(".")
    want = hmac.new(key, f"{purpose}.{body}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(want, _unb64(sig)):
        raise TokenError("bad signature")
    try:
        payload = json.loads(_unb64(body))
    except (ValueError, UnicodeDecodeError) as e:
        raise TokenError("malformed token") from e
    if payload.get("typ") != purpose:
        raise TokenError("wrong token type")
    if "exp" in payload and now >= payload["exp"]:
        raise TokenError("token expired")
    return payload
