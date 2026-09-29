"""
Access and refresh token handling.

Two kinds of credential exist here, and they are deliberately different:

* an **access token** is a short-lived signed JWT. It is verified without a
  database round trip, but it embeds the session id, so a revoked session stops
  working immediately instead of when the token expires;
* a **refresh token** carries a public, untrusted tenant routing hint and a
  384-bit random secret. Clients treat the whole value as opaque. Only its
  SHA-256 hash is stored; retained rotation history detects reuse.

Nothing in this module reads a configuration default: the signing key comes from
``Settings`` and is never logged, including on the error paths.
"""

from __future__ import annotations

import hashlib
import re
import secrets
import uuid
from datetime import timedelta
from typing import Any

import jwt
from jwt import InvalidTokenError

from app.core.errors import AuthenticationError, ErrorCode
from app.core.time import utc_now

__all__ = [
    "ACCESS_TOKEN_TYPE",
    "REFRESH_TOKEN_TYPE",
    "TokenClaims",
    "decode_access_token",
    "encode_access_token",
    "generate_refresh_token",
    "hash_token",
    "new_session_id",
    "refresh_token_tenant",
    "tokens_match",
]

ACCESS_TOKEN_TYPE = "access"  # noqa: S105 - a token-type label, not a credential
REFRESH_TOKEN_TYPE = "refresh"  # noqa: S105 - a token-type label, not a credential


class TokenClaims:
    """
    The verified contents of an access token.

    A plain object rather than a dict: the fields are named once here instead of
    being re-parsed as strings at each use, so a typo becomes an attribute error
    at import time rather than a silent ``None`` at request time.
    """

    __slots__ = ("expires_at", "issued_at", "session_id", "subject", "tenant_id", "token_type")

    def __init__(
        self,
        *,
        subject: uuid.UUID,
        tenant_id: uuid.UUID,
        session_id: uuid.UUID | None,
        issued_at: Any,
        expires_at: Any,
        token_type: str,
    ) -> None:
        self.subject = subject
        self.tenant_id = tenant_id
        self.session_id = session_id
        self.issued_at = issued_at
        self.expires_at = expires_at
        self.token_type = token_type

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return (
            f"TokenClaims(subject={self.subject}, tenant_id={self.tenant_id}, "
            f"session_id={self.session_id})"
        )


def new_session_id() -> uuid.UUID:
    """A fresh session identifier, minted by the application rather than the database."""
    return uuid.uuid4()


def generate_refresh_token(tenant_id: uuid.UUID) -> str:
    """
    A 384-bit opaque refresh token.

    ``secrets.token_urlsafe`` draws from the operating system's CSPRNG, so the
    token is not predictable from a previous token or from a timestamp.
    """
    # The prefix is a public routing hint, NOT proof of tenant membership. The
    # full token hash must match inside that tenant before any action is taken.
    return f"rt1.{tenant_id}.{secrets.token_urlsafe(48)}"


def refresh_token_tenant(token: str) -> uuid.UUID:
    """Read the untrusted routing hint; malformed/legacy tokens fail closed."""
    parts = token.split(".")
    try:
        if len(parts) != 3 or parts[0] != "rt1" or not re.fullmatch(r"[A-Za-z0-9_-]{64}", parts[2]):
            raise ValueError("Invalid refresh format")
        tenant_id = uuid.UUID(parts[1])
        if str(tenant_id) != parts[1]:
            raise ValueError("Noncanonical tenant")
        return tenant_id
    except ValueError as exc:
        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID, message="Refresh token is not valid."
        ) from exc


def hash_token(token: str) -> str:
    """
    SHA-256 of a token, hex-encoded.

    SHA-256 rather than Argon2 here is the correct choice and not a shortcut: the
    input already has 384 bits of entropy from a CSPRNG, so there is nothing to
    brute-force, and verification must be fast because it runs on every refresh.
    Argon2 is reserved for low-entropy human passwords.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def tokens_match(token: str, stored_hash: str) -> bool:
    """Constant-time comparison of a presented token against its stored hash."""
    presented = hash_token(token)
    return secrets.compare_digest(presented, stored_hash)


def encode_access_token(
    *,
    secret_key: str,
    algorithm: str,
    subject: uuid.UUID,
    tenant_id: uuid.UUID,
    session_id: uuid.UUID | None,
    lifetime: timedelta,
    extra_claims: dict[str, Any] | None = None,
) -> tuple[str, Any]:
    """
    Sign an access token, returning ``(token, expires_at)``.

    The expiry is returned as well because the caller stores it on the response
    and on the session row; recomputing it from the token would duplicate the
    clock arithmetic in two places that could then disagree.
    """
    issued_at = utc_now()
    expires_at = issued_at + lifetime
    claims: dict[str, Any] = {
        "sub": str(subject),
        "tid": str(tenant_id),
        "typ": ACCESS_TOKEN_TYPE,
        "iat": int(issued_at.timestamp()),
        "exp": int(expires_at.timestamp()),
        "jti": uuid.uuid4().hex,
    }
    if session_id is not None:
        claims["sid"] = str(session_id)
    if extra_claims:
        claims.update(extra_claims)
    token = jwt.encode(claims, secret_key, algorithm=algorithm)
    return token, expires_at


def decode_access_token(
    token: str,
    *,
    secret_key: str,
    algorithm: str,
    expected_type: str = ACCESS_TOKEN_TYPE,
) -> TokenClaims:
    """
    Verify and decode an access token.

    Every failure mode maps to a distinct, honest error rather than a generic
    401: an expired token tells the client to refresh, a tampered or wrongly
    typed token tells it to re-authenticate. Collapsing them would make the
    frontend retry a credential that can never work.
    """
    try:
        payload = jwt.decode(
            token,
            secret_key,
            algorithms=[algorithm],
            options={"require": ["exp", "iat", "sub", "tid", "typ"]},
        )
    except jwt.ExpiredSignatureError as exc:
        raise AuthenticationError(
            code=ErrorCode.TOKEN_EXPIRED,
            message="Access token has expired. Refresh it and retry.",
        ) from exc
    except InvalidTokenError as exc:
        # The library's message can include token fragments; it is not forwarded.
        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID,
            message="Access token is not valid.",
        ) from exc

    token_type = payload.get("typ")
    if token_type != expected_type:
        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID,
            message=f"Expected a {expected_type} token.",
        )

    try:
        subject = uuid.UUID(str(payload["sub"]))
        tenant_id = uuid.UUID(str(payload["tid"]))
        raw_session = payload.get("sid")
        session_id = uuid.UUID(str(raw_session)) if raw_session else None
    except (KeyError, ValueError) as exc:
        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID,
            message="Access token is not valid.",
        ) from exc

    from datetime import UTC
    from datetime import datetime as _datetime

    return TokenClaims(
        subject=subject,
        tenant_id=tenant_id,
        session_id=session_id,
        issued_at=_datetime.fromtimestamp(int(payload["iat"]), tz=UTC),
        expires_at=_datetime.fromtimestamp(int(payload["exp"]), tz=UTC),
        token_type=str(token_type),
    )
