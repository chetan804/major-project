"""
Identity, tenancy and access-control schemas.

Note what is absent from every response model here: ``password_hash``,
``refresh_token_hash``, ``password_reset_token_hash``. They are not omitted by
convention — the models do not declare them, so there is no field name a future
contributor could add to accidentally expose one.

``tenant_slug`` appears on the sign-in and password-reset bodies for a structural
reason rather than a convenience one: an email address is unique *per tenant*, so
"the user with this email" is not a well-defined question until a tenant is named.
Row-level security enforces the same thing from the other side — a connection with
no tenant bound sees no user rows at all.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import Field

from app.api.schemas.common import ORMModel, RequestModel, Timestamped

__all__ = [
    "LoginRequest",
    "MeResponse",
    "PasswordChangeRequest",
    "PasswordResetConfirmRequest",
    "PasswordResetRequest",
    "ProfileUpdateRequest",
    "RefreshRequest",
    "SessionResponse",
    "TokenResponse",
    "UserCreateRequest",
    "UserResponse",
    "UserUpdateRequest",
]


class LoginRequest(RequestModel):
    """A sign-in attempt."""

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=128)
    tenant_slug: str = Field(min_length=1, max_length=120)


class RefreshRequest(RequestModel):
    """A token refresh."""

    refresh_token: str = Field(min_length=16, max_length=512)


class TokenResponse(ORMModel):
    """
    A token pair.

    ``expires_in`` is a number of seconds rather than an absolute timestamp, so a
    client with a skewed clock still schedules its refresh correctly.
    """

    access_token: str
    refresh_token: str
    token_type: str = "bearer"  # noqa: S105 - an OAuth2 scheme name, not a credential
    expires_in: int
    refresh_expires_in: int
    session_id: UUID


class MeResponse(Timestamped):
    """
    The authenticated caller, with their own permissions.

    The permissions are included so the interface can grey out what the caller
    cannot do without a round trip per control — and because the caller is entitled
    to know what their own roles grant.
    """

    id: UUID
    email: str
    full_name: str
    phone: str | None = None
    status: str
    email_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    preferred_timezone: str | None = None
    preferred_locale: str | None = None
    tenant_id: UUID
    roles: list[str] = Field(default_factory=list)
    permissions: list[str] = Field(default_factory=list)


class ProfileUpdateRequest(RequestModel):
    """A self-service profile update. Email and status are deliberately absent."""

    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=40)
    preferred_timezone: str | None = Field(default=None, max_length=64)
    preferred_locale: str | None = Field(default=None, max_length=16)


class PasswordChangeRequest(RequestModel):
    """A password change by the authenticated caller."""

    current_password: str = Field(min_length=1, max_length=128)
    new_password: str = Field(min_length=8, max_length=128)


class PasswordResetRequest(RequestModel):
    """A request to start a password reset."""

    email: str = Field(min_length=3, max_length=320)
    tenant_slug: str = Field(min_length=1, max_length=120)


class PasswordResetConfirmRequest(RequestModel):
    """A completed password reset."""

    token: str = Field(min_length=16, max_length=256)
    tenant_slug: str = Field(min_length=1, max_length=120)
    new_password: str = Field(min_length=8, max_length=128)


class SessionResponse(ORMModel):
    """One of the caller's sessions. The token itself is never returned."""

    id: UUID
    issued_at: datetime
    last_used_at: datetime | None = None
    expires_at: datetime
    revoked_at: datetime | None = None
    user_agent: str | None = None


class UserCreateRequest(RequestModel):
    """An invitation: an administrator creating a user in their own tenant."""

    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=200)
    phone: str | None = Field(default=None, max_length=40)


class UserUpdateRequest(RequestModel):
    """
    An administrative update of a user.

    ``PATCH`` semantics: only the fields present are changed. The email is absent
    because changing it is a separate, verified operation rather than a field edit.
    """

    full_name: str | None = Field(default=None, max_length=200)
    phone: str | None = Field(default=None, max_length=40)
    status: str | None = Field(default=None, max_length=32)
    preferred_timezone: str | None = Field(default=None, max_length=64)
    preferred_locale: str | None = Field(default=None, max_length=16)


class UserResponse(Timestamped):
    """A user as an administrator sees them. No credential material."""

    id: UUID
    email: str
    full_name: str
    phone: str | None = None
    status: str
    email_verified_at: datetime | None = None
    last_login_at: datetime | None = None
    roles: list[str] = Field(default_factory=list)
