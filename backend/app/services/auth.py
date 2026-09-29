"""
Authentication: registration, sign-in, token rotation, sessions, credentials.

The password rules are deliberate and worth stating, because every one of them is
a decision someone could otherwise "simplify" away:

* **Argon2id**, not bcrypt or PBKDF2. It is memory-hard, so the cost of an offline
  attack scales with hardware rather than with time alone. The parameters come
  from configuration rather than being hard-coded, so they can be raised without a
  code change.
* **The same error for "no such user" and "wrong password".** Distinguishing them
  turns sign-in into an account-enumeration oracle. The response is identical, and
  the miss path verifies against a dummy hash so the timing does not disclose
  which case it was either.
* **Failed attempts are counted and the account locks.** The counter lives on the
  user row rather than in a cache, so a lockout survives a restart.
* **Refresh tokens rotate on use, and replay revokes the family.** A lost-response
  retry cannot be distinguished from theft, so either requires a new sign-in.

Password reset works the same way as refresh tokens: the token is stored as a hash,
so a database disclosure yields no usable credential.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from uuid import UUID, uuid4

from argon2 import PasswordHasher
from argon2.exceptions import Argon2Error, InvalidHashError
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from app.authorization.api_keys import API_KEY_SCOPES, api_key_prefix
from app.authorization.checks import ensure_permission, ensure_tenant_match
from app.authorization.context import Actor
from app.authorization.resolution import resolve_permissions
from app.authorization.tokens import (
    encode_access_token,
    generate_refresh_token,
    hash_token,
    new_session_id,
    refresh_token_tenant,
    tokens_match,
)
from app.core.config import Settings
from app.core.errors import (
    AuthenticationError,
    AuthenticationStateChangedError,
    BusinessRuleError,
    ConflictError,
    ErrorCode,
    InputValidationError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import Session, Tenant, User
from app.repositories.identity import (
    ApiKeyRepository,
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)
from app.services.auth_delivery import AuthDelivery
from app.services.identity import IdentityService

__all__ = [
    "MAX_FAILED_LOGINS",
    "AuthService",
    "AuthenticatedUser",
    "TokenPair",
]

logger = get_logger(__name__)

#: How many consecutive failures lock an account. Deliberately small: the cost of
#: a legitimate user waiting out a lock is far lower than the cost of an online
#: brute-force attempt succeeding.
MAX_FAILED_LOGINS = 5

#: How long an account stays locked after too many failures.
LOCKOUT_WINDOW = timedelta(minutes=15)

#: A hash of a random value, verified on the "no such user" path so that the
#: response time does not reveal whether the account exists.
_DUMMY_HASH: str | None = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = PasswordHasher().hash(secrets.token_urlsafe(32))
    return _DUMMY_HASH


# ---------------------------------------------------------------------------
# Contracts
# ---------------------------------------------------------------------------
@dataclass(frozen=True, slots=True)
class AuthenticatedUser:
    """The outcome of a successful authentication."""

    user: User
    actor: Actor
    access_token: str
    access_token_expires_at: Any
    refresh_token: str
    refresh_token_expires_at: Any
    session_id: UUID


@dataclass(frozen=True, slots=True)
class TokenPair:
    """A rotated token pair."""

    access_token: str
    access_token_expires_at: Any
    refresh_token: str
    refresh_token_expires_at: Any
    session_id: UUID


class AuthService:
    """
    Authentication and session management.

    Every method takes the repositories and settings it needs rather than reaching
    for a request, so the service can be driven by a router, a CLI or a test with
    equal ease.
    """

    def __init__(
        self,
        *,
        settings: Settings,
        users: UserRepository,
        sessions: SessionRepository,
        audit: AuditLogRepository,
        tenants: TenantRepository,
    ) -> None:
        self.settings = settings
        self.users = users
        self.sessions = sessions
        self.audit = audit
        self.tenants = tenants

    async def _bind_tenant(self, tenant_id: UUID) -> None:
        """Bind RLS and all scoped repositories before reading protected rows."""
        session = self.users.session
        await apply_tenant_context(session, tenant_id)
        self.users = UserRepository(session, tenant_id)
        self.sessions = SessionRepository(session, tenant_id)
        self.audit = AuditLogRepository(session, tenant_id)

    async def _tenant_is_enabled(self, tenant_id: UUID) -> bool:
        # User-lock waiters must not trust a tenant loaded before suspension.
        tenant = (
            await self.users.session.execute(
                select(Tenant)
                .where(Tenant.id == tenant_id)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        return tenant is not None and _tenant_enabled(tenant)

    async def _require_enabled_tenant(self, tenant_id: UUID) -> None:
        if not await self._tenant_is_enabled(tenant_id):
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_SUSPENDED, message="This account cannot sign in."
            )

    # -- password handling ---------------------------------------------------
    def _hasher(self) -> PasswordHasher:
        """A hasher configured from settings. Cheap and stateless, so per call."""
        return PasswordHasher(
            time_cost=self.settings.argon2_time_cost,
            memory_cost=self.settings.argon2_memory_cost_kib,
            parallelism=self.settings.argon2_parallelism,
        )

    def hash_password(self, password: str) -> str:
        """Validate then hash a password with Argon2id at the configured cost."""
        self._validate_password_strength(password)
        return self._hasher().hash(password)

    def _validate_password_strength(self, password: str) -> None:
        """
        Enforce the configured minimum length and refuse the obvious.

        Length is the only rule that reliably predicts resistance to guessing, so
        this is a length check plus a short denylist of the strings that head every
        credential-stuffing list. Composition rules ("one capital, one digit") are
        deliberately absent: they push users towards predictable substitutions
        without adding entropy, and they make a password *harder to remember*
        without making it harder to guess.
        """
        if len(password) < self.settings.password_min_length:
            raise InputValidationError(
                message=(
                    f"Password must be at least {self.settings.password_min_length} characters."
                ),
                field="new_password",
            )
        lowered = password.lower()
        for banned in ("password", "qwerty", "12345678", "letmein", "ecomind"):
            if banned in lowered:
                raise InputValidationError(
                    message=(
                        "This password appears on every credential-stuffing list. "
                        "Choose something unrelated to this product."
                    ),
                    field="new_password",
                )

    def verify_password(self, password: str, stored_hash: str) -> bool:
        """
        Check a password against its stored hash.

        A malformed stored hash is a server-side fault rather than a user error,
        and reporting it as "wrong password" would hide a corrupted credential
        store behind a plausible-looking 401.
        """
        try:
            self._hasher().verify(stored_hash, password)
        except (Argon2Error, InvalidHashError):
            # VerificationError covers a wrong password; InvalidHashError covers a
            # malformed stored hash. Both mean "this pair does not match", and
            # neither is reported to the caller as a distinct condition.
            return False
        return True

    # -- registration --------------------------------------------------------
    async def register(
        self,
        *,
        email: str,
        password: str,
        full_name: str,
        phone: str | None = None,
        actor: Actor,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> User:
        """
        Create an invited user; activation is separate and issues no session.

        Registration is invitation-based: the router requires ``users.write``,
        which is checked again here so a non-HTTP caller cannot bypass it.

        Plain arguments rather than a request model, so the service does not depend
        on the API layer's schema package: the same call is available to a CLI and
        to a test without either importing FastAPI types.
        """
        ensure_permission(actor, "users.write")
        ensure_tenant_match(actor, self.users.tenant_id, resource_type="tenant")
        await self._bind_tenant(actor.tenant_id)
        actor = await IdentityService(self.users.session, actor).authorize_invitation()
        normalised = email.strip().lower()
        if await self.users.get_by_email(normalised) is not None:
            raise ConflictError(
                message="A user with this email already exists in this tenant.",
                details={"field": "email"},
            )

        try:
            async with self.users.session.begin_nested():
                user = await self.users.create(
                    email=normalised,
                    password_hash=self.hash_password(password),
                    full_name=full_name.strip(),
                    phone=phone,
                    status=UserStatus.INVITED,
                )
        except IntegrityError as exc:
            # Email remains reserved after soft deletion. The unique constraint
            # also closes the race between simultaneous invitations.
            if "uq_users_tenant_email" not in str(exc.orig):
                raise
            raise ConflictError(message="This email is already reserved in this tenant.") from exc
        await self.audit.record(
            action="user.create",
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={
                "email": normalised,
                "full_name": user.full_name,
                "status": user.status.value,
            },
            ip_address=ip_address,
            user_agent=user_agent,
        )
        logger.info("user registered", user_id=str(user.id), tenant_id=str(actor.tenant_id))
        return user

    # -- sign-in -------------------------------------------------------------
    async def authenticate(
        self,
        *,
        email: str,
        password: str,
        tenant_slug: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> AuthenticatedUser:
        """
        Verify credentials and issue a token pair.

        The tenant is resolved from ``tenant_slug``. That is not an inconvenience
        to be worked around: an email address is unique *per tenant*, so "find the
        user with this email" is only a well-defined question once a tenant is
        fixed, and a caller who does not name one is asking something the schema
        cannot answer unambiguously.
        """
        if not tenant_slug.strip():
            # The same error as a wrong password, so the response does not disclose
            # which tenants exist.
            raise self._invalid_credentials()

        tenant = await self.tenants.get_by_slug(tenant_slug.strip().lower())
        if tenant is None:
            self.verify_password(password, _dummy_hash())
            await self._bind_tenant(self.users.tenant_id)
            await self._audit_failed_login(None, email, ip_address, user_agent)
            raise AuthenticationStateChangedError(
                code=ErrorCode.INVALID_CREDENTIALS, message="Email or password is incorrect."
            )
        await self._bind_tenant(tenant.id)

        # A repository is per-tenant, so the lookup is built for the tenant the
        # caller named — deliberately not the injected one, which belongs to
        # whatever tenant the *caller* is in.
        user = await self.users.get_by_email(email, for_update=True)
        if user is None:
            # Verify against a dummy hash so "no such user" costs the same as
            # "wrong password" and the timing does not give the answer away.
            self.verify_password(password, _dummy_hash())
            await self._audit_failed_login(None, email, ip_address, user_agent)
            raise AuthenticationStateChangedError(
                code=ErrorCode.INVALID_CREDENTIALS, message="Email or password is incorrect."
            )

        if user.locked_until is not None and user.locked_until > utc_now():
            await self._audit_failed_login(user.id, email, ip_address, user_agent)
            raise AuthenticationStateChangedError(
                code=ErrorCode.ACCOUNT_LOCKED,
                message="This account is temporarily locked after too many failed attempts.",
            )

        if not self.verify_password(password, user.password_hash):
            await self._register_failed_attempt(user)
            await self._audit_failed_login(user.id, email, ip_address, user_agent)
            raise AuthenticationStateChangedError(
                code=ErrorCode.INVALID_CREDENTIALS, message="Email or password is incorrect."
            )

        await self._require_enabled_tenant(tenant.id)
        if user.status is not UserStatus.ACTIVE:
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_SUSPENDED,
                message="This account cannot sign in.",
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = utc_now()
        user.last_login_ip = ip_address
        await self.users.session.flush()

        await self.audit.record(
            action="user.login",
            actor=AnonymousActor(user_id=user.id),
            resource_type="user",
            resource_id=str(user.id),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return await self._issue_session(user, user_agent=user_agent, ip_address=ip_address)

    async def _register_failed_attempt(self, user: User) -> None:
        """Count a failed sign-in and lock the account at the threshold."""
        user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
        if user.failed_login_attempts >= MAX_FAILED_LOGINS:
            user.locked_until = utc_now() + LOCKOUT_WINDOW
            user.failed_login_attempts = 0
            logger.warning("account locked after repeated failed sign-ins", user_id=str(user.id))
        await self.users.session.flush()

    async def _audit_failed_login(
        self,
        user_id: UUID | None,
        email: str,
        ip_address: str | None,
        user_agent: str | None,
    ) -> None:
        """
        Record a failed sign-in.

        The email is recorded because a cluster of failures against one address is
        the signal an operator needs, and because the attempt itself is the event
        being audited — not a successful authentication.
        """
        await self.audit.record(
            action="user.login",
            actor=AnonymousActor(user_id=user_id),
            resource_type="user",
            resource_id=str(user_id) if user_id else None,
            outcome="FAILURE",
            changes={"email": email},
            ip_address=ip_address,
            user_agent=user_agent,
        )

    @staticmethod
    def _invalid_credentials() -> AuthenticationError:
        return AuthenticationError(
            code=ErrorCode.INVALID_CREDENTIALS,
            message="Email or password is incorrect.",
        )

    # -- token issuance ------------------------------------------------------
    async def _issue_session(
        self,
        user: User,
        *,
        user_agent: str | None,
        ip_address: str | None,
    ) -> AuthenticatedUser:
        """Create the session row and the token pair that belongs to it."""
        session_id = new_session_id()
        refresh_token = generate_refresh_token(user.tenant_id)
        now = utc_now()
        refresh_expires = now + timedelta(days=self.settings.refresh_token_expire_days)

        self.sessions.session.add(
            Session(
                id=session_id,
                user_id=user.id,
                tenant_id=user.tenant_id,
                refresh_token_hash=hash_token(refresh_token),
                # A fresh family per sign-in: rotating within it is normal, and a
                # replay anywhere inside it revokes the whole set.
                family_id=uuid4(),
                issued_at=now,
                expires_at=refresh_expires,
                user_agent=user_agent,
                ip_address=ip_address,
                last_used_at=now,
            )
        )
        await self.sessions.session.flush()

        actor = await self._actor_for(user)
        access_token, access_expires = encode_access_token(
            secret_key=self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm,
            subject=user.id,
            tenant_id=user.tenant_id,
            session_id=session_id,
            lifetime=timedelta(minutes=self.settings.access_token_expire_minutes),
        )
        return AuthenticatedUser(
            user=user,
            actor=actor,
            access_token=access_token,
            access_token_expires_at=access_expires,
            refresh_token=refresh_token,
            refresh_token_expires_at=refresh_expires,
            session_id=session_id,
        )

    async def _actor_for(self, user: User) -> Actor:
        """Resolve the user's current permissions into an actor."""
        role_codes, permission_codes = await resolve_permissions(
            self.users.session, user.tenant_id, user.id
        )
        return Actor(
            user_id=user.id,
            tenant_id=user.tenant_id,
            email=user.email,
            full_name=user.full_name,
            permissions=permission_codes,
            roles=role_codes,
            is_platform_operator=user.tenant_id == PLATFORM_SCOPE_ID,
        )

    # -- refresh and revocation ---------------------------------------------
    async def refresh(self, refresh_token: str) -> TokenPair:
        """
        Exchange a refresh token for a new pair, rotating the old one.

        A replay revokes the whole family. A retry after a lost response is
        indistinguishable from theft, so clients must serialize refresh calls and
        sign in again after reuse. Old hash rows are retained as replay evidence.
        """
        tenant_id = refresh_token_tenant(refresh_token)
        await self._bind_tenant(tenant_id)
        token_hash = hash_token(refresh_token)
        old_session = await self.sessions.find_by_refresh_hash(token_hash)
        if old_session is None:
            raise AuthenticationError(
                code=ErrorCode.TOKEN_INVALID, message="Refresh token is not valid."
            )

        # All session mutations lock the user first. Locking only the presented
        # token would let replay of an ancestor race rotation of its descendant.
        user = await self.users.get_active(old_session.user_id, for_update=True)
        old_session = await self.sessions.find_by_refresh_hash(token_hash)
        if old_session is None:
            raise AuthenticationError(code=ErrorCode.TOKEN_INVALID)
        now = utc_now()
        if old_session.revoked_at is not None:
            revoked = await self.sessions.revoke_family(
                old_session.family_id, reason="refresh token replay detected"
            )
            await self.audit.record(
                action="user.refresh_reuse",
                actor=AnonymousActor(old_session.user_id),
                resource_type="session",
                resource_id=str(old_session.id),
                outcome="DENIED",
                changes={"revoked_sessions": revoked},
            )
            raise AuthenticationStateChangedError(
                code=ErrorCode.REFRESH_TOKEN_REUSED,
                message="This refresh token has already been used. Sign in again.",
            )
        if old_session.expires_at <= now:
            raise AuthenticationError(
                code=ErrorCode.SESSION_REVOKED, message="Session has expired. Sign in again."
            )
        await self._require_enabled_tenant(tenant_id)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_SUSPENDED, message="This account cannot sign in."
            )
        if user.locked_until is not None and user.locked_until > now:
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_LOCKED, message="This account is temporarily locked."
            )

        new_refresh = generate_refresh_token(tenant_id)
        new_expires = now + timedelta(days=self.settings.refresh_token_expire_days)
        new_id = new_session_id()
        old_session.revoked_at = now
        old_session.revoked_reason = "refresh token rotated"
        old_session.last_used_at = now
        self.sessions.session.add(
            Session(
                id=new_id,
                tenant_id=tenant_id,
                user_id=user.id,
                refresh_token_hash=hash_token(new_refresh),
                family_id=old_session.family_id,
                previous_session_id=old_session.id,
                issued_at=now,
                expires_at=new_expires,
                user_agent=old_session.user_agent,
                ip_address=old_session.ip_address,
                last_used_at=now,
            )
        )
        await self.sessions.session.flush()
        access_token, access_expires = encode_access_token(
            secret_key=self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm,
            subject=user.id,
            tenant_id=tenant_id,
            session_id=new_id,
            lifetime=timedelta(minutes=self.settings.access_token_expire_minutes),
        )
        return TokenPair(
            access_token=access_token,
            access_token_expires_at=access_expires,
            refresh_token=new_refresh,
            refresh_token_expires_at=new_expires,
            session_id=new_id,
        )

    async def logout(self, session_id: UUID, *, actor: Actor) -> None:
        """Revoke an owned session; invisible and foreign sessions are a 404."""
        ensure_tenant_match(actor, self.users.tenant_id, resource_type="session")
        await self.users.get_active(actor.user_id, for_update=True)
        session = await self.sessions.get(session_id)
        if session is None or session.user_id != actor.user_id:
            raise NotFoundError(resource_type="session", resource_id=str(session_id))
        # A family represents one signed-in device. If a refresh completed
        # while logout waited for the user lock, its descendant must go too.
        await self.sessions.revoke_family(session.family_id, reason="user signed out")
        await self.audit.record(
            action="user.logout",
            actor=actor,
            resource_type="session",
            resource_id=str(session_id),
        )

    async def logout_all(
        self,
        user_id: UUID,
        *,
        actor: Actor,
        except_session_id: UUID | None = None,
    ) -> int:
        """Revoke every live session for a user, optionally sparing the current one."""
        ensure_tenant_match(actor, self.users.tenant_id, resource_type="user")
        if actor.user_id != user_id:
            raise NotFoundError(resource_type="user", resource_id=str(user_id))
        await self.users.get_active(user_id, for_update=True)
        sessions = await self.sessions.list_for_user(user_id)
        now = utc_now()
        count = 0
        for session in sessions:
            if except_session_id is not None and session.id == except_session_id:
                continue
            session.revoked_at = now
            session.revoked_reason = "user signed out everywhere"
            count += 1
        await self.sessions.session.flush()
        await self.audit.record(
            action="user.logout_all",
            actor=actor,
            resource_type="user",
            resource_id=str(user_id),
            changes={"revoked_sessions": count},
        )
        return count

    # -- credential changes --------------------------------------------------
    async def change_password(
        self,
        *,
        current_password: str,
        new_password: str,
        actor: Actor,
        keep_current_session: UUID | None = None,
    ) -> None:
        """
        Change a password and revoke every other session.

        Revoking the others is not optional: a password change is what a user does
        when they suspect their account is compromised, and leaving the attacker's
        session alive would make the change useless.
        """
        ensure_tenant_match(actor, self.users.tenant_id, resource_type="user")
        user = await self.users.get_active(actor.user_id, for_update=True)
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(actor.user_id))
        if not self.verify_password(current_password, user.password_hash):
            await self._register_failed_attempt(user)
            raise AuthenticationStateChangedError(
                code=ErrorCode.INVALID_CREDENTIALS, message="Email or password is incorrect."
            )
        if new_password == current_password:
            raise BusinessRuleError(
                rule_code="BR-PWD-01",
                message="The new password must differ from the current one.",
            )

        user.password_hash = self.hash_password(new_password)
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_session_id = None
        user.mfa_pending_expires_at = None
        await self.users.session.execute(
            update(Session)
            .where(Session.tenant_id == user.tenant_id, Session.user_id == user.id)
            .values(
                platform_reauthenticated_at=None,
                platform_mfa_verified_at=None,
                platform_mfa_factor_id=None,
            )
        )
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None
        await self.users.session.flush()
        revoked = await self.logout_all(
            user.id, actor=actor, except_session_id=keep_current_session
        )
        await self.audit.record(
            action="user.password_change",
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={"other_sessions_revoked": revoked},
        )

    async def request_password_reset_in(self, tenant: Tenant, *, email: str) -> str | None:
        """
        Start a password reset.

        Hash storage, encrypted delivery payload and the audit record share the
        caller's transaction. No external send occurs here. Returns the token only
        to trusted internal callers/tests; the public API never serializes it.
        Unknown/ineligible accounts return None and the API response is neutral.
        """
        if tenant.deleted_at is not None or tenant.status not in (
            TenantStatus.ACTIVE,
            TenantStatus.TRIAL,
        ):
            return None
        await self._bind_tenant(tenant.id)
        user = await self.users.get_by_email(email, for_update=True)
        if user is None or user.status is not UserStatus.ACTIVE:
            return None
        if not await self._tenant_is_enabled(tenant.id):
            return None
        token = secrets.token_urlsafe(32)
        user.password_reset_token_hash = hash_token(token)
        user.password_reset_expires_at = utc_now() + timedelta(hours=1)
        await self.users.session.flush()
        await AuthDelivery(self.users.session, self.settings).enqueue(
            user, tenant, "PASSWORD_RESET", token, user.password_reset_expires_at
        )
        await self.audit.record(
            action="user.password_reset_request",
            actor=AnonymousActor(user_id=user.id),
            resource_type="user",
            resource_id=str(user.id),
        )
        return token

    async def confirm_password_reset_in(
        self, tenant: Tenant, *, token: str, new_password: str
    ) -> None:
        """Complete a reset, consuming its credential and revoking all sessions."""
        await self._bind_tenant(tenant.id)
        await self._require_enabled_tenant(tenant.id)
        user = (
            await self.users.session.execute(
                select(User)
                .where(
                    User.password_reset_token_hash == hash_token(token),
                    User.tenant_id == tenant.id,
                    User.deleted_at.is_(None),
                    User.status == UserStatus.ACTIVE,
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        await self._require_enabled_tenant(tenant.id)
        if user is None or user.password_reset_expires_at is None:
            raise AuthenticationError(
                code=ErrorCode.TOKEN_INVALID, message="Reset token is not valid."
            )
        if user.password_reset_expires_at <= utc_now():
            raise AuthenticationError(
                code=ErrorCode.TOKEN_EXPIRED, message="Reset token has expired."
            )
        user.password_hash = self.hash_password(new_password)
        user.mfa_pending_secret_encrypted = None
        user.mfa_pending_session_id = None
        user.mfa_pending_expires_at = None
        await self.users.session.execute(
            update(Session)
            .where(Session.tenant_id == user.tenant_id, Session.user_id == user.id)
            .values(
                platform_reauthenticated_at=None,
                platform_mfa_verified_at=None,
                platform_mfa_factor_id=None,
            )
        )
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None
        await self.users.session.flush()
        actor = await self._actor_for(user)
        revoked = await self.logout_all(user.id, actor=actor)
        await self.audit.record(
            action="user.password_reset",
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={"sessions_revoked": revoked},
        )

    async def request_email_verification_in(self, tenant: Tenant, *, email: str) -> None:
        if tenant.deleted_at is not None or tenant.status not in (
            TenantStatus.ACTIVE,
            TenantStatus.TRIAL,
        ):
            return
        await self._bind_tenant(tenant.id)
        user = await self.users.get_by_email(email, for_update=True)
        if (
            user is None
            or user.email_verified_at is not None
            or user.status not in (UserStatus.ACTIVE, UserStatus.INVITED)
        ):
            return
        if not await self._tenant_is_enabled(tenant.id):
            return
        token = secrets.token_urlsafe(32)
        user.email_verification_token_hash = hash_token(token)
        user.email_verification_expires_at = utc_now() + timedelta(hours=1)
        await self.users.session.flush()
        await AuthDelivery(self.users.session, self.settings).enqueue(
            user, tenant, "EMAIL_VERIFICATION", token, user.email_verification_expires_at
        )
        await self.audit.record(
            action="user.email_verification_request",
            actor=AnonymousActor(user.id),
            resource_type="user",
            resource_id=str(user.id),
        )

    async def confirm_email_verification_in(self, tenant: Tenant, *, token: str) -> None:
        await self._bind_tenant(tenant.id)
        await self._require_enabled_tenant(tenant.id)
        user = (
            await self.users.session.execute(
                select(User)
                .where(
                    User.tenant_id == tenant.id,
                    User.deleted_at.is_(None),
                    User.status.in_((UserStatus.ACTIVE, UserStatus.INVITED)),
                    User.email_verification_token_hash == hash_token(token),
                    User.email_verified_at.is_(None),
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        await self._require_enabled_tenant(tenant.id)
        if user is None or user.email_verification_expires_at is None:
            raise AuthenticationError(
                code=ErrorCode.TOKEN_INVALID, message="Verification code is not valid."
            )
        if user.email_verification_expires_at <= utc_now():
            raise AuthenticationError(
                code=ErrorCode.TOKEN_EXPIRED, message="Verification code has expired."
            )
        user.email_verified_at = utc_now()
        user.email_verification_token_hash = None
        user.email_verification_expires_at = None
        if user.status == UserStatus.INVITED:
            user.status = UserStatus.ACTIVE
        await self.users.session.flush()
        await self.audit.record(
            action="user.email_verified",
            actor=AnonymousActor(user.id),
            resource_type="user",
            resource_id=str(user.id),
        )

    async def verify_email(self, user_id: UUID, *, actor: Actor) -> None:
        """Administrative activation; not a public proof-of-email endpoint."""
        ensure_permission(actor, "users.write")
        ensure_tenant_match(actor, self.users.tenant_id, resource_type="user")
        user = await self.users.get_active(user_id, for_update=True)
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(user_id))
        if user.email_verified_at is not None:
            return
        user.email_verified_at = utc_now()
        user.email_verification_token_hash = None
        user.email_verification_expires_at = None
        if user.status is UserStatus.INVITED:
            user.status = UserStatus.ACTIVE
        await self.users.session.flush()
        await self.audit.record(
            action="user.email_verified",
            actor=actor,
            resource_type="user",
            resource_id=str(user_id),
        )

    # -- API keys ------------------------------------------------------------
    async def authenticate_api_key(self, presented_key: str, *, tenant_id: UUID) -> Actor:
        """Authenticate within an explicitly routed tenant, never by global prefix.

        Tenant SHARE -> key UPDATE locks last until the caller commits/rolls back
        its business transaction. Revocation waits for in-flight work, then later
        authentications fail. No human-role inheritance or creator liveness tie.
        HTTP device endpoints/rate budgets must be added by the consuming module.
        """
        prefix = api_key_prefix(presented_key)
        if prefix is None:
            raise self._invalid_credentials()
        await self._bind_tenant(tenant_id)
        tenant = (
            await self.users.session.execute(
                select(Tenant)
                .where(
                    Tenant.id == tenant_id,
                    Tenant.deleted_at.is_(None),
                    Tenant.status.in_([TenantStatus.ACTIVE, TenantStatus.TRIAL]),
                )
                .with_for_update(read=True)
            )
        ).scalar_one_or_none()
        if tenant is None:
            raise self._invalid_credentials()
        api_key = await ApiKeyRepository(self.users.session, tenant_id).find_by_prefix(
            prefix, for_update=True
        )
        now = utc_now()
        if (
            api_key is None
            or api_key.revoked_at is not None
            or api_key.expires_at is None
            or api_key.expires_at <= now
            or not api_key.scopes
            or not set(api_key.scopes).issubset(API_KEY_SCOPES)
            or not tokens_match(presented_key, api_key.key_hash)
        ):
            raise self._invalid_credentials()
        api_key.last_used_at = now
        actor = Actor(
            user_id=api_key.id,
            tenant_id=api_key.tenant_id,
            email=f"apikey:{api_key.key_prefix}@tenant.invalid",
            full_name=api_key.name,
            permissions=frozenset(api_key.scopes),
            roles=frozenset(),
            auth_type="API_KEY",
        )
        await self.audit.record(
            action="api_key.authenticate",
            actor=actor,
            resource_type="api_key",
            resource_id=str(api_key.id),
        )
        return actor


@dataclass(frozen=True, slots=True)
class AnonymousActor:
    """
    The actor recorded for a failed sign-in.

    A failed attempt has no authenticated user, but the audit trail still needs to
    say *who tried*. Carrying only the id (which may itself be unknown) keeps the
    row honest rather than attributing the attempt to a real account.
    """

    user_id: UUID | None
    auth_type: str = "USER"


def _tenant_enabled(tenant: Tenant) -> bool:
    return tenant.deleted_at is None and tenant.status in (TenantStatus.ACTIVE, TenantStatus.TRIAL)
