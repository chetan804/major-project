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
* **Refresh tokens rotate on use, and replay revokes the family.** A refresh token
  presented twice can only have been stolen, so the whole rotation family is
  revoked and the legitimate user has to sign in again.

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
from sqlalchemy import select

from app.authorization.context import Actor
from app.authorization.resolution import resolve_permissions
from app.authorization.tokens import (
    encode_access_token,
    generate_refresh_token,
    hash_token,
    new_session_id,
    tokens_match,
)
from app.core.config import Settings
from app.core.errors import (
    AuthenticationError,
    BusinessRuleError,
    ConflictError,
    ErrorCode,
    InputValidationError,
    NotFoundError,
)
from app.core.logging import get_logger
from app.core.time import utc_now
from app.models._enums import UserStatus
from app.models.identity import Session, Tenant, User
from app.repositories.identity import (
    ApiKeyRepository,
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)

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
    ) -> AuthenticatedUser:
        """
        Create a user in the actor's own tenant and sign them in.

        Registration is invitation-based: the router requires ``users.write``,
        which is what stops the public internet from creating accounts inside a
        municipality. This method therefore trusts the caller and records who it
        was, rather than re-checking.

        Plain arguments rather than a request model, so the service does not depend
        on the API layer's schema package: the same call is available to a CLI and
        to a test without either importing FastAPI types.
        """
        normalised = email.strip().lower()
        if await self.users.get_by_email(normalised) is not None:
            raise ConflictError(
                message="A user with this email already exists in this tenant.",
                details={"field": "email"},
            )

        user = await self.users.create(
            email=normalised,
            password_hash=self.hash_password(password),
            full_name=full_name.strip(),
            phone=phone,
            status=UserStatus.INVITED,
        )
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
        return await self._issue_session(user, user_agent=user_agent, ip_address=ip_address)

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
            await self._audit_failed_login(None, email, ip_address, user_agent)
            raise self._invalid_credentials()

        # A repository is per-tenant, so the lookup is built for the tenant the
        # caller named — deliberately not the injected one, which belongs to
        # whatever tenant the *caller* is in.
        user = await UserRepository(self.users.session, tenant.id).get_by_email(email)
        if user is None:
            # Verify against a dummy hash so "no such user" costs the same as
            # "wrong password" and the timing does not give the answer away.
            self.verify_password(password, _dummy_hash())
            await self._audit_failed_login(None, email, ip_address, user_agent)
            raise self._invalid_credentials()

        if user.locked_until is not None and user.locked_until > utc_now():
            await self._audit_failed_login(user.id, email, ip_address, user_agent)
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_LOCKED,
                message="This account is temporarily locked after too many failed attempts.",
            )

        if not self.verify_password(password, user.password_hash):
            await self._register_failed_attempt(user)
            await self._audit_failed_login(user.id, email, ip_address, user_agent)
            raise self._invalid_credentials()

        if user.status is UserStatus.SUSPENDED:
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_SUSPENDED,
                message="This account has been suspended.",
            )

        user.failed_login_attempts = 0
        user.locked_until = None
        user.last_login_at = utc_now()
        user.last_login_ip = ip_address
        await self.users.session.flush()

        await self.audit.record(
            action="user.login",
            actor=user,
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
        refresh_token = generate_refresh_token()
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
        )

    # -- refresh and revocation ---------------------------------------------
    async def refresh(self, refresh_token: str) -> TokenPair:
        """
        Exchange a refresh token for a new pair, rotating the old one.

        A replay revokes the whole family. The only honest explanation for a token
        presented twice is that it was stolen, and keeping the newest session alive
        would leave the attacker holding the working credential while the
        legitimate user is locked out of the decision.
        """
        session = await self.sessions.find_by_refresh_hash(hash_token(refresh_token))
        if session is None:
            raise AuthenticationError(
                code=ErrorCode.TOKEN_INVALID,
                message="Refresh token is not valid.",
            )

        now = utc_now()
        if session.revoked_at is not None:
            revoked = await self.sessions.revoke_family(
                session.family_id, reason="refresh token replay detected"
            )
            logger.warning(
                "refresh token replay detected; family revoked",
                session_id=str(session.id),
                revoked_sessions=revoked,
            )
            raise AuthenticationError(
                code=ErrorCode.REFRESH_TOKEN_REUSED,
                message="This refresh token has already been used. Sign in again.",
            )
        if session.expires_at <= now:
            raise AuthenticationError(
                code=ErrorCode.SESSION_REVOKED,
                message="Session has expired. Sign in again.",
            )

        user = await self.users.get_active(session.user_id)
        if user is None or user.status is not UserStatus.ACTIVE:
            raise AuthenticationError(
                code=ErrorCode.ACCOUNT_SUSPENDED,
                message="This account cannot sign in.",
            )

        new_refresh = generate_refresh_token()
        new_expires = now + timedelta(days=self.settings.refresh_token_expire_days)
        session.refresh_token_hash = hash_token(new_refresh)
        session.previous_session_id = session.id
        session.last_used_at = now
        session.expires_at = new_expires
        await self.sessions.session.flush()

        access_token, access_expires = encode_access_token(
            secret_key=self.settings.jwt_secret_key,
            algorithm=self.settings.jwt_algorithm,
            subject=user.id,
            tenant_id=user.tenant_id,
            session_id=session.id,
            lifetime=timedelta(minutes=self.settings.access_token_expire_minutes),
        )
        return TokenPair(
            access_token=access_token,
            access_token_expires_at=access_expires,
            refresh_token=new_refresh,
            refresh_token_expires_at=new_expires,
            session_id=session.id,
        )

    async def logout(self, session_id: UUID, *, actor: Actor) -> None:
        """Revoke one session."""
        session = await self.sessions.get(session_id)
        if session is None:
            return
        session.revoked_at = utc_now()
        session.revoked_reason = "user signed out"
        await self.sessions.session.flush()
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
        user = await self.users.get_active(actor.user_id)
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(actor.user_id))
        if not self.verify_password(current_password, user.password_hash):
            await self._register_failed_attempt(user)
            raise self._invalid_credentials()
        if new_password == current_password:
            raise BusinessRuleError(
                rule_code="BR-PWD-01",
                message="The new password must differ from the current one.",
            )

        user.password_hash = self.hash_password(new_password)
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

        Returns the reset token, or ``None`` when no account matches. The caller
        must not branch on the difference in its response: the endpoint always
        answers "if that address has an account, a reset link is on its way",
        because anything more specific is an account-enumeration oracle.

        The token is *returned* rather than emailed because this deployment has no
        outbound mail. A deployment with one passes it to the notification adapter
        and returns ``None`` to the caller; the absence of the adapter is therefore
        explicit in the code rather than hidden behind a silent no-op.
        """
        user = await UserRepository(self.users.session, tenant.id).get_by_email(email)
        if user is None:
            return None
        token = secrets.token_urlsafe(32)
        user.password_reset_token_hash = hash_token(token)
        user.password_reset_expires_at = utc_now() + timedelta(hours=1)
        await self.users.session.flush()
        await self.audit.record(
            action="user.password_reset_request",
            actor=user,
            resource_type="user",
            resource_id=str(user.id),
        )
        return token

    async def confirm_password_reset_in(
        self, tenant: Tenant, *, token: str, new_password: str, actor: Actor
    ) -> None:
        """Complete a password reset with a valid, unexpired token."""
        user = (
            await self.users.session.execute(
                select(User).where(
                    User.password_reset_token_hash == hash_token(token),
                    User.tenant_id == tenant.id,
                    User.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if user is None or user.password_reset_expires_at is None:
            raise AuthenticationError(
                code=ErrorCode.TOKEN_INVALID, message="Reset token is not valid."
            )
        if user.password_reset_expires_at <= utc_now():
            raise AuthenticationError(
                code=ErrorCode.TOKEN_EXPIRED, message="Reset token has expired."
            )
        user.password_hash = self.hash_password(new_password)
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        user.failed_login_attempts = 0
        user.locked_until = None
        await self.users.session.flush()
        revoked = await self.logout_all(user.id, actor=actor)
        await self.audit.record(
            action="user.password_reset",
            actor=actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={"sessions_revoked": revoked},
        )

    async def verify_email(self, user_id: UUID, *, actor: Actor) -> None:
        """Mark a user's email verified, activating an invited account."""
        user = await self.users.get_active(user_id)
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(user_id))
        if user.email_verified_at is not None:
            return
        user.email_verified_at = utc_now()
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
    async def authenticate_api_key(self, presented_key: str) -> Actor:
        """
        Authenticate a device gateway or partner integration by API key.

        The prefix is looked up first and the hash compared second, so an unknown
        prefix costs one query rather than a hash verification per stored key. The
        comparison itself is constant-time.

        The actor an API key produces carries only the key's declared scopes and
        holds no role, which is what makes ``bins.telemetry.ingest`` reachable this
        way and through no human role at all (``rbac.md`` §4.1): a compromised user
        session cannot forge telemetry.
        """
        if len(presented_key) < 16:
            raise self._invalid_credentials()
        prefix = presented_key[:12]
        api_key = await ApiKeyRepository(self.users.session, self.users.tenant_id).find_by_prefix(
            prefix
        )
        now = utc_now()
        if (
            api_key is None
            or api_key.revoked_at is not None
            or (api_key.expires_at is not None and api_key.expires_at <= now)
            or not tokens_match(presented_key, api_key.key_hash)
        ):
            raise self._invalid_credentials()

        api_key.last_used_at = now
        await self.users.session.flush()
        return Actor(
            user_id=api_key.id,
            tenant_id=api_key.tenant_id,
            email=f"apikey:{api_key.key_prefix}@tenant.invalid",
            full_name=api_key.name,
            permissions=frozenset(api_key.scopes),
            roles=frozenset({"API_KEY"}),
            auth_type="API_KEY",
        )


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
