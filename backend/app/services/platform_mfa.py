"""Platform TOTP enrollment and one-time recovery, never a password-only disable path."""

from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Literal
from urllib.parse import quote, urlencode
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import update

from app.authorization.tokens import hash_token, tokens_match
from app.authorization.totp import match_counter, new_seed
from app.core.config import Settings
from app.core.errors import (
    AuthenticationStateChangedError,
    ConflictError,
    DependencyUnavailableError,
    ErrorCode,
    InputValidationError,
    PermissionDeniedError,
)
from app.core.time import utc_now
from app.models.identity import Session, User
from app.repositories.identity import UserRepository
from app.services.platform_access import PlatformAccessService, auth_for, require_recent_step_up
from app.services.platform_access import mfa_enabled as enabled

SecondFactor = Literal["password+totp", "password+recovery_code"]


def cipher(settings: Settings) -> Fernet:
    try:
        if not settings.mfa_encryption_key or settings.mfa_key_reused():
            raise ValueError
        return Fernet(settings.mfa_encryption_key.encode())
    except (ValueError, TypeError) as exc:
        raise DependencyUnavailableError(
            "platform_mfa", message="Platform MFA encryption is unavailable."
        ) from exc


def encrypt_seed(settings: Settings, user: User, seed: str, factor_id: UUID) -> str:
    return (
        cipher(settings)
        .encrypt(
            json.dumps(
                {
                    "purpose": "platform_totp_v1",
                    "user": str(user.id),
                    "tenant": str(user.tenant_id),
                    "factor": str(factor_id),
                    "seed": seed,
                }
            ).encode()
        )
        .decode()
    )


def decrypt_seed(settings: Settings, user: User, ciphertext: str) -> tuple[str, UUID]:
    try:
        data = json.loads(cipher(settings).decrypt(ciphertext.encode()))
        if (
            data["purpose"] != "platform_totp_v1"
            or data["user"] != str(user.id)
            or data["tenant"] != str(user.tenant_id)
        ):
            raise ValueError
        if not isinstance(data["factor"], str):
            raise ValueError
        seed, factor = data["seed"], UUID(data["factor"])
        if not isinstance(seed, str) or not re.fullmatch(r"[A-Z2-7]{32}", seed):
            raise ValueError
        return seed, factor
    except (InvalidToken, ValueError, TypeError, KeyError) as exc:
        raise DependencyUnavailableError(
            "platform_mfa", message="Platform MFA material is unavailable."
        ) from exc


def clear_proof(live: Session) -> None:
    live.platform_reauthenticated_at = None
    live.platform_mfa_factor_id = None
    live.platform_mfa_verified_at = None


def clear_pending(user: User) -> None:
    user.mfa_pending_secret_encrypted = None
    user.mfa_pending_session_id = None
    user.mfa_pending_expires_at = None


def recovery_codes(user: User) -> list[str]:
    codes = ["rc1_" + secrets.token_urlsafe(24) for _ in range(10)]
    user.mfa_recovery_hashes = [hash_token(code) for code in codes]
    return codes


def consume_factor(
    settings: Settings, user: User, *, totp_code: str | None, recovery_code: str | None
) -> SecondFactor | None:
    if bool(totp_code) == bool(recovery_code) or not enabled(user) or user.mfa_factor_id is None:
        return None
    if recovery_code:
        stored = user.mfa_recovery_hashes or []
        match = next((value for value in stored if tokens_match(recovery_code, value)), None)
        if match is None:
            return None
        user.mfa_recovery_hashes = [value for value in stored if value != match]
        return "password+recovery_code"
    if user.mfa_secret_encrypted is None:
        return None
    seed, factor_id = decrypt_seed(settings, user, user.mfa_secret_encrypted)
    if factor_id != user.mfa_factor_id:
        raise DependencyUnavailableError(
            "platform_mfa", message="Platform MFA material is unavailable."
        )
    counter = match_counter(seed, totp_code or "", utc_now(), user.mfa_last_counter)
    if counter is None:
        return None
    user.mfa_last_counter = counter
    return "password+totp"


@dataclass(frozen=True, repr=False)
class Enrollment:
    secret: str
    otpauth_uri: str
    expires_at: datetime


class PlatformMfaService(PlatformAccessService):
    async def _context(self) -> tuple[Session, User]:
        live = await self._authorize_platform("platform.tenants.write")
        user = await UserRepository(self.session, self.actor.tenant_id).get_active(
            self.actor.user_id, for_update=True
        )
        if user is None:
            raise ConflictError(message="Operator unavailable.")
        return live, user

    async def _deny(self, user: User, live: Session, action: str) -> None:
        clear_proof(live)
        await auth_for(self.session, self.settings, user.tenant_id)._register_failed_attempt(user)
        await self.audit.record(
            action="platform.mfa." + action,
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
            outcome="DENIED",
        )
        raise AuthenticationStateChangedError(
            code=ErrorCode.INVALID_CREDENTIALS, message="Credential confirmation failed."
        )

    async def _password(self, user: User, live: Session, password: str, action: str) -> None:
        if not 1 <= len(password) <= 128:
            raise InputValidationError(message="Invalid password length.")
        if not auth_for(self.session, self.settings, user.tenant_id).verify_password(
            password, user.password_hash
        ):
            await self._deny(user, live, action)
        now = utc_now()
        if live.expires_at <= now or live.issued_at > now:
            raise PermissionDeniedError(message="This session has expired; sign in again.")

    async def _record(self, action: str, user: User) -> None:
        await self.audit.record(
            action="platform.mfa." + action,
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
        )

    async def _invalidate_proofs(self, user: User) -> None:
        await self.session.execute(
            update(Session)
            .where(Session.tenant_id == user.tenant_id, Session.user_id == user.id)
            .values(
                platform_reauthenticated_at=None,
                platform_mfa_verified_at=None,
                platform_mfa_factor_id=None,
            )
        )

    async def status(self) -> dict[str, object]:
        _, user = await self._context()
        await self._record("status", user)
        pending = user.mfa_pending_expires_at
        return {
            "enabled": enabled(user),
            "required_for_platform_actions": user.platform_mfa_required,
            "pending_expires_at": pending if pending and pending > utc_now() else None,
            "recovery_codes_remaining": len(user.mfa_recovery_hashes or []),
        }

    async def start(self, password: str) -> Enrollment:
        live, user = await self._context()
        if enabled(user):
            require_recent_step_up(live, user)
        await self._password(user, live, password, "enrollment_start")
        if enabled(user):
            require_recent_step_up(live, user)
        seed, factor_id = new_seed(), uuid4()
        user.mfa_pending_secret_encrypted = encrypt_seed(self.settings, user, seed, factor_id)
        user.mfa_pending_session_id = live.id
        user.mfa_pending_expires_at = min(utc_now() + timedelta(minutes=10), live.expires_at)
        user.failed_login_attempts = 0
        await self._record("enrollment_start", user)
        uri = (
            "otpauth://totp/"
            + quote("EcoMind-AI:" + user.email, safe="")
            + "?"
            + urlencode(
                {
                    "secret": seed,
                    "issuer": "EcoMind-AI",
                    "algorithm": "SHA1",
                    "digits": 6,
                    "period": 30,
                }
            )
        )
        return Enrollment(seed, uri, user.mfa_pending_expires_at)

    async def activate(self, password: str, totp_code: str) -> list[str]:
        live, user = await self._context()
        await self._password(user, live, password, "enrollment_confirm")
        if (
            user.mfa_pending_session_id != live.id
            or user.mfa_pending_expires_at is None
            or user.mfa_pending_expires_at <= utc_now()
            or user.mfa_pending_secret_encrypted is None
        ):
            raise ConflictError(message="Start a new enrollment in this session.")
        seed, factor_id = decrypt_seed(self.settings, user, user.mfa_pending_secret_encrypted)
        counter = match_counter(seed, totp_code, utc_now())
        if counter is None:
            await self._deny(user, live, "enrollment_confirm")
        user.mfa_secret_encrypted = user.mfa_pending_secret_encrypted
        user.mfa_factor_id = factor_id
        user.mfa_last_counter = counter
        codes = recovery_codes(user)
        clear_pending(user)
        await self._invalidate_proofs(user)
        user.failed_login_attempts = 0
        await self._record("enrollment_confirm", user)
        return codes

    async def cancel(self) -> None:
        _, user = await self._context()
        clear_pending(user)
        await self._record("enrollment_cancel", user)

    async def regenerate(self, password: str) -> list[str]:
        live, user = await self._context()
        if not enabled(user):
            raise ConflictError(message="Enroll an authenticator first.")
        require_recent_step_up(live, user)
        await self._password(user, live, password, "recovery_rotate")
        require_recent_step_up(live, user)
        codes = recovery_codes(user)
        await self._invalidate_proofs(user)
        user.failed_login_attempts = 0
        await self._record("recovery_rotate", user)
        return codes
