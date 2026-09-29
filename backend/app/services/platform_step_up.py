"""Session confirmation: password-only before enrollment, two factors after it."""

from datetime import datetime
from typing import Literal

from app.core.errors import (
    AuthenticationStateChangedError,
    ErrorCode,
    InputValidationError,
    PermissionDeniedError,
)
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.repositories.identity import UserRepository
from app.services.platform_access import (
    STEP_UP_LIFETIME,
    PlatformAccessService,
    auth_for,
    mfa_enabled,
)
from app.services.platform_mfa import clear_proof, consume_factor


class PlatformStepUpService(PlatformAccessService):
    method: Literal["password", "password+totp", "password+recovery_code"] = "password"

    async def confirm(
        self, password: str, *, totp_code: str | None = None, recovery_code: str | None = None
    ) -> datetime:
        live = await self._authorize_platform("platform.tenants.write")
        if not 1 <= len(password) <= 128:
            raise InputValidationError(message="Password must contain 1 to 128 characters.")
        user = await UserRepository(self.session, PLATFORM_SCOPE_ID).get_active(
            self.actor.user_id, for_update=True
        )
        # The shared guard already checked and locked this row.
        if user is None:
            raise PermissionDeniedError(message="Operator unavailable.")
        auth = auth_for(self.session, self.settings, PLATFORM_SCOPE_ID)
        password_ok = auth.verify_password(password, user.password_hash)
        factor_method = (
            consume_factor(self.settings, user, totp_code=totp_code, recovery_code=recovery_code)
            if password_ok and mfa_enabled(user)
            else None
        )
        factor_ok = (
            factor_method is not None
            if mfa_enabled(user)
            else totp_code is None and recovery_code is None
        )
        if not password_ok or not factor_ok:
            clear_proof(live)
            await auth._register_failed_attempt(user)
            await self.audit.record(
                action="platform.step_up.confirm",
                actor=self.actor,
                resource_type="session",
                resource_id=str(live.id),
                outcome="DENIED",
                metadata={"method": "password+second_factor" if mfa_enabled(user) else "password"},
            )
            raise AuthenticationStateChangedError(
                code=ErrorCode.INVALID_CREDENTIALS, message="Credential confirmation failed."
            )
        now = utc_now()
        if live.expires_at <= now or live.issued_at > now:
            raise PermissionDeniedError(message="This session cannot be confirmed; sign in again.")
        user.failed_login_attempts = 0
        live.platform_reauthenticated_at = now
        live.platform_mfa_verified_at = now if factor_method else None
        live.platform_mfa_factor_id = user.mfa_factor_id if factor_method else None
        self.method = factor_method or "password"
        expiry = min(live.platform_reauthenticated_at + STEP_UP_LIFETIME, live.expires_at)
        await self.audit.record(
            action="platform.step_up.confirm",
            actor=self.actor,
            resource_type="session",
            resource_id=str(live.id),
            metadata={"method": self.method, "expires_at": expiry.isoformat()},
        )
        return expiry

    async def clear(self) -> None:
        live = await self._authorize_platform("platform.tenants.write")
        changed = live.platform_reauthenticated_at is not None
        clear_proof(live)
        await self.audit.record(
            action="platform.step_up.clear",
            actor=self.actor,
            resource_type="session",
            resource_id=str(live.id),
            metadata={"changed": changed},
        )
