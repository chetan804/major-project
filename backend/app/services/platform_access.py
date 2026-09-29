"""Shared live platform identity checks; no tenant impersonation or bypass."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.context import Actor
from app.authorization.resolution import resolve_permissions
from app.core.config import Settings
from app.core.errors import PermissionDeniedError
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import Session, Tenant, User
from app.repositories.identity import (
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)
from app.services.auth import AuthService

STEP_UP_LIFETIME = timedelta(minutes=5)


def step_up_expiry(live: Session, now: datetime) -> datetime | None:
    verified = live.platform_reauthenticated_at
    if (
        verified is None
        or verified > now
        or verified < live.issued_at
        or live.revoked_at is not None
    ):
        return None
    expiry = min(verified + STEP_UP_LIFETIME, live.expires_at)
    return expiry if now < expiry else None


def mfa_enabled(user: User) -> bool:
    return (
        user.mfa_secret_encrypted is not None
        or user.mfa_factor_id is not None
        or user.mfa_recovery_hashes is not None
        or user.mfa_last_counter is not None
    )


def require_recent_step_up(live: Session, user: User | None) -> None:
    now = utc_now()
    strong = user is not None and (
        not (mfa_enabled(user) or user.platform_mfa_required)
        or (
            user.mfa_factor_id is not None
            and live.platform_mfa_factor_id == user.mfa_factor_id
            and live.platform_mfa_verified_at is not None
            and live.platform_mfa_verified_at == live.platform_reauthenticated_at
        )
    )
    if not strong or step_up_expiry(live, now) is None:
        raise PermissionDeniedError(
            message="Confirm the required credentials before this platform mutation.",
            step_up_required=True,
        )


def auth_for(session: AsyncSession, settings: Settings, tenant_id: UUID) -> AuthService:
    return AuthService(
        settings=settings,
        users=UserRepository(session, tenant_id),
        sessions=SessionRepository(session, tenant_id),
        audit=AuditLogRepository(session, tenant_id),
        tenants=TenantRepository(session),
    )


class PlatformAccessService:
    def __init__(self, session: AsyncSession, actor: Actor, settings: Settings) -> None:
        self.session, self.actor, self.settings = session, actor, settings
        self.operator: User | None = None
        self.audit = AuditLogRepository(session, PLATFORM_SCOPE_ID)

    def _require(self, permission: str) -> None:
        if (
            self.actor.tenant_id != PLATFORM_SCOPE_ID
            or not self.actor.is_platform_operator
            or self.actor.auth_type != "USER"
            or self.actor.session_id is None
        ):
            raise PermissionDeniedError(message="A platform operator session is required.")
        self.actor.require_permission(permission)

    async def _authorize_platform(self, permission: str) -> Session:
        self._require(permission)
        await apply_tenant_context(self.session, PLATFORM_SCOPE_ID)
        platform = (
            await self.session.execute(
                select(Tenant)
                .where(Tenant.id == PLATFORM_SCOPE_ID)
                .with_for_update(key_share=True)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if (
            platform is None
            or platform.deleted_at is not None
            or platform.status != TenantStatus.ACTIVE
        ):
            raise PermissionDeniedError(message="Platform administration is unavailable.")
        user = await UserRepository(self.session, PLATFORM_SCOPE_ID).get_active(
            self.actor.user_id, for_update=True
        )
        if (
            user is None
            or user.status != UserStatus.ACTIVE
            or (user.locked_until and user.locked_until > utc_now())
        ):
            raise PermissionDeniedError(message="This operator is not active.")
        if self.actor.session_id is None:
            raise PermissionDeniedError(message="A platform session is required.")
        live = await SessionRepository(self.session, PLATFORM_SCOPE_ID).get_live(
            self.actor.session_id
        )
        if live is None or live.user_id != user.id:
            raise PermissionDeniedError(message="This operator session is not active.")
        roles, permissions = await resolve_permissions(self.session, PLATFORM_SCOPE_ID, user.id)
        self.actor = replace(self.actor, roles=roles, permissions=permissions)
        self._require(permission)

        self.operator = user
        return live


def require_strong_step_up(live: Session, user: User | None) -> None:
    """Lifecycle administration never accepts the legacy password-only flow."""
    if user is None or not mfa_enabled(user):
        raise PermissionDeniedError(
            message="Enroll and confirm MFA before operator administration.", step_up_required=True
        )
    require_recent_step_up(live, user)
