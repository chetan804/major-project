"""Own-realm operator lifecycle; no role editor or lost-factor bypass.

The realm mutex serializes all lifecycle mutations. Auth/password/refresh locks
only User; acquire affected users before invalidating their sessions or codes.
"""

from __future__ import annotations

import secrets
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.authorization.permissions import PLATFORM_PERMISSION_CODES
from app.core.errors import (
    BusinessRuleError,
    ConflictError,
    DependencyUnavailableError,
    InputValidationError,
    NotFoundError,
    PermissionDeniedError,
)
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.models._enums import PermissionScope, UserStatus
from app.models.identity import Permission, Role, RolePermission, Session, Tenant, User, UserRole
from app.repositories.base import PaginationResult
from app.services.platform_access import PlatformAccessService, auth_for, require_strong_step_up
from app.services.platform_mfa import clear_pending, decrypt_seed
from app.services.platform_tenants import validate_operator_email, validate_operator_reason


class PlatformOperatorService(PlatformAccessService):
    async def _write(self) -> None:
        live = await self._authorize_platform("platform.operators.write")
        require_strong_step_up(live, self.operator)

    async def _target(self, user_id: UUID) -> User:
        row = (
            await self.session.execute(
                select(User)
                .where(
                    User.tenant_id == PLATFORM_SCOPE_ID,
                    User.id == user_id,
                    User.deleted_at.is_(None),
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(resource_type="operator")
        return row

    async def _record(self, action: str, user: User | None = None, **metadata: Any) -> None:
        await self.audit.record(
            action="platform.operator." + action,
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id) if user else None,
            metadata=metadata,
        )

    async def list_operators(self, *, page: int = 1, page_size: int = 25) -> PaginationResult:
        await self._authorize_platform("platform.operators.read")
        if not 1 <= page <= 10000 or not 1 <= page_size <= 100:
            raise InputValidationError(message="Invalid operator pagination.")
        query = select(User).where(User.tenant_id == PLATFORM_SCOPE_ID, User.deleted_at.is_(None))
        total = int(
            (
                await self.session.execute(select(func.count()).select_from(query.subquery()))
            ).scalar_one()
        )
        rows = list(
            (
                await self.session.execute(
                    query.order_by(User.created_at, User.id)
                    .offset((page - 1) * page_size)
                    .limit(page_size)
                )
            ).scalars()
        )
        await self._record("list", page=page, page_size=page_size, returned=len(rows))
        return PaginationResult(rows, total=total, page=page, page_size=page_size)

    async def detail(self, user_id: UUID) -> User:
        await self._authorize_platform("platform.operators.read")
        user = await self._target(user_id)
        await self._record("read", user)
        return user

    async def invite(self, *, email: str, full_name: str, reason: str) -> User:
        await self._write()
        reason = validate_operator_reason(reason)
        email = validate_operator_email(email)
        if not full_name.strip() or len(full_name) > 200:
            raise InputValidationError(message="Invalid operator name.")
        if not PLATFORM_PERMISSION_CODES.issubset(self.actor.permissions):
            raise PermissionDeniedError(
                message="Inviting a full operator requires the complete platform grant set."
            )
        if (
            await self.session.execute(
                select(User.id).where(User.tenant_id == PLATFORM_SCOPE_ID, User.email == email)
            )
        ).first():
            raise ConflictError(message="The operator email is unavailable.")
        role = (
            await self.session.execute(
                select(Role).where(
                    Role.tenant_id == PLATFORM_SCOPE_ID,
                    Role.code == "SUPER_ADMIN",
                    Role.is_system.is_(True),
                )
            )
        ).scalar_one_or_none()
        if role is None:
            raise ConflictError(message="Platform operator role is unavailable.")
        grants = set(
            (
                await self.session.execute(
                    select(Permission.code)
                    .join(RolePermission, RolePermission.permission_id == Permission.id)
                    .where(
                        RolePermission.tenant_id == PLATFORM_SCOPE_ID,
                        RolePermission.role_id == role.id,
                    )
                )
            ).scalars()
        )
        if grants != PLATFORM_PERMISSION_CODES:
            raise ConflictError(
                message="Platform operator role does not match the reviewed catalogue."
            )
        auth = auth_for(self.session, self.settings, PLATFORM_SCOPE_ID)
        user = User(
            tenant_id=PLATFORM_SCOPE_ID,
            email=email,
            full_name=full_name.strip(),
            status=UserStatus.INVITED,
            platform_mfa_required=True,
            password_hash=auth.hash_password(secrets.token_urlsafe(96)),
        )
        self.session.add(user)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise ConflictError(message="The operator email is unavailable.") from exc
        self.session.add(UserRole(tenant_id=PLATFORM_SCOPE_ID, user_id=user.id, role_id=role.id))
        await self.session.flush()
        tenant = (
            await self.session.execute(select(Tenant).where(Tenant.id == PLATFORM_SCOPE_ID))
        ).scalar_one()
        await auth.request_email_verification_in(tenant, email=email)
        await self._record(
            "invite",
            user,
            reason=reason,
            delivery_status="queued_if_eligible",
            role="SUPER_ADMIN",
            mfa_required=True,
        )
        await self.session.refresh(user)
        return user

    async def _survivor(self, excluded: UUID) -> bool:
        users = list(
            (
                await self.session.execute(
                    select(User)
                    .where(
                        User.tenant_id == PLATFORM_SCOPE_ID,
                        User.deleted_at.is_(None),
                        User.status == UserStatus.ACTIVE,
                    )
                    .order_by(User.id)
                    .with_for_update()
                    .execution_options(populate_existing=True)
                )
            ).scalars()
        )
        for user in users:
            if user.id == excluded or (user.locked_until and user.locked_until > utc_now()):
                continue
            if (
                user.mfa_factor_id is None
                or user.mfa_secret_encrypted is None
                or user.mfa_last_counter is None
                or user.mfa_last_counter < 0
            ):
                continue
            try:
                _, factor_id = decrypt_seed(self.settings, user, user.mfa_secret_encrypted)
            except DependencyUnavailableError:
                continue
            if factor_id != user.mfa_factor_id:
                continue
            # Expiring or expired grants cannot be the permanent safety net.
            grants = set(
                (
                    await self.session.execute(
                        select(Permission.code)
                        .join(RolePermission, RolePermission.permission_id == Permission.id)
                        .join(Role, Role.id == RolePermission.role_id)
                        .join(UserRole, UserRole.role_id == Role.id)
                        .where(
                            UserRole.user_id == user.id,
                            UserRole.tenant_id == PLATFORM_SCOPE_ID,
                            UserRole.expires_at.is_(None),
                            Role.tenant_id == PLATFORM_SCOPE_ID,
                            RolePermission.tenant_id == PLATFORM_SCOPE_ID,
                            Permission.scope == PermissionScope.PLATFORM,
                        )
                    )
                ).scalars()
            )
            if {"platform.operators.write", "platform.tenants.write"}.issubset(grants):
                return True
        return False

    async def _clear_sessions(self, user: User, *, revoke: bool) -> int:
        values: dict[str, Any] = {
            "platform_reauthenticated_at": None,
            "platform_mfa_factor_id": None,
            "platform_mfa_verified_at": None,
        }
        if revoke:
            # Preserve original revocation timestamps on historical sessions.
            values["revoked_at"] = func.coalesce(Session.revoked_at, utc_now())
        ids = (
            await self.session.execute(
                update(Session)
                .where(Session.tenant_id == PLATFORM_SCOPE_ID, Session.user_id == user.id)
                .values(**values)
                .returning(Session.id)
            )
        ).all()
        return len(ids)

    async def set_suspended(self, user_id: UUID, *, suspended: bool, reason: str) -> User:
        await self._write()
        reason = validate_operator_reason(reason)
        user = await self._target(user_id)
        if user.status not in {UserStatus.ACTIVE, UserStatus.INVITED, UserStatus.SUSPENDED}:
            raise ConflictError(message="This operator state cannot be changed here.")
        previous = user.status
        changed_sessions = 0
        if suspended:
            if not await self._survivor(user.id):
                raise BusinessRuleError(
                    rule_code="BR-PLATFORM-LAST-OPERATOR",
                    message="Keep another active MFA-enrolled permanent operator before suspension.",
                )
            user.status = UserStatus.SUSPENDED
            changed_sessions = await self._clear_sessions(user, revoke=True)
            clear_pending(user)
            user.password_reset_token_hash = None
            user.password_reset_expires_at = None
            user.email_verification_token_hash = None
            user.email_verification_expires_at = None
        elif user.status == UserStatus.SUSPENDED:
            user.status = UserStatus.ACTIVE if user.email_verified_at else UserStatus.INVITED
        await self._record(
            "suspend" if suspended else "activate",
            user,
            reason=reason,
            previous_status=previous.value,
            status=user.status.value,
            affected_sessions=changed_sessions,
        )
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def require_mfa(self, user_id: UUID, *, reason: str) -> User:
        await self._write()
        reason = validate_operator_reason(reason)
        user = await self._target(user_id)
        if user.status not in {UserStatus.ACTIVE, UserStatus.INVITED, UserStatus.SUSPENDED}:
            raise ConflictError(message="This operator state cannot be changed here.")
        changed = not user.platform_mfa_required
        user.platform_mfa_required = True
        await self._clear_sessions(user, revoke=False)
        await self._record("require_mfa", user, reason=reason, changed=changed)
        await self.session.flush()
        await self.session.refresh(user)
        return user
