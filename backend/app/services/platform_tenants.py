"""Platform registry operations, never a general cross-tenant data access service."""

from __future__ import annotations

import re
import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from email.errors import MessageError
from email.headerregistry import Address
from typing import Any
from uuid import UUID

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError

from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.errors import (
    ConflictError,
    InputValidationError,
    NotFoundError,
)
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.models._enums import PermissionScope, TenantStatus, TenantType, UserStatus
from app.models.identity import Permission, Role, RolePermission, Session, Tenant, User, UserRole
from app.repositories.base import PaginationResult
from app.services.identity import validate_timezone
from app.services.platform_access import PlatformAccessService, auth_for, require_recent_step_up


def validate_operator_reason(reason: str) -> str:
    if not 10 <= len(reason.strip()) <= 1000:
        raise InputValidationError(
            message="An operator reason of 10 to 1000 characters is required."
        )
    return reason.strip()


def validate_metadata(values: dict[str, Any]) -> None:
    if set(values) - {"name", "timezone", "locale"}:
        raise InputValidationError(message="Only name, timezone and locale may be changed.")
    for name, value in values.items():
        limit = {"name": 200, "timezone": 64, "locale": 16}[name]
        if not isinstance(value, str) or not value.strip() or len(value) > limit:
            raise InputValidationError(message="Invalid tenant metadata.", field=name)
    if "timezone" in values:
        validate_timezone(values["timezone"])
    if "locale" in values and not re.fullmatch(
        r"[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*", values["locale"]
    ):
        raise InputValidationError(message="Invalid locale.", field="locale")


def validate_operator_email(value: str) -> str:
    email = value.strip().lower()
    try:
        if (
            len(email) > 320
            or not email.isascii()
            or any(ord(c) < 32 or ord(c) == 127 for c in email)
        ):
            raise ValueError
        address = Address(addr_spec=email)
        if not address.username or not address.domain or address.addr_spec != email:
            raise ValueError
    except (ValueError, IndexError, MessageError) as exc:
        raise InputValidationError(
            message="A single valid administrator email address is required."
        ) from exc
    return email


class PlatformTenantService(PlatformAccessService):
    async def _authorize(self, permission: str) -> None:
        live = await self._authorize_platform(permission)
        if permission == "platform.tenants.write":
            require_recent_step_up(live, self.operator)

    @asynccontextmanager
    async def _target_scope(self, tenant_id: UUID) -> AsyncIterator[None]:
        await apply_tenant_context(self.session, tenant_id)
        try:
            yield
        except BaseException:
            # Also handles cancellation/DB errors: do not attempt SET on an
            # aborted connection or leave a usable foreign scope after failure.
            await self.session.rollback()
            raise
        else:
            await apply_tenant_context(self.session, PLATFORM_SCOPE_ID)

    async def _target(self, tenant_id: UUID, *, lock: bool = False) -> Tenant:
        query = select(Tenant).where(
            Tenant.id == tenant_id, Tenant.id != PLATFORM_SCOPE_ID, Tenant.deleted_at.is_(None)
        )
        if lock:
            query = query.with_for_update(key_share=True)
        row = (
            await self.session.execute(query.execution_options(populate_existing=True))
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(resource_type="tenant")
        return row

    async def _record(
        self, action: str, row: Tenant, reason: str | None = None, **metadata: Any
    ) -> None:
        await apply_tenant_context(self.session, PLATFORM_SCOPE_ID)
        await self.audit.record(
            action="platform.tenant." + action,
            actor=self.actor,
            resource_type="tenant",
            resource_id=str(row.id),
            metadata={**metadata, **({"reason": reason} if reason else {})},
        )

    async def list_tenants_platform(
        self, *, page: int = 1, page_size: int = 25, status: str | None = None
    ) -> PaginationResult:
        await self._authorize("platform.tenants.read")
        if (
            not 1 <= page <= 10000
            or not 1 <= page_size <= 100
            or (status is not None and status not in set(TenantStatus))
        ):
            raise InputValidationError(message="Invalid tenant query.")
        query = select(Tenant).where(Tenant.id != PLATFORM_SCOPE_ID, Tenant.deleted_at.is_(None))
        if status:
            query = query.where(Tenant.status == status)
        total = int(
            (
                await self.session.execute(select(func.count()).select_from(query.subquery()))
            ).scalar_one()
        )
        rows = list(
            (
                await self.session.execute(
                    query.order_by(Tenant.created_at.desc(), Tenant.id.desc())
                    .limit(page_size)
                    .offset((page - 1) * page_size)
                )
            ).scalars()
        )
        await self.audit.record(
            action="platform.tenant.list",
            actor=self.actor,
            resource_type="tenant",
            metadata={"returned_ids": [str(row.id) for row in rows], "status": status},
        )
        return PaginationResult(rows, page=page, page_size=page_size, total=total)

    async def get_tenant_platform(self, tenant_id: UUID) -> Tenant:
        await self._authorize("platform.tenants.read")
        row = await self._target(tenant_id)
        await self._record("read", row)
        return row

    async def create_tenant_platform(
        self,
        *,
        name: str,
        slug: str,
        type: TenantType,
        admin_email: str,
        admin_name: str,
        reason: str,
        timezone: str = "UTC",
        locale: str = "en-IN",
    ) -> Tenant:
        await self._authorize("platform.tenants.write")
        reason = validate_operator_reason(reason)
        validate_metadata({"name": name, "timezone": timezone, "locale": locale})
        if (
            not 3 <= len(slug) <= 120
            or not re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", slug)
            or slug.startswith("ecomind-")
            or type not in set(TenantType)
        ):
            raise InputValidationError(message="Invalid or reserved tenant identifier/type.")
        if not admin_name.strip() or len(admin_name) > 200:
            raise InputValidationError(message="Invalid administrator name.")
        email = validate_operator_email(admin_email)
        row = Tenant(
            name=name.strip(),
            slug=slug,
            type=type,
            status=TenantStatus.ACTIVE,
            timezone=timezone,
            locale=locale,
        )
        self.session.add(row)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            raise ConflictError(message="The tenant identifier is unavailable.") from exc
        async with self._target_scope(row.id):
            permissions = {
                p.code: p for p in (await self.session.execute(select(Permission))).scalars()
            }
            admin_role: Role | None = None
            for definition in ROLE_DEFINITIONS.values():
                if definition.code == "SUPER_ADMIN":
                    continue
                if any(
                    permissions[code].scope != PermissionScope.TENANT
                    for code in definition.permissions
                ):
                    raise ConflictError(message="Tenant permission catalogue is inconsistent.")
                role = Role(
                    tenant_id=row.id,
                    code=definition.code,
                    name=definition.name,
                    description=definition.description,
                    level=definition.level,
                    is_system=False,
                    is_default=definition.is_default,
                )
                self.session.add(role)
                await self.session.flush()
                self.session.add_all(
                    [
                        RolePermission(
                            tenant_id=row.id, role_id=role.id, permission_id=permissions[code].id
                        )
                        for code in sorted(definition.permissions)
                    ]
                )
                if definition.code == "TENANT_ADMIN":
                    admin_role = role
            if admin_role is None:
                raise ConflictError(message="Tenant administrator catalogue is missing.")
            auth = auth_for(self.session, self.settings, row.id)
            user = User(
                tenant_id=row.id,
                email=email,
                full_name=admin_name.strip(),
                status=UserStatus.INVITED,
                # 128 characters also satisfy the largest configurable minimum.
                password_hash=auth.hash_password(secrets.token_urlsafe(96)),
            )
            self.session.add(user)
            await self.session.flush()
            self.session.add(UserRole(tenant_id=row.id, user_id=user.id, role_id=admin_role.id))
            await self.session.flush()
            await auth.request_email_verification_in(row, email=email)
            await self._record(
                "create",
                row,
                reason,
                administrator_id=str(user.id),
                delivery_status="queued_if_eligible",
            )
        return row

    async def update_tenant_platform(
        self, tenant_id: UUID, *, reason: str, values: dict[str, Any]
    ) -> Tenant:
        await self._authorize("platform.tenants.write")
        reason = validate_operator_reason(reason)
        validate_metadata(values)
        if not values:
            raise InputValidationError(message="Provide at least one metadata field.")
        row = await self._target(tenant_id, lock=True)
        if row.status == TenantStatus.CANCELLED:
            raise ConflictError(message="Cancelled tenants cannot be changed here.")
        for field, value in values.items():
            setattr(row, field, value.strip())
        await self.session.flush()
        await self._record("update", row, reason, fields=sorted(values))
        await self.session.refresh(row)
        return row

    async def set_status_platform(self, tenant_id: UUID, *, suspended: bool, reason: str) -> Tenant:
        await self._authorize("platform.tenants.write")
        reason = validate_operator_reason(reason)
        row = await self._target(tenant_id, lock=True)
        if row.status == TenantStatus.CANCELLED:
            raise ConflictError(message="Cancelled tenants cannot be changed here.")
        old_status = row.status
        row.status = TenantStatus.SUSPENDED if suspended else TenantStatus.ACTIVE
        await self.session.flush()
        revoked = 0
        if suspended:
            async with self._target_scope(row.id):
                # Login/refresh/recovery hold User, so wait before invalidating.
                await self.session.execute(
                    select(User.id)
                    .where(User.tenant_id == row.id)
                    .order_by(User.id)
                    .with_for_update()
                )
                changed = await self.session.execute(
                    update(Session)
                    .where(Session.tenant_id == row.id, Session.revoked_at.is_(None))
                    .values(revoked_at=utc_now())
                    .returning(Session.id)
                )
                revoked = len(changed.all())
                await self.session.execute(
                    update(User)
                    .where(User.tenant_id == row.id)
                    .values(
                        password_reset_token_hash=None,
                        password_reset_expires_at=None,
                        email_verification_token_hash=None,
                        email_verification_expires_at=None,
                    )
                )
        await self._record(
            "suspend" if suspended else "activate",
            row,
            reason,
            previous_status=old_status.value,
            status=row.status.value,
            revoked_sessions=revoked,
        )
        await self.session.refresh(row)
        return row
