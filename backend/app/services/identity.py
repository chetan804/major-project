"""Tenant administration with service-layer authorization and audited writes.

Administrative writes take a tenant NO KEY UPDATE lock before users/roles. This serializes the
last-administrator invariant and permission changes; permission grants are
re-resolved *after* the lock, so a waiter cannot use a revoked grant. Authentication
for passwords/sessions locks User, not this mutex. Machine authentication takes
Tenant SHARE before its key row. Recovery's implicit FK KEY SHARE is compatible
with the tenant NO KEY UPDATE mutex (no inverted lock order).
"""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
from typing import Any
from uuid import UUID
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.checks import ensure_permission
from app.authorization.context import Actor
from app.authorization.resolution import resolve_permissions
from app.core.errors import (
    BusinessRuleError,
    ConflictError,
    InputValidationError,
    NotFoundError,
    PermissionDeniedError,
)
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.models._enums import PermissionScope, TenantStatus, UserStatus
from app.models.identity import Permission, Role, RolePermission, Tenant, User, UserRole
from app.repositories.base import PaginationResult
from app.repositories.identity import (
    AuditLogRepository,
    RoleRepository,
    SessionRepository,
    UserRepository,
)

# These permissions are deliberately not available to human tenant roles.
NON_HUMAN_PERMISSIONS = frozenset({"bins.telemetry.ingest", "models.manage"})


class IdentityService:
    def __init__(self, session: AsyncSession, actor: Actor) -> None:
        self.session = session
        self.actor = actor
        self.users = UserRepository(session, actor.tenant_id)
        self.roles = RoleRepository(session, actor.tenant_id)
        self.audit = AuditLogRepository(session, actor.tenant_id)

    def _require(self, permission: str) -> None:
        ensure_permission(self.actor, permission)
        if self.actor.tenant_id == PLATFORM_SCOPE_ID:
            raise PermissionDeniedError(message="Tenant administration requires a tenant account.")

    async def _write(self, permission: str) -> None:
        self._require(permission)
        await apply_tenant_context(self.session, self.actor.tenant_id)
        tenant = (
            await self.session.execute(
                select(Tenant)
                .where(
                    Tenant.id == self.actor.tenant_id,
                    Tenant.deleted_at.is_(None),
                )
                # Serialize administrators without blocking the KEY SHARE lock
                # acquired by recovery outbox INSERT foreign-key checks. FOR UPDATE
                # here would invert Tenant -> User against User -> FK Tenant.
                .with_for_update(key_share=True)
                .execution_options(populate_existing=True)
            )
        ).scalar_one_or_none()
        if tenant is None:
            raise NotFoundError(resource_type="tenant")
        if tenant.status not in (TenantStatus.ACTIVE, TenantStatus.TRIAL):
            raise PermissionDeniedError(message="This tenant is not active.")
        caller = await self.users.get_active(self.actor.user_id, for_update=True)
        if (
            caller is None
            or caller.status != UserStatus.ACTIVE
            or (caller.locked_until is not None and caller.locked_until > utc_now())
        ):
            raise PermissionDeniedError(message="This account is not active.")
        if self.actor.session_id is not None:
            live = await SessionRepository(self.session, self.actor.tenant_id).get_live(
                self.actor.session_id
            )
            if live is None or live.user_id != caller.id:
                raise PermissionDeniedError(message="This session is no longer active.")
        roles, permissions = await resolve_permissions(
            self.session, self.actor.tenant_id, caller.id
        )
        self.actor = replace(self.actor, roles=roles, permissions=permissions)
        self._require(permission)

    async def authorize_invitation(self) -> Actor:
        """Use the same live tenant/caller mutex for both invitation aliases."""
        if self.actor.auth_type != "USER":
            raise PermissionDeniedError(message="Invitations require a human account.")
        await self._write("users.write")
        return self.actor

    async def _user(self, user_id: UUID, *, lock: bool = False) -> User:
        user = await self.users.get_active(user_id, for_update=lock)
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(user_id))
        return user

    def _grant_guard(self, permissions: frozenset[str]) -> None:
        if not permissions.issubset(self.actor.permissions):
            ensure_permission(self.actor, "roles.assign.elevate")

    async def _target_guard(self, user: User) -> None:
        _, permissions = await resolve_permissions(self.session, self.actor.tenant_id, user.id)
        self._grant_guard(permissions)

    async def _keep_admin(self) -> None:
        if await self.users.count_admins() == 0:
            raise BusinessRuleError(
                rule_code="BR-IDENTITY-LAST-ADMIN",
                message=(
                    "Keep at least one active administrator with non-expiring account and role recovery permissions."
                ),
            )

    async def list_users(
        self,
        *,
        page: int,
        page_size: int,
        search: str | None = None,
        status: str | None = None,
        role_code: str | None = None,
        sort: tuple[str, ...] = (),
    ) -> PaginationResult:
        self._require("users.read")
        return await self.users.list_users(
            page=page,
            page_size=page_size,
            search=search,
            status=status,
            role_code=role_code,
            sort=sort,
        )

    async def get_user(self, user_id: UUID) -> User:
        self._require("users.read")
        return await self._user(user_id)

    async def update_user(self, user_id: UUID, values: dict[str, Any]) -> User:
        await self._write("users.write")
        user = await self._user(user_id, lock=True)
        await self._target_guard(user)
        _validate_profile(values, allow_status=True)
        old_status = user.status
        was_admin = await self.users.is_permanent_admin(user.id)
        if "status" in values:
            values = {**values, "status": UserStatus(values["status"])}
        await self.users.update(user, **values)
        if user.status != old_status:
            user.password_reset_token_hash = None
            user.password_reset_expires_at = None
            user.email_verification_token_hash = None
            user.email_verification_expires_at = None
            await self._revoke_sessions(user.id, "account status changed")
        if was_admin and user.status != UserStatus.ACTIVE:
            await self._keep_admin()
        await self.audit.record(
            action="user.update",
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
            changes=values,
        )
        await self.session.refresh(user)
        return user

    async def delete_user(self, user_id: UUID) -> None:
        await self._write("users.delete")
        user = await self._user(user_id, lock=True)
        await self._target_guard(user)
        was_admin = await self.users.is_permanent_admin(user.id)
        user.deleted_at = utc_now()
        user.status = UserStatus.DISABLED
        user.password_reset_token_hash = None
        user.password_reset_expires_at = None
        user.email_verification_token_hash = None
        user.email_verification_expires_at = None
        await self._revoke_sessions(user.id, "account deleted")
        await self.session.flush()
        if was_admin:
            await self._keep_admin()
        await self.audit.record(
            action="user.delete", actor=self.actor, resource_type="user", resource_id=str(user.id)
        )

    async def _revoke_sessions(self, user_id: UUID, reason: str) -> None:
        for row in await SessionRepository(self.session, self.actor.tenant_id).list_for_user(
            user_id
        ):
            row.revoked_at = utc_now()
            row.revoked_reason = reason
        await self.session.flush()

    async def list_roles(self, *, page: int, page_size: int) -> PaginationResult:
        self._require("roles.read")
        return await self.roles.list(page=page, page_size=page_size, sort=("code",))

    async def role_permissions(self, role_id: UUID) -> frozenset[str]:
        self._require("roles.read")
        await self.roles.get_or_404(role_id)
        return await self.roles.permission_codes(role_id)

    async def list_permissions(self) -> list[Permission]:
        self._require("roles.read")
        return list(
            (
                await self.session.execute(
                    select(Permission)
                    .where(
                        Permission.scope == PermissionScope.TENANT,
                        Permission.code.not_in(NON_HUMAN_PERMISSIONS),
                    )
                    .order_by(Permission.code)
                )
            )
            .scalars()
            .all()
        )

    async def assign_role(self, user_id: UUID, role_id: UUID, expires_at: datetime | None) -> None:
        await self._write("roles.assign")
        user = await self._user(user_id, lock=True)
        role = await self.roles.get_or_404(role_id)
        codes = await self.roles.permission_codes(role.id)
        await self._validate_role_permissions(codes)
        was_admin = await self.users.is_permanent_admin(user.id)
        if expires_at is not None and (expires_at.tzinfo is None or expires_at <= utc_now()):
            raise InputValidationError(message="Role expiry must be an aware future timestamp.")
        grant = (
            await self.session.execute(
                select(UserRole).where(
                    UserRole.tenant_id == self.actor.tenant_id,
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                )
            )
        ).scalar_one_or_none()
        if grant is None:
            grant = UserRole(user_id=user.id, role_id=role.id, tenant_id=self.actor.tenant_id)
            self.session.add(grant)
        grant.expires_at = expires_at
        grant.assigned_by = self.actor.user_id
        grant.assigned_at = utc_now()
        await self.session.flush()
        if was_admin:
            await self._keep_admin()
        await self.audit.record(
            action="user.role_assign",
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={
                "role_id": str(role.id),
                "expires_at": expires_at.isoformat() if expires_at else None,
            },
        )

    async def revoke_role(self, user_id: UUID, role_id: UUID) -> None:
        await self._write("roles.assign")
        user = await self._user(user_id, lock=True)
        role = await self.roles.get_or_404(role_id)
        self._grant_guard(await self.roles.permission_codes(role.id))
        was_admin = await self.users.is_permanent_admin(user.id)
        grant = (
            await self.session.execute(
                select(UserRole).where(
                    UserRole.tenant_id == self.actor.tenant_id,
                    UserRole.user_id == user.id,
                    UserRole.role_id == role.id,
                )
            )
        ).scalar_one_or_none()
        if grant is None:
            raise NotFoundError(resource_type="role assignment")
        await self.session.delete(grant)
        await self.session.flush()
        if was_admin:
            await self._keep_admin()
        await self.audit.record(
            action="user.role_revoke",
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
            changes={"role_id": str(role.id)},
        )

    async def _validate_role_permissions(self, codes: frozenset[str]) -> list[Permission]:
        rows = list(
            (await self.session.execute(select(Permission).where(Permission.code.in_(codes))))
            .scalars()
            .all()
        )
        if len(rows) != len(codes):
            raise InputValidationError(message="Unknown permission code.")
        if any(p.scope != PermissionScope.TENANT or p.code in NON_HUMAN_PERMISSIONS for p in rows):
            raise PermissionDeniedError(
                message="Platform and device permissions cannot be granted to tenant roles."
            )
        self._grant_guard(codes)
        return rows

    async def create_role(
        self, *, code: str, name: str, description: str | None, permissions: frozenset[str]
    ) -> Role:
        await self._write("roles.write")
        if await self.roles.get_by_code(code) is not None:
            raise ConflictError(message="A role with this code already exists.")
        rows = await self._validate_role_permissions(permissions)
        role = await self.roles.create(
            code=code, name=name, description=description, is_system=False
        )
        for row in rows:
            self.session.add(
                RolePermission(
                    tenant_id=self.actor.tenant_id, role_id=role.id, permission_id=row.id
                )
            )
        await self.session.flush()
        await self.audit.record(
            action="role.create",
            actor=self.actor,
            resource_type="role",
            resource_id=str(role.id),
            changes={"code": code, "permissions": sorted(permissions)},
        )
        return role

    async def update_role(self, role_id: UUID, values: dict[str, Any]) -> Role:
        await self._write("roles.write")
        role = await self.roles.get_or_404(role_id)
        if role.is_system:
            raise PermissionDeniedError(message="System roles cannot be edited.")
        if set(values) - {"name", "description"} or ("name" in values and not values["name"]):
            raise InputValidationError(
                message="Only a nonempty name and description may be changed."
            )
        self._grant_guard(await self.roles.permission_codes(role.id))
        await self.roles.update(role, **values)
        await self.audit.record(
            action="role.update",
            actor=self.actor,
            resource_type="role",
            resource_id=str(role.id),
            changes=values,
        )
        await self.session.refresh(role)
        return role

    async def set_role_permissions(self, role_id: UUID, codes: frozenset[str]) -> Role:
        await self._write("roles.write")
        role = await self.roles.get_or_404(role_id)
        if role.is_system:
            raise PermissionDeniedError(message="System roles cannot be edited.")
        old = await self.roles.permission_codes(role.id)
        self._grant_guard(old)
        rows = await self._validate_role_permissions(codes)
        had_admins = await self.users.count_admins() > 0
        role.updated_at = utc_now()
        await self.session.execute(
            delete(RolePermission).where(
                RolePermission.tenant_id == self.actor.tenant_id,
                RolePermission.role_id == role.id,
            )
        )
        for row in rows:
            self.session.add(
                RolePermission(
                    tenant_id=self.actor.tenant_id, role_id=role.id, permission_id=row.id
                )
            )
        await self.session.flush()
        if had_admins:
            await self._keep_admin()
        await self.audit.record(
            action="role.permissions_update",
            actor=self.actor,
            resource_type="role",
            resource_id=str(role.id),
            changes={"permissions": sorted(codes)},
        )
        return role

    async def current_tenant(self) -> Tenant:
        self._require("settings.read")
        return await self._tenant()

    async def _tenant(self) -> Tenant:
        tenant = (
            await self.session.execute(
                select(Tenant).where(
                    Tenant.id == self.actor.tenant_id,
                    Tenant.deleted_at.is_(None),
                )
            )
        ).scalar_one_or_none()
        if tenant is None:
            raise NotFoundError(resource_type="tenant")
        return tenant

    async def update_tenant(self, values: dict[str, Any]) -> Tenant:
        await self._write("settings.write")
        if set(values) - {"name", "timezone", "locale"} or any(not v for v in values.values()):
            raise InputValidationError(
                message="Only nonempty name, timezone and locale may be changed."
            )
        if "timezone" in values:
            validate_timezone(values["timezone"])
        tenant = await self._tenant()
        for key, value in values.items():
            setattr(tenant, key, value)
        await self.session.flush()
        await self.audit.record(
            action="tenant.update",
            actor=self.actor,
            resource_type="tenant",
            resource_id=str(tenant.id),
            changes=values,
        )
        await self.session.refresh(tenant)
        return tenant


def validate_timezone(value: str) -> None:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise InputValidationError(message="Unknown IANA timezone.", field="timezone") from exc


def _validate_profile(values: dict[str, Any], *, allow_status: bool) -> None:
    allowed = {"full_name", "phone", "preferred_timezone", "preferred_locale"}
    if allow_status:
        allowed.add("status")
    if set(values) - allowed:
        raise InputValidationError(message="Unsupported profile field.")
    if "full_name" in values and not values["full_name"]:
        raise InputValidationError(message="Full name cannot be empty.")
    if "status" in values and values["status"] not in ("ACTIVE", "SUSPENDED", "DISABLED"):
        raise InputValidationError(message="Status must be ACTIVE, SUSPENDED or DISABLED.")
    if values.get("preferred_timezone") is not None:
        validate_timezone(values["preferred_timezone"])
