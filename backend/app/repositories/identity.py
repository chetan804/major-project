"""
Identity, tenancy and access-control repositories.

The lookups here are the security-critical ones: finding a user by email is how
a login is authenticated, and finding a session is how a token is checked. Both
therefore return exactly what the caller needs and nothing else — in particular,
neither returns a password hash to anything but the service that verifies it.

``UserRepository`` is tenant-scoped like every other repository. The one place a
user is looked up *without* a tenant is authentication, where the tenant is not
yet known; that path lives in ``AuthService`` and is documented there, because
"find the user by email across the platform, then verify they belong to the
requested tenant" is a decision that deserves to be visible in the code rather
than hidden in a repository flag.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.models.identity import (
    ApiKey,
    AuditLog,
    Permission,
    Role,
    RolePermission,
    Session,
    Tenant,
    User,
    UserRole,
)
from app.repositories.base import BaseRepository, PlatformRepository

__all__ = [
    "ApiKeyRepository",
    "AuditLogRepository",
    "PermissionRepository",
    "RoleRepository",
    "SessionRepository",
    "TenantRepository",
    "UserRepository",
]


class UserRepository(BaseRepository[User]):
    """Users within one tenant."""

    model = User
    selectin_loads = (selectinload(User.roles).selectinload(UserRole.role),)
    sortable_fields = ("created_at", "updated_at", "email", "full_name", "status")
    resource_name = "user"

    def _visible_query(self) -> Select:
        """
        Users that are not soft-deleted.

        ``User`` carries ``TenantScopedMixin`` and ``TimestampMixin``; the
        soft-delete filter is applied here rather than in ``_base_query`` so a
        caller that genuinely needs deleted rows (a retention job, a restore) can
        ask for them explicitly.
        """
        return self._base_query().where(User.deleted_at.is_(None))

    async def get_active(self, user_id: UUID) -> User | None:
        result = await self.session.execute(
            self._visible_query().where(User.id == user_id)
        )
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """
        The user with this email **in this tenant**.

        Compared case-insensitively, because the database enforces uniqueness on
        ``lower(email)`` and a case-sensitive lookup here would fail to find a user
        the schema considers a duplicate of an existing one.
        """
        result = await self.session.execute(
            self._visible_query().where(func.lower(User.email) == email.strip().lower())
        )
        return result.scalar_one_or_none()

    async def list_users(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        sort: tuple[str, ...] = (),
        status: str | None = None,
        search: str | None = None,
        role_code: str | None = None,
    ):
        """
        One page of users, with the filters the user-management screen offers.

        ``search`` matches name or email with a case-insensitive substring. It is
        escaped before use: ``ILIKE`` treats ``%`` and ``_`` as wildcards, and an
        unescaped user-supplied pattern would let a caller widen their own search
        to "everyone" or slow the query with a leading wildcard.
        """
        query = self._visible_query()
        if status:
            query = query.where(User.status == status)
        if search:
            pattern = f"%{_escape_like(search.strip().lower())}%"
            query = query.where(
                func.lower(User.email).ilike(pattern, escape="\\")
                | func.lower(User.full_name).ilike(pattern, escape="\\")
            )
        if role_code:
            query = query.where(
                User.id.in_(
                    select(UserRole.user_id)
                    .join(Role, Role.id == UserRole.role_id)
                    .where(Role.code == role_code, Role.tenant_id == self.tenant_id)
                )
            )
        total = int(
            (await self.session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        )
        query = self._apply_sort(query, sort)
        result = await self.session.execute(query.limit(page_size).offset((page - 1) * page_size))
        from app.repositories.base import PaginationResult

        return PaginationResult(
            list(result.scalars().unique().all()),
            page=page,
            page_size=page_size,
            total=total,
        )

    async def count_admins(self) -> int:
        """How many users hold a role with ``roles.assign.elevate`` — used to refuse removing the last one."""
        result = await self.session.execute(
            select(func.count(func.distinct(User.id)))
            .join(UserRole, UserRole.user_id == User.id)
            .join(Role, Role.id == UserRole.role_id)
            .join(RolePermission, RolePermission.role_id == Role.id)
            .join(Permission, Permission.id == RolePermission.permission_id)
            .where(
                User.tenant_id == self.tenant_id,
                User.deleted_at.is_(None),
                Permission.code == "roles.assign.elevate",
            )
        )
        return int(result.scalar_one())


def _escape_like(value: str) -> str:
    """Escape ``LIKE`` wildcards so a search term is matched literally."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


class RoleRepository(BaseRepository[Role]):
    """Roles within one tenant."""

    model = Role
    selectin_loads = (selectinload(Role.permissions),)
    sortable_fields = ("created_at", "updated_at", "code", "name", "level")
    resource_name = "role"

    async def get_by_code(self, code: str) -> Role | None:
        result = await self.session.execute(
            self._base_query().where(Role.code == code, Role.deleted_at.is_(None))
        )
        return result.scalars().unique().one_or_none()

    async def permission_codes(self, role_id: UUID) -> frozenset[str]:
        """The permission codes a role grants, read from the join table."""
        result = await self.session.execute(
            select(Permission.code)
            .join(RolePermission, RolePermission.permission_id == Permission.id)
            .where(RolePermission.role_id == role_id, RolePermission.tenant_id == self.tenant_id)
        )
        return frozenset(result.scalars().all())


class SessionRepository(BaseRepository[Session]):
    """Refresh-token sessions."""

    model = Session
    sortable_fields = ("issued_at", "expires_at", "last_used_at")
    resource_name = "session"

    async def get_live(self, session_id: UUID) -> Session | None:
        """A session that has not been revoked and has not expired."""
        result = await self.session.execute(
            self._base_query().where(
                Session.id == session_id,
                Session.revoked_at.is_(None),
                Session.expires_at > _now(),
            )
        )
        return result.scalar_one_or_none()

    async def find_by_refresh_hash(self, token_hash: str) -> Session | None:
        result = await self.session.execute(
            self._base_query().where(Session.refresh_token_hash == token_hash)
        )
        return result.scalars().one_or_none()

    async def list_for_user(self, user_id: UUID, *, include_revoked: bool = False) -> list[Session]:
        query = self._base_query().where(Session.user_id == user_id)
        if not include_revoked:
            query = query.where(Session.revoked_at.is_(None))
        result = await self.session.execute(query.order_by(Session.issued_at.desc()))
        return list(result.scalars().all())

    async def revoke_family(self, family_id: UUID, *, reason: str) -> int:
        """
        Revoke every session in a rotation family.

        Called when a refresh token is replayed. The only honest explanation for a
        replayed token is that it was stolen, so the whole family goes: keeping the
        newest session alive would leave the attacker with the working credential
        and the legitimate user locked out of the decision.
        """
        sessions = (
            await self.session.execute(
                self._base_query().where(
                    Session.family_id == family_id, Session.revoked_at.is_(None)
                )
            )
        ).scalars().all()
        now = _now()
        for session in sessions:
            session.revoked_at = now
            session.revoked_reason = reason
        await self.session.flush()
        return len(sessions)


class ApiKeyRepository(BaseRepository[ApiKey]):
    """API keys (device gateways and partner integrations) within one tenant."""

    model = ApiKey
    sortable_fields = ("created_at", "name", "last_used_at", "expires_at")
    resource_name = "api key"

    async def find_by_prefix(self, key_prefix: str) -> ApiKey | None:
        """
        The key whose visible prefix matches.

        The prefix is unique across the platform, so this is the lookup an
        authenticating device gateway performs before the hash comparison. It is
        tenant-scoped, which is correct: a key presented to the wrong tenant is
        simply not found.
        """
        result = await self.session.execute(
            self._base_query().where(ApiKey.key_prefix == key_prefix)
        )
        return result.scalars().one_or_none()


class AuditLogRepository(BaseRepository[AuditLog]):
    """
    The append-only audit trail.

    Note what is absent: no ``update`` and no ``soft_delete``. ``audit_logs`` has
    no ``updated_at`` and no ``deleted_at``, so there is nothing here to override —
    immutability is structural rather than promised. Retention is an archival job
    that copies rows out before any deletion, and that job lives in the workers
    layer, not here.
    """

    model = AuditLog
    sortable_fields = ("created_at", "action", "resource_type")
    resource_name = "audit log"

    async def record(
        self,
        *,
        action: str,
        actor: object,
        resource_type: str | None = None,
        resource_id: str | None = None,
        outcome: str = "SUCCESS",
        changes: dict | None = None,
        request_id: str | None = None,
        ip_address: str | None = None,
        user_agent: str | None = None,
        metadata: dict | None = None,
    ) -> AuditLog:
        """
        Append one audit row.

        ``actor`` is the :class:`~app.authorization.context.Actor` that performed
        the action, and only its identity is recorded — never a token, never a
        credential. ``metadata`` is the caller's structured detail and is stored as
        JSONB; it must not contain secrets, and ``tests/architecture``'s secret
        scanner is the backstop for that.
        """
        entry = AuditLog(
            tenant_id=self.tenant_id,
            actor_user_id=getattr(actor, "user_id", None),
            actor_type=getattr(actor, "auth_type", "USER"),
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            changes=changes,
            request_id=request_id,
            ip_address=ip_address,
            user_agent=user_agent,
            event_metadata=metadata,
        )
        self.session.add(entry)
        await self.session.flush()
        return entry

    async def list_recent(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        resource_type: str | None = None,
        resource_id: str | None = None,
        actor_user_id: UUID | None = None,
        action: str | None = None,
        from_time: datetime | None = None,
        to_time: datetime | None = None,
    ):
        from app.repositories.base import PaginationResult

        query = self._base_query()
        if resource_type:
            query = query.where(AuditLog.resource_type == resource_type)
        if resource_id:
            query = query.where(AuditLog.resource_id == resource_id)
        if actor_user_id:
            query = query.where(AuditLog.actor_user_id == actor_user_id)
        if action:
            query = query.where(AuditLog.action == action)
        if from_time:
            query = query.where(AuditLog.created_at >= from_time)
        if to_time:
            query = query.where(AuditLog.created_at <= to_time)
        total = int(
            (await self.session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        )
        query = query.order_by(AuditLog.created_at.desc())
        result = await self.session.execute(query.limit(page_size).offset((page - 1) * page_size))
        return PaginationResult(
            list(result.scalars().all()), page=page, page_size=page_size, total=total
        )


class TenantRepository(PlatformRepository[Tenant]):
    """
    The tenant registry.

    Platform-scoped: a tenant row is not owned by a tenant, it *is* one. Access is
    decided by platform-level authorization (``platform.tenants.*``), not by
    row-level security, which is why ``tenants`` appears in
    ``app.db.rls.GLOBAL_TABLES``.
    """

    model = Tenant
    sortable_fields = ("created_at", "name", "slug", "status")
    resource_name = "tenant"

    async def get_by_slug(self, slug: str) -> Tenant | None:
        result = await self.session.execute(
            self._base_query().where(Tenant.slug == slug, Tenant.deleted_at.is_(None))
        )
        return result.scalars().one_or_none()

    async def list_active(self, *, page: int = 1, page_size: int = 100):
        from app.repositories.base import PaginationResult

        query = self._base_query().where(Tenant.deleted_at.is_(None))
        total = int(
            (await self.session.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
        )
        result = await self.session.execute(
            query.order_by(Tenant.name).limit(page_size).offset((page - 1) * page_size)
        )
        return PaginationResult(
            list(result.scalars().all()), page=page, page_size=page_size, total=total
        )


class PermissionRepository(PlatformRepository[Permission]):
    """The permission catalogue. Global: a code is platform-wide vocabulary."""

    model = Permission
    sortable_fields = ("code", "resource", "action")
    resource_name = "permission"


def _now() -> datetime:
    from app.core.time import utc_now

    return utc_now()
