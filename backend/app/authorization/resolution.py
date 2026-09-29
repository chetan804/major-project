"""
Permission resolution: turning a user's role grants into a permission set.

This sits in the authorization layer (below services) because two callers need it
for different reasons and neither should reach *up* to get it:

* the API dependency that builds the request actor;
* the authentication service, which builds an actor immediately after sign-in so
  the response can report the caller's own permissions.

Both must see the same answer, so the query lives in exactly one place. It is
resolved per request rather than cached, because a revoked grant has to take
effect on the next request rather than whenever a cache expires.
"""

from __future__ import annotations

from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.models._enums import PermissionScope
from app.models.identity import Permission, Role, RolePermission, UserRole

__all__ = ["resolve_permissions"]


async def resolve_permissions(
    session: AsyncSession,
    tenant_id: UUID,
    user_id: UUID,
) -> tuple[frozenset[str], frozenset[str]]:
    """
    The role codes and permission codes a user holds *in one tenant*.

    Expired role grants are excluded here rather than at assignment time, so a
    time-boxed contractor grant stops working on its own without a job to clean up
    after it.

    The permission codes are read from the ``permissions`` table rather than taken
    from the role definition in code, because a tenant may edit its cloned roles:
    what a user holds is whatever the database says, not what the seed said.
    """
    statement = (
        select(Role.code, Permission.code)
        .join(UserRole, UserRole.role_id == Role.id)
        .outerjoin(
            RolePermission,
            (RolePermission.role_id == Role.id) & (RolePermission.tenant_id == Role.tenant_id),
        )
        .outerjoin(
            Permission,
            (Permission.id == RolePermission.permission_id)
            & (
                Permission.scope
                == (
                    PermissionScope.PLATFORM
                    if tenant_id == PLATFORM_SCOPE_ID
                    else PermissionScope.TENANT
                )
            ),
        )
        .where(
            UserRole.user_id == user_id,
            UserRole.tenant_id == tenant_id,
            Role.tenant_id == tenant_id,
            (UserRole.expires_at.is_(None)) | (UserRole.expires_at > utc_now()),
        )
    )
    role_codes: set[str] = set()
    permission_codes: set[str] = set()
    for role_code, permission_code in (await session.execute(statement)).all():
        role_codes.add(str(role_code))
        if permission_code is not None:
            permission_codes.add(str(permission_code))
    return frozenset(role_codes), frozenset(permission_codes)
