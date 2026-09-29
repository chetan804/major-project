"""Offline first-operator bootstrap, never an HTTP enrollment or account repair path.

Run with controlled database access and a real interactive terminal. Passwords
are read twice using getpass, not flags/environment/files. No default operator is
created by migrations, development seed or application startup.
"""

from __future__ import annotations

import argparse
import asyncio
import getpass
import sys
import warnings
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.resolution import resolve_permissions
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.db.session import Database
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import Role, Tenant, User, UserRole
from app.repositories.identity import AuditLogRepository
from app.services.auth import AnonymousActor
from app.services.platform_access import auth_for
from app.services.platform_tenants import (
    validate_operator_email,
    validate_operator_reason,
)


async def bootstrap_operator(
    session: AsyncSession,
    settings: Settings,
    *,
    email: str,
    full_name: str,
    password: str,
    reason: str,
) -> UUID:
    """Caller owns commit/rollback. Refuse any pre-existing platform User row."""
    email = validate_operator_email(email)
    reason = validate_operator_reason(reason)
    if not full_name.strip() or len(full_name) > 200:
        raise ConflictError(message="A valid operator name is required.")
    await apply_tenant_context(session, PLATFORM_SCOPE_ID)
    platform = (
        await session.execute(
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
        raise ConflictError(
            message="The active platform registry must be provisioned by migrations."
        )
    if (
        await session.execute(select(User.id).where(User.tenant_id == PLATFORM_SCOPE_ID).limit(1))
    ).first():
        raise ConflictError(
            message="Platform accounts already exist; bootstrap will not repair or add access."
        )
    role = (
        await session.execute(
            select(Role).where(
                Role.tenant_id == PLATFORM_SCOPE_ID,
                Role.code == "SUPER_ADMIN",
                Role.is_system.is_(True),
            )
        )
    ).scalar_one_or_none()
    if role is None:
        raise ConflictError(message="Platform role catalogue is missing.")
    user = User(
        tenant_id=PLATFORM_SCOPE_ID,
        email=email,
        full_name=full_name.strip(),
        status=UserStatus.ACTIVE,
        password_hash=auth_for(session, settings, PLATFORM_SCOPE_ID).hash_password(password),
    )
    session.add(user)
    await session.flush()
    session.add(UserRole(tenant_id=PLATFORM_SCOPE_ID, user_id=user.id, role_id=role.id))
    await session.flush()
    _, permissions = await resolve_permissions(session, PLATFORM_SCOPE_ID, user.id)
    if permissions != ROLE_DEFINITIONS["SUPER_ADMIN"].permissions:
        raise ConflictError(message="Platform role catalogue does not match the reviewed baseline.")
    await AuditLogRepository(session, PLATFORM_SCOPE_ID).record(
        action="platform.operator.bootstrap",
        actor=AnonymousActor(None, "SYSTEM"),
        resource_type="user",
        resource_id=str(user.id),
        metadata={"reason": reason, "source": "offline_cli"},
    )
    return user.id


async def run(email: str, name: str, password: str, reason: str) -> UUID:
    settings = get_settings()
    database = Database(settings.database_url, use_null_pool=True)
    try:
        async with database.session() as session:
            user_id = await bootstrap_operator(
                session, settings, email=email, full_name=name, password=password, reason=reason
            )
            await session.commit()
            return user_id
    finally:
        await database.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--reason", required=True)
    args = parser.parse_args()
    if not sys.stdin.isatty():
        parser.error(
            "An interactive terminal is required; password arguments/pipes are not supported."
        )
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        try:
            password = getpass.getpass("Initial operator password: ")
            confirmation = getpass.getpass("Confirm password: ")
        except getpass.GetPassWarning:
            parser.error("A terminal with disabled password echo is required.")
    if password != confirmation:
        parser.error("Passwords do not match.")
    try:
        user_id = asyncio.run(run(args.email, args.name, password, args.reason))
    except Exception:
        # No traceback with database parameters or accidental credential context.
        parser.exit(
            1,
            "Bootstrap failed; no success is claimed. Review database state and the documented prerequisites.\n",
        )
    print(f"Created first platform operator {user_id}. Sign in under ecomind-platform.")


if __name__ == "__main__":
    main()
