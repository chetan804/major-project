"""Idempotent, development-only identity seed. No fabricated operational data.

Run through bootstrap or ``make seed``. Initial login details are kept in an
ignored, mode-0600 local file, never printed. Re-running does not reset passwords,
reactivate disabled users, repair revoked roles or overwrite tenant customizations.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path
from uuid import UUID

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.config import Settings, get_settings
from app.core.errors import ConflictError
from app.db.rls import apply_tenant_context
from app.db.session import Database
from app.models._enums import PermissionScope, TenantStatus, TenantType, UserStatus
from app.models.identity import Permission, Role, RolePermission, Tenant, User, UserRole
from app.repositories.identity import (
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)
from app.scripts.seed_catalogue import deterministic_id
from app.services.auth import AnonymousActor, AuthService

DEV_SLUG = "ecomind-dev"
DEV_EMAIL = "admin@ecomind.test"
DEV_TENANT_ID = deterministic_id("dev", "tenant")
DEV_ADMIN_ID = deterministic_id("dev", "admin")
CREDENTIALS_PATH = Path(__file__).resolve().parents[3] / ".runtime" / "dev-account.json"


@dataclass(frozen=True)
class SeedResult:
    tenant_id: UUID
    user_id: UUID
    created: bool


def require_development(settings: Settings) -> None:
    if settings.environment not in ("development", "test"):
        raise RuntimeError("The dev seed is forbidden outside development/test environments.")


async def seed_dev(session: AsyncSession, settings: Settings, password: str) -> SeedResult:
    """Provision one dev tenant atomically; caller commits or rolls back."""
    require_development(settings)
    # Serialize initial provisioning before there is a tenant row to lock.
    await session.execute(text("SELECT pg_advisory_xact_lock(761834201)"))
    await apply_tenant_context(session, DEV_TENANT_ID)
    existing = (
        (
            await session.execute(
                select(Tenant).where((Tenant.id == DEV_TENANT_ID) | (Tenant.slug == DEV_SLUG))
            )
        )
        .scalars()
        .all()
    )
    if existing:
        if len(existing) != 1 or existing[0].id != DEV_TENANT_ID or existing[0].slug != DEV_SLUG:
            raise ConflictError(
                message="The development tenant slug or identifier is already in use."
            )
        admin = await session.get(User, DEV_ADMIN_ID)
        if admin is None or admin.tenant_id != DEV_TENANT_ID:
            raise ConflictError(
                message="The dev tenant exists without its seed account; refusing to repair access automatically."
            )
        return SeedResult(DEV_TENANT_ID, DEV_ADMIN_ID, False)

    auth = AuthService(
        settings=settings,
        users=UserRepository(session, DEV_TENANT_ID),
        sessions=SessionRepository(session, DEV_TENANT_ID),
        audit=AuditLogRepository(session, DEV_TENANT_ID),
        tenants=TenantRepository(session),
    )
    password_hash = auth.hash_password(password)
    permissions = {p.code: p for p in (await session.execute(select(Permission))).scalars()}
    session.add(
        Tenant(
            id=DEV_TENANT_ID,
            name="EcoMind Development",
            slug=DEV_SLUG,
            type=TenantType.MUNICIPALITY,
            status=TenantStatus.ACTIVE,
            timezone="Asia/Kolkata",
        )
    )
    await session.flush()
    admin_role_id: UUID | None = None
    for definition in ROLE_DEFINITIONS.values():
        if definition.code == "SUPER_ADMIN":
            continue
        if any(
            code not in permissions or permissions[code].scope != PermissionScope.TENANT
            for code in definition.permissions
        ):
            raise RuntimeError(
                "Seed permission catalogue is missing or contains non-tenant grants; run migrations first."
            )
        role_id = deterministic_id("dev", "role", definition.code)
        session.add(
            Role(
                id=role_id,
                tenant_id=DEV_TENANT_ID,
                code=definition.code,
                name=definition.name,
                description=definition.description,
                level=definition.level,
                is_system=False,
                is_default=definition.is_default,
            )
        )
        await session.flush()
        for code in sorted(definition.permissions):
            session.add(
                RolePermission(
                    tenant_id=DEV_TENANT_ID, role_id=role_id, permission_id=permissions[code].id
                )
            )
        if definition.code == "TENANT_ADMIN":
            admin_role_id = role_id
    if admin_role_id is None:
        raise RuntimeError("Tenant administrator role is missing from the seed definitions.")
    session.add(
        User(
            id=DEV_ADMIN_ID,
            tenant_id=DEV_TENANT_ID,
            email=DEV_EMAIL,
            full_name="Development Administrator",
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
        )
    )
    await session.flush()
    session.add(UserRole(user_id=DEV_ADMIN_ID, role_id=admin_role_id, tenant_id=DEV_TENANT_ID))
    await session.flush()
    await AuditLogRepository(session, DEV_TENANT_ID).record(
        action="tenant.dev_seed",
        actor=AnonymousActor(user_id=None, auth_type="SYSTEM"),
        resource_type="tenant",
        resource_id=str(DEV_TENANT_ID),
        metadata={"profile": "dev"},
    )
    return SeedResult(DEV_TENANT_ID, DEV_ADMIN_ID, True)


def initial_credentials(path: Path) -> str:
    """Create once using exclusive/no-follow open; reuse the initial local secret.

    This happens before DB provisioning. If the transaction fails, a retry reuses
    the same secret. A successful seed followed by a lost console connection can
    therefore never leave an account whose generated password was lost.
    """
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) & 0o077:
                raise RuntimeError(
                    "Dev credentials must be a private regular file (mode 0600)."
                ) from None
            data = json.load(source)
        if data.get("tenant_slug") != DEV_SLUG or data.get("email") != DEV_EMAIL:
            raise RuntimeError("Dev credentials file belongs to a different account.") from None
        password = data.get("password")
        if not isinstance(password, str) or len(password) < 12:
            raise RuntimeError("Dev credentials file has an invalid password.") from None
        return password
    password = secrets.token_urlsafe(32)
    with os.fdopen(fd, "w") as destination:
        json.dump({"tenant_slug": DEV_SLUG, "email": DEV_EMAIL, "password": password}, destination)
        destination.write("\n")
        destination.flush()
        os.fsync(destination.fileno())
    return password


async def run_seed(settings: Settings, path: Path = CREDENTIALS_PATH) -> SeedResult:
    require_development(settings)
    database = Database(settings.database_url, use_null_pool=True)
    try:
        async with database.session() as session:
            # Check under the same seed lock *before* writing a credential file.
            # Losing the file must never generate a fake password for an account
            # that already exists and whose password the seed will not reset.
            await session.execute(text("SELECT pg_advisory_xact_lock(761834201)"))
            existing = (
                await session.execute(
                    select(Tenant.id).where(
                        (Tenant.id == DEV_TENANT_ID) | (Tenant.slug == DEV_SLUG)
                    )
                )
            ).first()
            password = initial_credentials(path) if existing is None else ""
            result = await seed_dev(session, settings, password)
            await session.commit()
        return result
    finally:
        await database.dispose()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["dev"], required=True)
    parser.parse_args()
    result = asyncio.run(run_seed(get_settings()))
    print(
        "Development identity created."
        if result.created
        else "Development account already exists; no credentials or grants were changed."
    )
    if CREDENTIALS_PATH.exists():
        print(f"Initial local login details: {CREDENTIALS_PATH} (private, ignored by Git).")
        print(
            "The file contains the initial password only; later password changes are not overwritten."
        )
    else:
        print(
            "No local credentials file exists. Use account recovery; the seed will not reset access."
        )
    print("No bins, telemetry, model evaluations or accuracy claims were generated.")


if __name__ == "__main__":
    main()
