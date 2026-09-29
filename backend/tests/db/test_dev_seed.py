"""The seed is repeatable, keeps changed access intact and never runs in production."""

from __future__ import annotations

import asyncio
import json
import secrets
import stat

import pytest
from argon2 import PasswordHasher
from sqlalchemy import delete, func, select

from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.models._enums import UserStatus
from app.models.identity import AuditLog, Permission, Role, RolePermission, Tenant, User, UserRole
from app.scripts.seed import (
    DEV_ADMIN_ID,
    DEV_EMAIL,
    DEV_SLUG,
    DEV_TENANT_ID,
    initial_credentials,
    run_seed,
    seed_dev,
)

pytestmark = pytest.mark.db


@pytest.fixture
async def clean_seed(db_session):
    yield
    await db_session.rollback()
    for model in (AuditLog, UserRole, RolePermission, Role, User):
        await db_session.execute(delete(model).where(model.tenant_id == DEV_TENANT_ID))
    await db_session.execute(delete(Tenant).where(Tenant.id == DEV_TENANT_ID))
    await db_session.commit()


async def test_seed_creates_only_tenant_roles_and_a_usable_admin(
    db_session, test_settings, clean_seed, client
):
    password = secrets.token_urlsafe(32)
    result = await seed_dev(db_session, test_settings, password)
    assert result.created
    await db_session.commit()
    roles = (
        (await db_session.execute(select(Role).where(Role.tenant_id == DEV_TENANT_ID)))
        .scalars()
        .all()
    )
    assert {r.code for r in roles} == set(ROLE_DEFINITIONS) - {"SUPER_ADMIN"}
    assert not any(r.is_system for r in roles)
    for role in roles:
        codes = (
            (
                await db_session.execute(
                    select(Permission.code)
                    .join(RolePermission)
                    .where(RolePermission.role_id == role.id)
                )
            )
            .scalars()
            .all()
        )
        assert set(codes) == ROLE_DEFINITIONS[role.code].permissions
    login = await client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": DEV_SLUG, "email": DEV_EMAIL, "password": password},
    )
    assert login.status_code == 200, login.text
    response = await client.get(
        "/api/v1/users", headers={"Authorization": "Bearer " + login.json()["access_token"]}
    )
    assert response.status_code == 200, response.text
    assert response.json()["meta"]["total_items"] == 1
    audits = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.action == "tenant.dev_seed", AuditLog.tenant_id == DEV_TENANT_ID
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(audits) == 1
    assert audits[0].actor_user_id is None
    assert audits[0].actor_type == "SYSTEM"
    assert password not in json.dumps(audits[0].event_metadata)


async def test_rerun_never_resets_password_reactivates_or_regrants_access(
    db_session, test_settings, clean_seed
):
    await seed_dev(db_session, test_settings, secrets.token_urlsafe(32))
    await db_session.commit()
    user = await db_session.get(User, DEV_ADMIN_ID)
    new_hash = PasswordHasher(time_cost=1, memory_cost=8192).hash(secrets.token_urlsafe(32))
    user.password_hash = new_hash
    user.status = UserStatus.DISABLED
    await db_session.execute(delete(UserRole).where(UserRole.user_id == DEV_ADMIN_ID))
    tenant = await db_session.get(Tenant, DEV_TENANT_ID)
    tenant.name = "Customized"
    await db_session.commit()
    result = await seed_dev(db_session, test_settings, secrets.token_urlsafe(32))
    await db_session.commit()
    assert not result.created
    await db_session.refresh(user)
    await db_session.refresh(tenant)
    assert user.password_hash == new_hash
    assert user.status == UserStatus.DISABLED
    assert tenant.name == "Customized"
    assert (
        await db_session.execute(
            select(func.count()).select_from(UserRole).where(UserRole.user_id == DEV_ADMIN_ID)
        )
    ).scalar_one() == 0


@pytest.mark.parametrize("environment", ["production", "staging"])
async def test_dev_seed_refuses_production_before_touching_db_or_files(
    test_settings, tmp_path, environment
):
    settings = test_settings.model_copy(update={"environment": environment})
    path = tmp_path / "credentials.json"
    with pytest.raises(RuntimeError, match="forbidden"):
        await run_seed(settings, path)
    assert not path.exists()


async def test_seed_cli_path_is_idempotent_and_private(test_settings, clean_seed, tmp_path):
    path = tmp_path / "credentials.json"
    first = await run_seed(test_settings, path)
    assert first.created
    original = path.read_bytes()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    second = await run_seed(test_settings, path)
    assert not second.created
    assert path.read_bytes() == original
    path.unlink()
    third = await run_seed(test_settings, path)
    assert not third.created
    assert not path.exists(), "Must not invent a password for an existing account"


async def test_concurrent_seed_is_atomic(test_settings, clean_seed, tmp_path):
    path = tmp_path / "credentials.json"
    results = await asyncio.gather(run_seed(test_settings, path), run_seed(test_settings, path))
    assert sorted(result.created for result in results) == [False, True]
    assert path.exists()


@pytest.mark.parametrize("unsafe", ["public", "symlink"])
def test_credential_file_rejects_unsafe_permissions_and_symlinks(tmp_path, unsafe):
    path = tmp_path / "credentials.json"
    initial_credentials(path)
    if unsafe == "public":
        path.chmod(0o644)
        with pytest.raises(RuntimeError, match="private"):
            initial_credentials(path)
    else:
        link = tmp_path / "link.json"
        link.symlink_to(path)
        with pytest.raises(OSError):
            initial_credentials(link)
