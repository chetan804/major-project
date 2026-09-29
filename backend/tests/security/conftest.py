"""Real HTTP authentication against PostgreSQL as a NON-superuser.

No actor/session dependency is mocked. Only the database binding is replaced,
so token validation, the transaction error path and forced RLS all run for real.
"""

from __future__ import annotations

import secrets
from types import SimpleNamespace
from uuid import uuid4

import pytest
from argon2 import PasswordHasher
from sqlalchemy import delete, func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker

from app.api.deps import get_database_dep
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.models._enums import TenantStatus, TenantType, UserStatus
from app.models.auth_mail import AuthMail
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

from .support import bearer, login

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


@pytest.fixture
async def auth_env(client, app, db_session, rls_engine, rls_role, test_settings):
    # These grants are only on the throwaway database. The role has neither
    # superuser nor BYPASSRLS, and every new connection uses that role directly.
    await db_session.execute(
        text(
            f"GRANT SELECT, INSERT, UPDATE ON users, sessions, roles, api_keys, auth_mail_outbox, "
            f'role_permissions, user_roles TO "{rls_role}"'
        )
    )
    # Invitation guards take the tenant mutex; row locks require UPDATE privilege.
    await db_session.execute(text(f'GRANT SELECT, UPDATE ON tenants TO "{rls_role}"'))
    await db_session.execute(text(f'GRANT SELECT ON permissions TO "{rls_role}"'))
    await db_session.execute(text(f'GRANT SELECT, INSERT ON audit_logs TO "{rls_role}"'))
    await db_session.execute(text(f'REVOKE UPDATE, DELETE ON audit_logs FROM "{rls_role}"'))
    await db_session.execute(text(f'GRANT USAGE ON SEQUENCE audit_logs_id_seq TO "{rls_role}"'))
    test_settings.argon2_time_cost = 1
    test_settings.argon2_memory_cost_kib = 8192
    test_settings.argon2_parallelism = 1
    password = "  " + secrets.token_urlsafe(24) + "  "
    password_hash = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1).hash(password)
    tenants = [
        Tenant(
            id=uuid4(),
            slug=f"auth-{uuid4().hex}",
            name="Auth test",
            type=TenantType.MUNICIPALITY,
            status=TenantStatus.ACTIVE,
        )
        for _ in range(2)
    ]
    db_session.add_all(tenants)
    await db_session.flush()
    users = [
        User(
            id=uuid4(),
            tenant_id=t.id,
            email="member@example.test",
            full_name="Test member",
            password_hash=password_hash,
            status=UserStatus.ACTIVE,
        )
        for t in tenants
    ]
    colleague = User(
        id=uuid4(),
        tenant_id=tenants[0].id,
        email="colleague@example.test",
        full_name="Colleague",
        password_hash=password_hash,
        status=UserStatus.ACTIVE,
    )
    db_session.add_all([*users, colleague])
    await db_session.commit()
    tenant_ids = [t.id for t in tenants]
    factory = async_sessionmaker(rls_engine, expire_on_commit=False)
    bindings = []

    def restricted_database():
        bindings.append(True)
        return SimpleNamespace(session=factory)

    app.dependency_overrides[get_database_dep] = restricted_database
    env = SimpleNamespace(
        client=client,
        tenants=tenants,
        users=users,
        colleague=colleague,
        password=password,
        factory=factory,
        settings=test_settings,
        bindings=bindings,
    )
    try:
        async with factory() as session:
            privileged = (
                await session.execute(
                    text(
                        "SELECT rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = current_user"
                    )
                )
            ).scalar_one()
            assert not privileged
            assert (await session.execute(select(func.count()).select_from(User))).scalar_one() == 0
        yield env
    finally:
        app.dependency_overrides.pop(get_database_dep)
        await db_session.rollback()
        for model in (AuthMail, AuditLog, ApiKey, Session, UserRole, RolePermission, Role, User):
            await db_session.execute(delete(model).where(model.tenant_id.in_(tenant_ids)))
        await db_session.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
        await db_session.commit()


@pytest.fixture
async def admin_env(auth_env, db_session, rls_role):
    env = auth_env
    await db_session.execute(text(f'GRANT UPDATE ON tenants TO "{rls_role}"'))
    await db_session.execute(text(f'GRANT DELETE ON user_roles, role_permissions TO "{rls_role}"'))
    permissions = {p.code: p.id for p in (await db_session.execute(select(Permission))).scalars()}
    env.roles = {}
    for tenant in env.tenants:
        for definition in ROLE_DEFINITIONS.values():
            if definition.code == "SUPER_ADMIN":
                continue
            role = Role(
                id=uuid4(),
                tenant_id=tenant.id,
                code=definition.code,
                name=definition.name,
                is_default=definition.is_default,
                level=definition.level,
                is_system=False,
            )
            db_session.add(role)
            await db_session.flush()
            for code in definition.permissions:
                db_session.add(
                    RolePermission(
                        tenant_id=tenant.id, role_id=role.id, permission_id=permissions[code]
                    )
                )
            env.roles[tenant.id, role.code] = role
    for user in env.users:
        db_session.add(
            UserRole(
                user_id=user.id,
                tenant_id=user.tenant_id,
                role_id=env.roles[user.tenant_id, "TENANT_ADMIN"].id,
            )
        )
    db_session.add(
        UserRole(
            user_id=env.colleague.id,
            tenant_id=env.colleague.tenant_id,
            role_id=env.roles[env.colleague.tenant_id, "VIEWER"].id,
        )
    )
    await db_session.commit()
    env.headers = bearer((await login(env)).json())
    return env
