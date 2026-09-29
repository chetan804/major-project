"""Platform control plane under restricted PostgreSQL, real login and forced RLS."""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import replace
from datetime import timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select, text, update

from app.authorization.context import Actor
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.errors import AuthenticationError, ConflictError, PermissionDeniedError
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.db.rls import apply_tenant_context
from app.integrations.auth_mail import transport_for
from app.models._enums import TenantStatus, UserStatus
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
from app.repositories.identity import AuditLogRepository
from app.scripts.bootstrap_operator import bootstrap_operator
from app.services.auth_delivery import AuthDelivery
from app.services.platform_tenants import PlatformTenantService

from .support import bearer, login, refresh, service
from .test_auth_delivery import decrypt

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]
REASON = {"reason": "Approved operator change for lifecycle testing"}
BASE = "/api/v1/platform/tenants"


@pytest.fixture
async def platform_env(admin_env, db_session, rls_role):
    env = admin_env
    await db_session.execute(text(f'GRANT INSERT ON tenants TO "{rls_role}"'))
    await db_session.commit()
    env.created_ids = []
    env.extra_roles = []
    env.operator_email = "operator@example.test"
    async with env.factory() as session:
        env.operator_id = await bootstrap_operator(
            session,
            env.settings,
            email=env.operator_email,
            full_name="Test operator",
            password=env.password,
            **REASON,
        )
        await session.commit()
    response = await env.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "ecomind-platform",
            "email": env.operator_email,
            "password": env.password,
        },
    )
    assert response.status_code == 200, response.text
    env.operator_tokens = response.json()
    env.operator_headers = bearer(env.operator_tokens)
    env.operator = Actor(
        user_id=env.operator_id,
        tenant_id=PLATFORM_SCOPE_ID,
        email=env.operator_email,
        full_name="Test operator",
        permissions=ROLE_DEFINITIONS["SUPER_ADMIN"].permissions,
        session_id=UUID(env.operator_tokens["session_id"]),
        is_platform_operator=True,
    )
    try:
        confirmed = await env.client.post(
            "/api/v1/platform/auth/step-up",
            headers=env.operator_headers,
            json={"password": env.password},
        )
        assert confirmed.status_code == 200, confirmed.text
        yield env
    finally:
        await db_session.rollback()
        for model in (AuthMail, AuditLog, ApiKey, Session, UserRole):
            await db_session.execute(
                delete(model).where(model.tenant_id.in_([PLATFORM_SCOPE_ID, *env.created_ids]))
            )
        await db_session.execute(
            delete(RolePermission).where(RolePermission.role_id.in_(env.extra_roles))
        )
        await db_session.execute(delete(Role).where(Role.id.in_(env.extra_roles)))
        for model in (RolePermission, Role):
            await db_session.execute(delete(model).where(model.tenant_id.in_(env.created_ids)))
        await db_session.execute(
            delete(User).where(User.tenant_id.in_([PLATFORM_SCOPE_ID, *env.created_ids]))
        )
        await db_session.execute(delete(Tenant).where(Tenant.id.in_(env.created_ids)))
        await db_session.commit()


def payload(**overrides):
    return {
        "slug": "ptest-" + uuid4().hex,
        "name": "New municipality",
        "type": "MUNICIPALITY",
        "admin_email": "New.Admin@example.test",
        "admin_name": "New administrator",
        **REASON,
        **overrides,
    }


async def create(env, **overrides):
    body = payload(**overrides)
    response = await env.client.post(BASE, headers=env.operator_headers, json=body)
    assert response.status_code == 201, response.text
    env.created_ids.append(UUID(response.json()["id"]))
    return response


async def delivered_code(env, row, expected_recipient="new.admin@example.test"):
    async with env.factory() as session:
        result = await AuthDelivery(session, env.settings).deliver_batch(
            row.tenant_id, transport_for(env.settings)
        )
        assert result["sent"] == 1
        await session.commit()
    path = Path(env.settings.auth_mailbox_root) / str(row.tenant_id) / f"{row.id}.eml"
    assert path.stat().st_mode & 0o777 == 0o600
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    assert message["To"] == expected_recipient
    return message.get_content().splitlines()[0].split(": ", 1)[1]


async def events(db, action):
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(
                    AuditLog.tenant_id == PLATFORM_SCOPE_ID,
                    AuditLog.action == "platform.tenant." + action,
                )
                .order_by(AuditLog.id)
            )
        ).scalars()
    )


async def test_provisioning_to_verified_administrator_login(platform_env, db_session, caplog):
    env = platform_env
    response = await create(env)
    tenant_id = UUID(response.json()["id"])
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["status"] == "ACTIVE"
    assert (
        not {"password", "password_hash", "token", "admin_email", "permissions"}
        & response.json().keys()
    )
    users = list(
        (await db_session.execute(select(User).where(User.tenant_id == tenant_id))).scalars()
    )
    assert len(users) == 1
    user = users[0]
    assert user.email == "new.admin@example.test" and user.status == UserStatus.INVITED
    roles = list(
        (await db_session.execute(select(Role).where(Role.tenant_id == tenant_id))).scalars()
    )
    assert {r.code for r in roles} == set(ROLE_DEFINITIONS) - {"SUPER_ADMIN"}
    assert (
        len(
            list(
                (
                    await db_session.execute(
                        select(UserRole).where(UserRole.tenant_id == tenant_id)
                    )
                ).scalars()
            )
        )
        == 1
    )
    outbox = (
        await db_session.execute(select(AuthMail).where(AuthMail.tenant_id == tenant_id))
    ).scalar_one()
    encrypted_token = decrypt(env, outbox)["token"]
    token = await delivered_code(env, outbox)
    assert token == encrypted_token
    assert token not in response.text + caplog.text
    assert (
        await env.client.post(
            "/api/v1/auth/email/verify-confirm",
            json={"tenant_slug": response.json()["slug"], "token": token},
        )
    ).status_code == 200
    # No known password was supplied by the operator: the admin sets their own.
    requested = await env.client.post(
        "/api/v1/auth/password-reset",
        json={"tenant_slug": response.json()["slug"], "email": user.email},
    )
    assert requested.status_code == 202
    reset_mail = (
        await db_session.execute(
            select(AuthMail).where(
                AuthMail.tenant_id == tenant_id, AuthMail.purpose == "PASSWORD_RESET"
            )
        )
    ).scalar_one()
    reset = await delivered_code(env, reset_mail)
    assert reset not in requested.text + caplog.text
    password = secrets.token_urlsafe(24)
    assert (
        await env.client.post(
            "/api/v1/auth/password-reset/confirm",
            json={"tenant_slug": response.json()["slug"], "token": reset, "new_password": password},
        )
    ).status_code == 200
    signed_in = await env.client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": response.json()["slug"], "email": user.email, "password": password},
    )
    assert signed_in.status_code == 200
    headers = bearer(signed_in.json())
    assert (await env.client.get("/api/v1/users", headers=headers)).status_code == 200
    assert (await env.client.get(BASE, headers=headers)).status_code == 403
    records = await events(db_session, "create")
    assert len(records) == 1 and records[0].actor_user_id == env.operator_id
    assert records[0].resource_id == str(tenant_id)
    assert records[0].event_metadata["reason"] == REASON["reason"]
    assert token not in json.dumps(records[0].event_metadata)


async def test_registry_paging_metadata_and_explicit_activation(platform_env, db_session):
    env = platform_env
    response = await create(env)
    row = response.json()
    listing = await env.client.get(BASE, headers=env.operator_headers, params={"page_size": 1})
    assert listing.status_code == 200 and listing.headers["cache-control"] == "no-store"
    assert listing.json()["items"][0]["id"] == row["id"]
    assert listing.json()["meta"]["total_items"] == 3
    detail = await env.client.get(BASE + "/" + row["id"], headers=env.operator_headers)
    assert detail.status_code == 200
    changed = await env.client.patch(
        BASE + "/" + row["id"],
        headers=env.operator_headers,
        json={
            **REASON,
            "name": "Updated registry",
            "timezone": "Europe/Amsterdam",
            "locale": "nl-NL",
        },
    )
    assert changed.status_code == 200 and changed.json()["name"] == "Updated registry"
    for suffix in ("suspend", "suspend", "activate", "activate"):
        changed = await env.client.post(
            BASE + "/" + row["id"] + "/" + suffix, headers=env.operator_headers, json=REASON
        )
        assert changed.status_code == 200
        assert changed.json()["status"] == ("SUSPENDED" if suffix == "suspend" else "ACTIVE")
    assert len(await events(db_session, "suspend")) == 2
    assert len(await events(db_session, "activate")) == 2
    assert len(await events(db_session, "list")) == 1
    assert len(await events(db_session, "read")) == 1


@pytest.mark.parametrize("role_code", [r for r in ROLE_DEFINITIONS if r != "SUPER_ADMIN"])
async def test_all_tenant_roles_denied_every_platform_route(platform_env, db_session, role_code):
    env = platform_env
    user = env.users[0]
    await db_session.execute(delete(UserRole).where(UserRole.user_id == user.id))
    db_session.add(
        UserRole(
            user_id=user.id,
            tenant_id=user.tenant_id,
            role_id=env.roles[user.tenant_id, role_code].id,
        )
    )
    await db_session.commit()
    headers = {**bearer((await login(env)).json()), "X-Tenant-ID": str(PLATFORM_SCOPE_ID)}
    target = BASE + "/" + str(env.tenants[1].id)
    for method, url, body in [
        ("GET", BASE, None),
        ("GET", target, None),
        ("POST", BASE, payload()),
        ("PATCH", target, {**REASON, "name": "Attack"}),
        ("POST", target + "/suspend", REASON),
        ("POST", target + "/activate", REASON),
    ]:
        result = await env.client.request(
            method, url, headers=headers, **({"json": body} if body else {})
        )
        assert result.status_code == 403
    assert await events(db_session, "create") == []


@pytest.mark.parametrize(
    "path", ["/users", "/roles", "/tenants/current", "/audit-logs", "/api-keys", "/sessions"]
)
async def test_platform_operator_cannot_browse_tenant_data(platform_env, path):
    env = platform_env
    result = await env.client.get(
        "/api/v1" + path, headers={**env.operator_headers, "X-Tenant-ID": str(env.tenants[0].id)}
    )
    assert result.status_code == 403
    async with env.factory() as session:
        await apply_tenant_context(session, PLATFORM_SCOPE_ID)
        assert (
            await session.execute(select(User).where(User.id == env.users[0].id))
        ).scalar_one_or_none() is None


@pytest.mark.parametrize(
    "method,suffix,body",
    [
        ("GET", "", None),
        ("POST", "", {}),
        ("GET", "/id", None),
        ("PATCH", "/id", {}),
        ("POST", "/id/suspend", {}),
        ("POST", "/id/activate", {}),
    ],
)
async def test_platform_routes_require_authentication(platform_env, method, suffix, body):
    env = platform_env
    url = BASE + suffix.replace("id", str(env.tenants[0].id))
    result = await env.client.request(method, url, **({"json": body} if body is not None else {}))
    assert result.status_code == 401


@pytest.mark.parametrize(
    "overrides",
    [
        {"reason": "short"},
        {"slug": "UPPER"},
        {"slug": "ecomind-other"},
        {"id": str(uuid4())},
        {"status": "TRIAL"},
        {"plan": "platform"},
        {"admin_password": "not-accepted"},
        {"permissions": ["platform.tenants.write"]},
        {"admin_email": "bad\naddress@example.test"},
        {"admin_email": "invalid"},
        {"timezone": "Missing/City"},
        {"type": "PLATFORM"},
        {"name": " "},
    ],
)
async def test_provisioning_closed_inputs(platform_env, overrides):
    result = await platform_env.client.post(
        BASE, headers=platform_env.operator_headers, json=payload(**overrides)
    )
    assert result.status_code == 400, result.text


@pytest.mark.parametrize(
    "values",
    [
        {"status": "ACTIVE"},
        {"slug": "new-slug"},
        {"name": None},
        {"timezone": "No/Zone"},
        {"locale": "invalid tag"},
        {},
        {"admin_email": "other@example.test"},
        {"tenant_id": str(uuid4())},
    ],
)
async def test_metadata_cannot_change_identity_or_lifecycle(platform_env, values):
    env = platform_env
    result = await env.client.patch(
        BASE + "/" + str(env.tenants[0].id), headers=env.operator_headers, json={**REASON, **values}
    )
    assert result.status_code == 400


@pytest.mark.parametrize(
    "query",
    [
        {"tenant_id": str(uuid4())},
        {"page": 0},
        {"page_size": 101},
        {"status": "DELETED"},
        {"sort": "email"},
    ],
)
async def test_closed_platform_listing_filters(platform_env, query):
    env = platform_env
    assert (
        await env.client.get(BASE, headers=env.operator_headers, params=query)
    ).status_code == 400


async def test_reserved_missing_deleted_and_cancelled_targets(platform_env, db_session):
    env = platform_env
    for tenant_id in (PLATFORM_SCOPE_ID, uuid4()):
        for method, suffix, body in [
            ("GET", "", None),
            ("PATCH", "", {**REASON, "name": "Unsafe"}),
            ("POST", "/suspend", REASON),
            ("POST", "/activate", REASON),
        ]:
            result = await env.client.request(
                method,
                BASE + "/" + str(tenant_id) + suffix,
                headers=env.operator_headers,
                **({"json": body} if body else {}),
            )
            assert result.status_code == 404
    target = env.tenants[1]
    target.status = TenantStatus.CANCELLED
    await db_session.commit()
    for suffix in ("/suspend", "/activate"):
        assert (
            await env.client.post(
                BASE + "/" + str(target.id) + suffix, headers=env.operator_headers, json=REASON
            )
        ).status_code == 409
    target.deleted_at = utc_now()
    await db_session.commit()
    assert (
        await env.client.get(BASE + "/" + str(target.id), headers=env.operator_headers)
    ).status_code == 404


async def test_duplicate_slug_is_safe_and_does_not_repair_existing_tenant(platform_env, db_session):
    env = platform_env
    first = (await create(env)).json()
    result = await env.client.post(
        BASE, headers=env.operator_headers, json=payload(slug=first["slug"])
    )
    assert result.status_code == 409 and "INSERT" not in result.text
    assert len(await events(db_session, "create")) == 1


@pytest.mark.parametrize("failure", ["audit", "mail", "commit"])
async def test_failed_provisioning_rolls_back_everything(
    platform_env, db_session, monkeypatch, failure
):
    from sqlalchemy.ext.asyncio import AsyncSession

    env = platform_env
    body = payload()

    async def fail(*args, **kwargs):
        raise RuntimeError("Controlled failure")

    with monkeypatch.context() as patch:
        if failure == "audit":
            patch.setattr(PlatformTenantService, "_record", fail)
        elif failure == "commit":
            patch.setattr(AsyncSession, "commit", fail)
        else:
            patch.setattr(env.settings, "auth_delivery_enabled", False)
        result = await env.client.post(BASE, headers=env.operator_headers, json=body)
    assert result.status_code in (500, 503)
    assert "password" not in result.text and "token" not in result.text
    assert (
        await db_session.execute(select(Tenant).where(Tenant.slug == body["slug"]))
    ).scalar_one_or_none() is None
    assert await events(db_session, "create") == []


async def test_suspension_revokes_human_access_without_resurrecting_it_on_activation(
    platform_env, db_session
):
    env = platform_env
    tokens = (await login(env)).json()
    replacement = (await refresh(env, tokens)).json()
    other = (await login(env, index=1)).json()
    key = (
        await env.client.post(
            "/api/v1/api-keys",
            headers=env.headers,
            json={"name": "Gateway", "scopes": ["bins.telemetry.ingest"]},
        )
    ).json()
    async with env.factory() as session:
        reset = await service(session, env.settings).request_password_reset_in(
            env.tenants[0], email=env.users[0].email
        )
        await session.commit()
    target = BASE + "/" + str(env.tenants[0].id)
    assert (
        await env.client.post(target + "/suspend", headers=env.operator_headers, json=REASON)
    ).status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(replacement))).status_code in (
        401,
        403,
    )
    assert (await login(env)).status_code == 403
    async with env.factory() as session:
        with pytest.raises(AuthenticationError):
            await service(session, env.settings).authenticate_api_key(
                key["api_key"], tenant_id=env.tenants[0].id
            )
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(other))).status_code == 200
    assert (
        await env.client.post(target + "/activate", headers=env.operator_headers, json=REASON)
    ).status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(replacement))).status_code == 401
    assert (await refresh(env, replacement)).status_code == 401
    assert (
        await env.client.post(
            "/api/v1/auth/password-reset/confirm",
            json={
                "tenant_slug": env.tenants[0].slug,
                "token": reset,
                "new_password": secrets.token_urlsafe(24),
            },
        )
    ).status_code == 401
    assert (await login(env)).status_code == 200
    async with env.factory() as session:
        assert (
            await service(session, env.settings).authenticate_api_key(
                key["api_key"], tenant_id=env.tenants[0].id
            )
        ).auth_type == "API_KEY"
        await session.commit()
    assert (await events(db_session, "suspend"))[0].event_metadata["revoked_sessions"] >= 2


async def test_failed_suspension_restores_sessions_and_tenant(
    platform_env, db_session, monkeypatch
):
    env = platform_env

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    monkeypatch.setattr(PlatformTenantService, "_record", fail)
    result = await env.client.post(
        BASE + "/" + str(env.tenants[0].id) + "/suspend", headers=env.operator_headers, json=REASON
    )
    assert result.status_code == 500
    assert (await env.client.get("/api/v1/auth/me", headers=env.headers)).status_code == 200
    await db_session.refresh(env.tenants[0])
    assert env.tenants[0].status == TenantStatus.ACTIVE


@pytest.mark.parametrize(
    "mutation",
    [
        "tenant",
        "flag",
        "auth_type",
        "session",
        "grant",
        "expired_grant",
        "disabled",
        "locked",
        "revoked",
    ],
)
async def test_service_rechecks_forged_or_stale_actor(platform_env, db_session, mutation):
    env = platform_env
    actor = env.operator
    if mutation == "tenant":
        actor = replace(actor, tenant_id=env.tenants[0].id)
    elif mutation == "flag":
        actor = replace(actor, is_platform_operator=False)
    elif mutation == "auth_type":
        actor = replace(actor, auth_type="API_KEY")
    elif mutation == "session":
        actor = replace(actor, session_id=None)
    elif mutation in ("grant", "expired_grant"):
        if mutation == "grant":
            await db_session.execute(delete(UserRole).where(UserRole.user_id == actor.user_id))
        else:
            await db_session.execute(
                update(UserRole)
                .where(UserRole.user_id == actor.user_id)
                .values(expires_at=utc_now() - timedelta(seconds=1))
            )
    elif mutation in ("disabled", "locked"):
        await db_session.execute(
            update(User)
            .where(User.id == actor.user_id)
            .values(
                **(
                    {"status": UserStatus.DISABLED}
                    if mutation == "disabled"
                    else {"locked_until": utc_now() + timedelta(hours=1)}
                )
            )
        )
    else:
        await db_session.execute(
            update(Session).where(Session.id == actor.session_id).values(revoked_at=utc_now())
        )
    await db_session.commit()
    async with env.factory() as session:
        with pytest.raises(PermissionDeniedError):
            await PlatformTenantService(session, actor, env.settings).get_tenant_platform(
                env.tenants[0].id
            )


async def test_permission_resolution_rejects_scope_pollution(platform_env, db_session):
    env = platform_env
    platform_role = (
        await db_session.execute(
            select(Role).where(Role.code == "TENANT_ADMIN", Role.tenant_id == PLATFORM_SCOPE_ID)
        )
    ).scalar_one()
    db_session.add(
        UserRole(tenant_id=PLATFORM_SCOPE_ID, user_id=env.operator_id, role_id=platform_role.id)
    )
    permission = (
        await db_session.execute(
            select(Permission).where(Permission.code == "platform.tenants.read")
        )
    ).scalar_one()
    polluted = RolePermission(
        tenant_id=env.tenants[0].id,
        role_id=env.roles[env.tenants[0].id, "TENANT_ADMIN"].id,
        permission_id=permission.id,
    )
    db_session.add(polluted)
    await db_session.commit()
    me = await env.client.get("/api/v1/auth/me", headers=env.operator_headers)
    assert "users.write" not in me.json()["permissions"]
    assert (await env.client.get(BASE, headers=env.headers)).status_code == 403


async def test_bootstrap_never_repairs_or_adds_access(platform_env, db_session):
    env = platform_env
    await db_session.execute(
        update(User)
        .where(User.id == env.operator_id)
        .values(status=UserStatus.DISABLED, deleted_at=utc_now())
    )
    await db_session.commit()
    async with env.factory() as session:
        with pytest.raises(ConflictError):
            await bootstrap_operator(
                session,
                env.settings,
                email="replacement@example.test",
                full_name="Replacement",
                password=env.password,
                **REASON,
            )


async def test_suspension_waits_for_inflight_login_then_invalidates_it(platform_env, monkeypatch):
    env = platform_env
    acquired = asyncio.Event()
    original = PlatformTenantService._target

    async def observe(self, *args, **kwargs):
        row = await original(self, *args, **kwargs)
        acquired.set()
        return row

    monkeypatch.setattr(PlatformTenantService, "_target", observe)
    async with env.factory() as holder:
        await apply_tenant_context(holder, env.tenants[0].id)
        await holder.execute(select(User).where(User.id == env.users[0].id).with_for_update())
        task = asyncio.create_task(
            env.client.post(
                BASE + "/" + str(env.tenants[0].id) + "/suspend",
                headers=env.operator_headers,
                json=REASON,
            )
        )
        try:
            await asyncio.wait_for(acquired.wait(), 5)
            issued = await asyncio.wait_for(
                service(holder, env.settings).authenticate(
                    tenant_slug=env.tenants[0].slug, email=env.users[0].email, password=env.password
                ),
                5,
            )
            await holder.commit()
            assert (await asyncio.wait_for(task, 5)).status_code == 200
        finally:
            await holder.rollback()
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    target = BASE + "/" + str(env.tenants[0].id)
    assert (
        await env.client.post(target + "/activate", headers=env.operator_headers, json=REASON)
    ).status_code == 200
    assert (
        await env.client.get(
            "/api/v1/auth/me", headers={"Authorization": "Bearer " + issued.access_token}
        )
    ).status_code == 401


async def test_login_waiter_does_not_reuse_pre_suspension_tenant_snapshot(
    platform_env, monkeypatch
):
    from app.repositories.identity import UserRepository

    env = platform_env
    invalidate_done = asyncio.Event()
    snapshot_loaded = asyncio.Event()
    release = asyncio.Event()
    original_record = PlatformTenantService._record
    original_lookup = UserRepository.get_by_email

    async def pause_before_commit(self, *args, **kwargs):
        invalidate_done.set()
        await asyncio.wait_for(release.wait(), 10)
        return await original_record(self, *args, **kwargs)

    async def observe_snapshot(self, *args, **kwargs):
        if self.tenant_id == env.tenants[0].id and kwargs.get("for_update"):
            cached = await self.session.get(Tenant, self.tenant_id)
            assert cached.status == TenantStatus.ACTIVE
            snapshot_loaded.set()
        return await original_lookup(self, *args, **kwargs)

    monkeypatch.setattr(PlatformTenantService, "_record", pause_before_commit)
    monkeypatch.setattr(UserRepository, "get_by_email", observe_snapshot)
    suspend = asyncio.create_task(
        env.client.post(
            BASE + "/" + str(env.tenants[0].id) + "/suspend",
            headers=env.operator_headers,
            json=REASON,
        )
    )
    attempt = None
    try:
        await asyncio.wait_for(invalidate_done.wait(), 5)
        attempt = asyncio.create_task(login(env))
        await asyncio.wait_for(snapshot_loaded.wait(), 5)
        release.set()
        assert (await asyncio.wait_for(suspend, 5)).status_code == 200
        assert (await asyncio.wait_for(attempt, 5)).status_code == 403
    finally:
        release.set()
        for task in (suspend, attempt):
            if task is not None and not task.done():
                task.cancel()
        await asyncio.gather(
            *[t for t in (suspend, attempt) if t is not None], return_exceptions=True
        )


@pytest.mark.parametrize("kind", ["PASSWORD_RESET", "EMAIL_VERIFICATION"])
async def test_recovery_waiter_rechecks_tenant_after_user_lock(
    platform_env, monkeypatch, db_session, kind
):
    from app.repositories.identity import UserRepository

    env = platform_env
    reached = asyncio.Event()
    release = asyncio.Event()
    original = UserRepository.get_by_email

    async def pause(self, *args, **kwargs):
        if self.tenant_id == env.tenants[0].id and kwargs.get("for_update"):
            reached.set()
            await asyncio.wait_for(release.wait(), 10)
        return await original(self, *args, **kwargs)

    monkeypatch.setattr(UserRepository, "get_by_email", pause)
    endpoint = "/password-reset" if kind == "PASSWORD_RESET" else "/email/verify-request"
    request = asyncio.create_task(
        env.client.post(
            "/api/v1/auth" + endpoint,
            json={"tenant_slug": env.tenants[0].slug, "email": env.users[0].email},
        )
    )
    try:
        await asyncio.wait_for(reached.wait(), 5)
        assert (
            await env.client.post(
                BASE + "/" + str(env.tenants[0].id) + "/suspend",
                headers=env.operator_headers,
                json=REASON,
            )
        ).status_code == 200
        release.set()
        assert (await asyncio.wait_for(request, 5)).status_code == 202
        assert (
            list(
                (
                    await db_session.execute(
                        select(AuthMail).where(AuthMail.tenant_id == env.tenants[0].id)
                    )
                ).scalars()
            )
            == []
        )
    finally:
        release.set()
        if not request.done():
            request.cancel()
        await asyncio.gather(request, return_exceptions=True)


async def test_read_only_platform_role_has_no_write_authority(platform_env, db_session):
    env = platform_env
    permission = (
        await db_session.execute(
            select(Permission).where(Permission.code == "platform.tenants.read")
        )
    ).scalar_one()
    role = Role(
        tenant_id=PLATFORM_SCOPE_ID, code="PLATFORM_READER", name="Registry reader", is_system=False
    )
    db_session.add(role)
    await db_session.flush()
    env.extra_roles.append(role.id)
    await db_session.execute(delete(UserRole).where(UserRole.user_id == env.operator_id))
    db_session.add_all(
        [
            UserRole(tenant_id=PLATFORM_SCOPE_ID, user_id=env.operator_id, role_id=role.id),
            RolePermission(
                tenant_id=PLATFORM_SCOPE_ID, role_id=role.id, permission_id=permission.id
            ),
        ]
    )
    await db_session.commit()
    assert (await env.client.get(BASE, headers=env.operator_headers)).status_code == 200
    assert (
        await env.client.post(BASE, headers=env.operator_headers, json=payload())
    ).status_code == 403
    async with env.factory() as session:
        # The cached actor still claims SUPER_ADMIN; the live guard must reject it.
        with pytest.raises(PermissionDeniedError):
            await PlatformTenantService(session, env.operator, env.settings).set_status_platform(
                env.tenants[0].id, suspended=True, **REASON
            )


async def test_read_audit_failure_does_not_disclose_registry(platform_env, monkeypatch):
    env = platform_env

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    monkeypatch.setattr(AuditLogRepository, "record", fail)
    for url in (BASE, BASE + "/" + str(env.tenants[0].id)):
        response = await env.client.get(url, headers=env.operator_headers)
        assert response.status_code == 500
        assert env.tenants[0].slug not in response.text


async def test_provisioning_restores_scope_and_concurrent_slug_has_one_winner(platform_env):
    env = platform_env
    body = payload()

    async def provision():
        async with env.factory() as session:
            try:
                row = await PlatformTenantService(
                    session, env.operator, env.settings
                ).create_tenant_platform(**body)
                env.created_ids.append(row.id)
                assert (
                    await session.execute(text("SELECT current_setting('app.tenant_id')"))
                ).scalar_one() == str(PLATFORM_SCOPE_ID)
                assert (
                    list(
                        (
                            await session.execute(select(User).where(User.tenant_id == row.id))
                        ).scalars()
                    )
                    == []
                )
                await session.commit()
                return 201
            except ConflictError:
                await session.rollback()
                return 409

    assert sorted(await asyncio.wait_for(asyncio.gather(provision(), provision()), 10)) == [
        201,
        409,
    ]


async def test_invitation_cannot_use_a_stale_session_after_suspension(platform_env):
    env = platform_env
    user = env.users[0]
    actor = Actor(
        user_id=user.id,
        tenant_id=user.tenant_id,
        email=user.email,
        full_name=user.full_name,
        permissions=ROLE_DEFINITIONS["TENANT_ADMIN"].permissions,
        session_id=UUID((await login(env)).json()["session_id"]),
    )
    target = BASE + "/" + str(user.tenant_id)
    for action in ("suspend", "activate"):
        assert (
            await env.client.post(target + "/" + action, headers=env.operator_headers, json=REASON)
        ).status_code == 200
    async with env.factory() as session:
        with pytest.raises(PermissionDeniedError):
            await service(session, env.settings, user.tenant_id).register(
                email="stale@example.test",
                password=env.password,
                full_name="Stale inviter",
                actor=actor,
            )


async def test_provisioning_supports_maximum_configured_password_minimum(platform_env, monkeypatch):
    env = platform_env
    monkeypatch.setattr(env.settings, "password_min_length", 128)
    assert (await create(env)).status_code == 201
