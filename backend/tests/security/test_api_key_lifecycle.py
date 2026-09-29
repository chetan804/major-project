"""Key management HTTP + machine authentication, using actual restricted-role RLS."""

from __future__ import annotations

import asyncio
import secrets
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select

from app.authorization.api_keys import API_KEY_SCOPES, api_key_prefix, generate_api_key
from app.authorization.context import Actor
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.authorization.tokens import hash_token
from app.core.errors import AuthenticationError, PermissionDeniedError
from app.core.time import utc_now
from app.db.rls import apply_tenant_context
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import ApiKey, AuditLog, UserRole
from app.repositories.identity import AuditLogRepository
from app.services.api_keys import ApiKeyService

from .support import bearer, login, service

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


async def issue(env, **values):
    response = await env.client.post(
        "/api/v1/api-keys",
        headers=env.headers,
        json={"name": "Gateway", "scopes": ["bins.telemetry.ingest"], **values},
    )
    assert response.status_code == 201, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    return response.json()


async def authenticate(env, plaintext, index=0):
    async with env.factory() as session:
        actor = await service(session, env.settings).authenticate_api_key(
            plaintext, tenant_id=env.tenants[index].id
        )
        await session.commit()
        return actor


async def key_events(db, env, action):
    return list(
        (
            await db.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == env.tenants[0].id, AuditLog.action == action
                )
            )
        ).scalars()
    )


async def test_create_secret_once_hashed_storage_and_real_machine_audit_attribution(
    admin_env, db_session, caplog
):
    env = admin_env
    issued = await issue(env)
    secret = issued["api_key"]
    row = await db_session.get(ApiKey, UUID(issued["id"]))
    assert row.key_hash == hash_token(secret)
    assert row.key_prefix == api_key_prefix(secret)
    assert timedelta(days=89) < row.expires_at - utc_now() <= timedelta(days=90)
    assert row.created_by == env.users[0].id
    assert secret not in str(row.__dict__)
    for path in ("/api-keys", f"/api-keys/{row.id}"):
        response = await env.client.get("/api/v1" + path, headers=env.headers)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert secret not in response.text and row.key_hash not in response.text
        assert '"api_key":' not in response.text and "key_hash" not in response.text
    actor = await authenticate(env, secret)
    assert actor.auth_type == "API_KEY"
    assert actor.permissions == API_KEY_SCOPES
    assert actor.roles == frozenset() and actor.session_id is None
    await db_session.refresh(row)
    assert row.last_used_at is not None
    events = await key_events(db_session, env, "api_key.authenticate")
    assert len(events) == 1
    assert events[0].actor_user_id is None
    assert events[0].actor_api_key_id == row.id
    assert events[0].actor_type.value == "API_KEY"
    assert events[0].actor_label == "Gateway"
    audit = await env.client.get(
        "/api/v1/audit-logs", headers=env.headers, params={"actor_api_key_id": str(row.id)}
    )
    assert audit.status_code == 200
    assert [item["id"] for item in audit.json()["items"]] == [events[0].id]
    assert secret not in audit.text + caplog.text
    assert row.key_hash not in audit.text
    catalog = await env.client.get("/api/v1/api-key-scopes", headers=env.headers)
    assert catalog.json() == [
        {
            "code": "bins.telemetry.ingest",
            "description": "Device telemetry ingestion capability. The ingestion endpoint is not implemented yet.",
            "endpoint_status": "planned",
        }
    ]


@pytest.mark.parametrize(
    "values",
    [
        {"scopes": []},
        {"scopes": ["bins.telemetry.ingest"] * 2},
        {"scopes": ["users.write"]},
        {"scopes": ["apikeys.write"]},
        {"scopes": ["roles.assign.elevate"]},
        {"scopes": ["platform.tenants.read"]},
        {"scopes": ["models.manage"]},
        {"scopes": ["made.up"]},
        {"scopes": ["bins.read"]},
        {"expires_at": None},
        {"expires_at": "2020-01-01T00:00:00Z"},
        {"expires_at": "2099-01-01T00:00:00Z"},
        {"expires_at": "2026-09-29T00:00:00"},
        {"name": "  "},
        {"name": "x" * 201},
        {"tenant_id": str(uuid4())},
        {"key_hash": "not-client-writable"},
        {"rotation_of_id": str(uuid4())},
    ],
)
async def test_creation_rejects_unsafe_scope_expiry_and_mass_assignment(
    admin_env, db_session, values
):
    env = admin_env
    response = await env.client.post(
        "/api/v1/api-keys",
        headers=env.headers,
        json={"name": "Gateway", "scopes": ["bins.telemetry.ingest"], **values},
    )
    assert response.status_code == 400, response.text
    assert (
        list(
            (
                await db_session.execute(
                    select(ApiKey).where(ApiKey.tenant_id == env.tenants[0].id)
                )
            ).scalars()
        )
        == []
    )
    assert await key_events(db_session, env, "api_key.create") == []


async def test_rotate_is_immediate_preserves_expiry_and_records_lineage(admin_env, db_session):
    env = admin_env
    old = await issue(env, expires_at=(utc_now() + timedelta(hours=2)).isoformat())
    response = await env.client.post(
        f"/api/v1/api-keys/{old['id']}/rotate", headers=env.headers, json={}
    )
    assert response.status_code == 201
    assert response.headers["cache-control"] == "no-store"
    new = response.json()
    assert new["id"] != old["id"] and new["api_key"] != old["api_key"]
    assert new["rotation_of_id"] == old["id"]
    assert new["expires_at"] == old["expires_at"]
    assert new["name"] == old["name"]
    with pytest.raises(AuthenticationError):
        await authenticate(env, old["api_key"])
    await authenticate(env, new["api_key"])
    retry = await env.client.post(
        f"/api/v1/api-keys/{old['id']}/rotate", headers=env.headers, json={}
    )
    assert retry.status_code == 409
    # Revocation is per credential, not family-wide: old history is already inert.
    assert (
        await env.client.delete(f"/api/v1/api-keys/{old['id']}", headers=env.headers)
    ).status_code == 204
    await authenticate(env, new["api_key"])
    for _ in range(2):
        assert (
            await env.client.delete(f"/api/v1/api-keys/{new['id']}", headers=env.headers)
        ).status_code == 204
    with pytest.raises(AuthenticationError):
        await authenticate(env, new["api_key"])
    rows = list(
        (
            await db_session.execute(select(ApiKey).where(ApiKey.tenant_id == env.tenants[0].id))
        ).scalars()
    )
    assert len(rows) == 2 and all(row.revoked_at is not None for row in rows)
    assert len(await key_events(db_session, env, "api_key.rotate")) == 1


async def test_concurrent_rotation_creates_exactly_one_replacement(admin_env, db_session):
    env = admin_env
    key = await issue(env)
    responses = await asyncio.wait_for(
        asyncio.gather(
            *[
                env.client.post(
                    f"/api/v1/api-keys/{key['id']}/rotate", headers=env.headers, json={}
                )
                for _ in range(2)
            ]
        ),
        timeout=10,
    )
    assert sorted(r.status_code for r in responses) == [201, 409]
    replacements = list(
        (
            await db_session.execute(select(ApiKey).where(ApiKey.rotation_of_id == UUID(key["id"])))
        ).scalars()
    )
    assert len(replacements) == 1
    assert len(await key_events(db_session, env, "api_key.rotate")) == 1


@pytest.mark.parametrize("operation", ["create", "rotate", "revoke", "read"])
async def test_audit_failure_rolls_back_key_state_and_discloses_no_secret(
    admin_env, db_session, monkeypatch, operation
):
    env = admin_env
    original = await issue(env)

    async def broken(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(AuditLogRepository, "record", broken)
        if operation == "create":
            response = await env.client.post(
                "/api/v1/api-keys",
                headers=env.headers,
                json={"name": "Other", "scopes": ["bins.telemetry.ingest"]},
            )
        elif operation == "rotate":
            response = await env.client.post(
                f"/api/v1/api-keys/{original['id']}/rotate", headers=env.headers, json={}
            )
        elif operation == "revoke":
            response = await env.client.delete(
                f"/api/v1/api-keys/{original['id']}", headers=env.headers
            )
        else:
            response = await env.client.get("/api/v1/api-keys", headers=env.headers)
        assert response.status_code == 500
        assert '"api_key":' not in response.text and "items" not in response.json()
    rows = list(
        (
            await db_session.execute(select(ApiKey).where(ApiKey.tenant_id == env.tenants[0].id))
        ).scalars()
    )
    assert len(rows) == 1 and rows[0].revoked_at is None
    await authenticate(env, original["api_key"])


async def test_prefix_collision_rolls_back_rotation_without_leaking_secret(
    admin_env, db_session, monkeypatch, caplog
):
    env = admin_env
    old = await issue(env)
    plaintext = old["key_prefix"] + "." + secrets.token_urlsafe(32)
    monkeypatch.setattr(
        "app.services.api_keys.generate_api_key", lambda: (old["key_prefix"], plaintext)
    )
    response = await env.client.post(
        f"/api/v1/api-keys/{old['id']}/rotate", headers=env.headers, json={}
    )
    assert response.status_code == 409
    assert plaintext not in response.text + caplog.text
    await authenticate(env, old["api_key"])
    assert await key_events(db_session, env, "api_key.rotate") == []


async def test_foreign_management_and_wrong_tenant_authentication_fail(admin_env, db_session):
    env = admin_env
    key = await issue(env)
    other_headers = bearer((await login(env, 1)).json())
    for identifier in (key["id"], str(uuid4())):
        for method, suffix, body in (
            ("GET", "", None),
            ("DELETE", "", None),
            ("POST", "/rotate", {}),
        ):
            response = await env.client.request(
                method, f"/api/v1/api-keys/{identifier}{suffix}", headers=other_headers, json=body
            )
            assert response.status_code == 404
    assert (await env.client.get("/api/v1/api-keys", headers=other_headers)).json()["meta"][
        "total_items"
    ] == 0
    with pytest.raises(AuthenticationError):
        await authenticate(env, key["api_key"], index=1)
    row = await db_session.get(ApiKey, UUID(key["id"]))
    assert row.last_used_at is None
    async with env.factory() as session:
        assert list((await session.execute(select(ApiKey))).scalars()) == []
        await apply_tenant_context(session, env.tenants[1].id)
        assert list((await session.execute(select(ApiKey))).scalars()) == []
    await authenticate(env, key["api_key"])


@pytest.mark.parametrize(
    "state",
    [
        "expired",
        "revoked",
        "unbounded",
        "unsafe_scopes",
        "empty_scopes",
        "tenant_suspended",
        "tenant_deleted",
    ],
)
async def test_machine_authentication_fails_closed_for_invalid_state(admin_env, db_session, state):
    env = admin_env
    key = await issue(env)
    row = await db_session.get(ApiKey, UUID(key["id"]))
    if state == "expired":
        row.expires_at = utc_now() - timedelta(seconds=1)
    elif state == "revoked":
        row.revoked_at = utc_now()
    elif state == "unbounded":
        row.expires_at = None
    elif state == "unsafe_scopes":
        row.scopes = ["users.write"]
    elif state == "empty_scopes":
        row.scopes = []
    elif state == "tenant_suspended":
        env.tenants[0].status = TenantStatus.SUSPENDED
    else:
        env.tenants[0].deleted_at = utc_now()
    await db_session.commit()
    with pytest.raises(AuthenticationError):
        await authenticate(env, key["api_key"])
    await db_session.refresh(row)
    assert row.last_used_at is None
    assert await key_events(db_session, env, "api_key.authenticate") == []
    if state == "unbounded":
        repaired = await env.client.post(
            f"/api/v1/api-keys/{key['id']}/rotate", headers=env.headers, json={}
        )
        assert repaired.status_code == 201
        assert repaired.json()["expires_at"] is not None
        await authenticate(env, repaired.json()["api_key"])
        with pytest.raises(AuthenticationError):
            await authenticate(env, key["api_key"])


async def test_creator_status_and_grants_do_not_implicitly_disable_tenant_device(
    admin_env, db_session
):
    env = admin_env
    key = await issue(env)
    env.users[0].status = UserStatus.DISABLED
    await db_session.execute(delete(UserRole).where(UserRole.user_id == env.users[0].id))
    await db_session.commit()
    assert (await authenticate(env, key["api_key"])).permissions == API_KEY_SCOPES
    assert (
        await env.client.delete(f"/api/v1/api-keys/{key['id']}", headers=env.headers)
    ).status_code == 403


async def test_key_cannot_authenticate_as_bearer_or_manage_other_keys(admin_env):
    env = admin_env
    key = await issue(env)
    for path in ("/api-keys", "/auth/me"):
        result = await env.client.get(
            "/api/v1" + path, headers={"Authorization": "Bearer " + key["api_key"]}
        )
        assert result.status_code == 401
    actor = await authenticate(env, key["api_key"])
    # Even a fabricated overprivileged machine actor cannot invoke human management.
    actor = replace(actor, permissions=ROLE_DEFINITIONS["TENANT_ADMIN"].permissions)
    async with env.factory() as session:
        with pytest.raises(PermissionDeniedError):
            await ApiKeyService(session, actor).list_keys()


async def test_filters_pages_and_explicit_rotation_expiry(admin_env, db_session):
    env = admin_env
    first = await issue(env)
    expired = await issue(env)
    old = await db_session.get(ApiKey, UUID(expired["id"]))
    old.expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    assert (
        await env.client.post(
            f"/api/v1/api-keys/{expired['id']}/rotate", headers=env.headers, json={}
        )
    ).status_code == 409
    expiry = (utc_now() + timedelta(hours=1)).isoformat()
    response = await env.client.post(
        f"/api/v1/api-keys/{first['id']}/rotate", headers=env.headers, json={"expires_at": expiry}
    )
    assert response.status_code == 201
    for state, expected in (("active", 1), ("revoked", 1), ("expired", 1), ("all", 3)):
        result = await env.client.get(
            "/api/v1/api-keys", headers=env.headers, params={"state": state, "page_size": 1}
        )
        assert result.json()["meta"]["total_items"] == expected
        assert len(result.json()["items"]) == 1
    first_page = (
        await env.client.get(
            "/api/v1/api-keys", headers=env.headers, params={"state": "all", "page_size": 1}
        )
    ).json()
    second_page = (
        await env.client.get(
            "/api/v1/api-keys",
            headers=env.headers,
            params={"state": "all", "page_size": 1, "page": 2},
        )
    ).json()
    assert first_page["items"][0]["id"] != second_page["items"][0]["id"]
    for query in (
        {"page": 0},
        {"page": 10001},
        {"page_size": 101},
        {"state": "bad"},
        {"tenant_id": str(uuid4())},
        {"sort": "key_hash"},
    ):
        assert (
            await env.client.get("/api/v1/api-keys", headers=env.headers, params=query)
        ).status_code == 400


@pytest.mark.parametrize("role_code", [code for code in ROLE_DEFINITIONS if code != "SUPER_ADMIN"])
async def test_all_tenant_roles_against_all_key_management_routes(admin_env, db_session, role_code):
    env = admin_env
    user = env.colleague
    await db_session.execute(delete(UserRole).where(UserRole.user_id == user.id))
    db_session.add(
        UserRole(
            user_id=user.id,
            tenant_id=user.tenant_id,
            role_id=env.roles[user.tenant_id, role_code].id,
        )
    )
    await db_session.commit()
    headers = bearer((await login(env, email=user.email)).json())
    cases = [
        ("GET", "/api-key-scopes", None, "apikeys.read", 200),
        ("GET", "/api-keys", None, "apikeys.read", 200),
        ("GET", f"/api-keys/{uuid4()}", None, "apikeys.read", 404),
        (
            "POST",
            "/api-keys",
            {"name": "Matrix", "scopes": ["bins.telemetry.ingest"]},
            "apikeys.write",
            201,
        ),
        ("POST", f"/api-keys/{uuid4()}/rotate", {}, "apikeys.write", 404),
        ("DELETE", f"/api-keys/{uuid4()}", None, "apikeys.write", 404),
    ]
    for method, path, payload, permission, expected in cases:
        response = await env.client.request(method, "/api/v1" + path, json=payload, headers=headers)
        assert response.status_code == (
            expected if permission in ROLE_DEFINITIONS[role_code].permissions else 403
        ), (role_code, path, response.text)


async def test_service_rechecks_live_key_administration_grants(admin_env, db_session):
    env = admin_env
    actor = Actor(
        user_id=env.users[0].id,
        tenant_id=env.tenants[0].id,
        email=env.users[0].email,
        full_name="Admin",
        permissions=ROLE_DEFINITIONS["TENANT_ADMIN"].permissions,
    )
    await db_session.execute(delete(UserRole).where(UserRole.user_id == actor.user_id))
    await db_session.commit()
    async with env.factory() as session:
        with pytest.raises(PermissionDeniedError):
            await ApiKeyService(session, actor).create_key(
                name="Denied", scopes=["bins.telemetry.ingest"]
            )


async def test_machine_auth_failure_never_accepts_changed_secret_or_prefix(admin_env):
    env = admin_env
    key = await issue(env)
    candidates = [
        key["key_prefix"],
        " " + key["api_key"],
        key["api_key"] + "x",
        key["key_prefix"] + "." + secrets.token_urlsafe(32),
        generate_api_key()[1],
    ]
    for value in candidates:
        with pytest.raises(AuthenticationError):
            await authenticate(env, value)


async def test_machine_work_is_transactional_and_revocation_waits_for_inflight_key(
    admin_env, db_session, monkeypatch
):
    env = admin_env
    key = await issue(env)
    entered = asyncio.Event()
    original = ApiKeyService._write

    async def observe(self, permission):
        entered.set()
        await original(self, permission)

    monkeypatch.setattr(ApiKeyService, "_write", observe)
    async with env.factory() as session:
        await service(session, env.settings).authenticate_api_key(
            key["api_key"], tenant_id=env.tenants[0].id
        )
        pending = asyncio.create_task(
            env.client.delete(f"/api/v1/api-keys/{key['id']}", headers=env.headers)
        )
        try:
            await asyncio.wait_for(entered.wait(), timeout=5)
            assert not pending.done()
            await session.rollback()  # failed business operation must not persist last-use/audit
            result = await asyncio.wait_for(pending, timeout=5)
            assert result.status_code == 204
        finally:
            await session.rollback()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
    row = await db_session.get(ApiKey, UUID(key["id"]))
    assert row.last_used_at is None
    assert await key_events(db_session, env, "api_key.authenticate") == []
    with pytest.raises(AuthenticationError):
        await authenticate(env, key["api_key"])


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/api-key-scopes", None),
        ("GET", "/api-keys", None),
        ("GET", f"/api-keys/{uuid4()}", None),
        ("POST", "/api-keys", {"name": "Denied", "scopes": ["bins.telemetry.ingest"]}),
        ("POST", f"/api-keys/{uuid4()}/rotate", {}),
        ("DELETE", f"/api-keys/{uuid4()}", None),
    ],
)
async def test_key_routes_require_bearer_authentication(auth_env, method, path, body):
    assert (await auth_env.client.request(method, "/api/v1" + path, json=body)).status_code == 401


@pytest.mark.parametrize(
    "values",
    [
        {"scopes": None},
        {"expires_at": None},
        {"scopes": []},
        {"scopes": ["users.write"]},
        {"name": "not-editable"},
    ],
)
async def test_rotation_rejects_nulls_unsafe_scopes_and_extra_fields(admin_env, values):
    key = await issue(admin_env)
    response = await admin_env.client.post(
        f"/api/v1/api-keys/{key['id']}/rotate", headers=admin_env.headers, json=values
    )
    assert response.status_code == 400
    await authenticate(admin_env, key["api_key"])


async def test_rotation_cannot_expand_even_a_future_allowlisted_scope(admin_env, monkeypatch):
    key = await issue(admin_env)
    monkeypatch.setattr(
        "app.services.api_keys.API_KEY_SCOPES", frozenset({"bins.telemetry.ingest", "bins.read"})
    )
    response = await admin_env.client.post(
        f"/api/v1/api-keys/{key['id']}/rotate",
        headers=admin_env.headers,
        json={"scopes": ["bins.telemetry.ingest", "bins.read"]},
    )
    assert response.status_code == 403
    await authenticate(admin_env, key["api_key"])


async def test_custom_delegation_permission_is_not_a_human_ingestion_grant(admin_env, db_session):
    env = admin_env
    role = await env.client.post(
        "/api/v1/roles",
        headers=env.headers,
        json={
            "code": "DEVICE_PROVISIONER",
            "name": "Device provisioner",
            "permissions": ["apikeys.write"],
        },
    )
    assert role.status_code == 201
    assert (
        await env.client.post(
            f"/api/v1/users/{env.colleague.id}/roles",
            headers=env.headers,
            json={"role_id": role.json()["id"]},
        )
    ).status_code == 204
    headers = bearer((await login(env, email=env.colleague.email)).json())
    me = (await env.client.get("/api/v1/auth/me", headers=headers)).json()
    assert "bins.telemetry.ingest" not in me["permissions"]
    response = await env.client.post(
        "/api/v1/api-keys",
        headers=headers,
        json={"name": "Delegated device", "scopes": ["bins.telemetry.ingest"]},
    )
    assert response.status_code == 201
    assert (await authenticate(env, response.json()["api_key"])).permissions == API_KEY_SCOPES
    assert (await env.client.get("/api/v1/api-keys", headers=headers)).status_code == 403


async def test_commit_failure_never_releases_an_uncommitted_secret(
    admin_env, db_session, monkeypatch, caplog
):
    from sqlalchemy.ext.asyncio import AsyncSession

    env = admin_env
    prefix, plaintext = generate_api_key()

    async def fail_commit(self):
        raise RuntimeError("Commit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr("app.services.api_keys.generate_api_key", lambda: (prefix, plaintext))
        patch.setattr(AsyncSession, "commit", fail_commit)
        response = await env.client.post(
            "/api/v1/api-keys",
            headers=env.headers,
            json={"name": "Uncommitted", "scopes": ["bins.telemetry.ingest"]},
        )
    assert response.status_code == 500
    assert plaintext not in response.text + caplog.text
    assert '"api_key":' not in response.text
    assert (
        list(
            (
                await db_session.execute(
                    select(ApiKey).where(ApiKey.tenant_id == env.tenants[0].id)
                )
            ).scalars()
        )
        == []
    )
    assert await key_events(db_session, env, "api_key.create") == []


async def test_database_refuses_second_child_for_same_rotation_source(admin_env):
    from sqlalchemy.exc import IntegrityError

    env = admin_env
    old = await issue(env)
    assert (
        await env.client.post(f"/api/v1/api-keys/{old['id']}/rotate", headers=env.headers, json={})
    ).status_code == 201
    prefix, plaintext = generate_api_key()
    async with env.factory() as session:
        await apply_tenant_context(session, env.tenants[0].id)
        session.add(
            ApiKey(
                tenant_id=env.tenants[0].id,
                name="Illegal fork",
                key_prefix=prefix,
                key_hash=hash_token(plaintext),
                scopes=["bins.telemetry.ingest"],
                rotation_of_id=UUID(old["id"]),
            )
        )
        with pytest.raises(IntegrityError):
            await session.flush()
        await session.rollback()
