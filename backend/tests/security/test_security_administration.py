"""Audit access and administrator session controls under non-superuser RLS."""

from __future__ import annotations

import asyncio
import secrets
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select

from app.authorization.context import Actor
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.errors import PermissionDeniedError
from app.core.time import utc_now
from app.models.identity import AuditLog, Session, User, UserRole
from app.repositories.identity import AuditLogRepository
from app.services.security_administration import SecurityAdministrationService

from .support import bearer, login, refresh, service

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


async def events(db, tenant_id, action):
    return list(
        (
            await db.execute(
                select(AuditLog)
                .where(AuditLog.tenant_id == tenant_id, AuditLog.action == action)
                .order_by(AuditLog.id)
            )
        ).scalars()
    )


async def seed_events(env, db, count=5):
    when = utc_now() - timedelta(days=1)
    rows = [
        AuditLog(
            tenant_id=env.tenants[0].id,
            actor_user_id=env.users[0].id,
            action="test.event",
            resource_type="sensor",
            resource_id=str(index),
            created_at=when,
            event_metadata={"sequence": index},
        )
        for index in range(count)
    ]
    foreign = AuditLog(
        tenant_id=env.tenants[1].id,
        action="test.event",
        created_at=when,
        event_metadata={"foreign": True},
    )
    db.add_all([*rows, foreign])
    await db.commit()
    return rows, foreign


async def test_audit_cursor_is_stable_for_equal_timestamps_and_reads_are_audited(
    admin_env, db_session
):
    env = admin_env
    rows, foreign = await seed_events(env, db_session)
    params = {"page_size": 2, "action": "test.event"}
    seen = []
    for _ in range(3):
        response = await env.client.get("/api/v1/audit-logs", params=params, headers=env.headers)
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        body = response.json()
        seen.extend(row["id"] for row in body["items"])
        assert body["has_more"] == (body["next_cursor"] is not None)
        if body["next_cursor"]:
            params["cursor"] = body["next_cursor"]
    assert seen == sorted([row.id for row in rows], reverse=True)
    assert foreign.id not in seen
    reads = await events(db_session, env.tenants[0].id, "audit.list")
    assert len(reads) == 3
    assert sum(e.event_metadata["returned_count"] for e in reads) == 5
    assert all(e.actor_user_id == env.users[0].id and e.request_id for e in reads)
    assert all("cursor" not in e.event_metadata for e in reads)


async def test_unfiltered_cursor_does_not_chase_its_own_read_events(admin_env, db_session):
    env = admin_env
    await seed_events(env, db_session)
    original = set(
        (
            await db_session.execute(
                select(AuditLog.id).where(AuditLog.tenant_id == env.tenants[0].id)
            )
        ).scalars()
    )
    seen = []
    cursor = None
    for _ in range(10):
        params = {"page_size": 2}
        if cursor:
            params["cursor"] = cursor
        body = (
            await env.client.get("/api/v1/audit-logs", params=params, headers=env.headers)
        ).json()
        seen.extend(row["id"] for row in body["items"])
        cursor = body["next_cursor"]
        if not cursor:
            break
    assert set(seen) == original
    assert len(seen) == len(original)
    assert cursor is None


async def test_cursor_tampering_filter_change_and_cross_tenant_reuse_fail(admin_env, db_session):
    env = admin_env
    await seed_events(env, db_session)
    params = {"page_size": 1, "action": "test.event"}
    response = await env.client.get("/api/v1/audit-logs", params=params, headers=env.headers)
    cursor = response.json()["next_cursor"]
    for changed in (
        {**params, "cursor": cursor + "x"},
        {**params, "cursor": cursor, "action": "audit.list"},
    ):
        result = await env.client.get("/api/v1/audit-logs", params=changed, headers=env.headers)
        assert result.status_code == 400, result.text
    foreign_headers = bearer((await login(env, 1)).json())
    result = await env.client.get(
        "/api/v1/audit-logs", params={**params, "cursor": cursor}, headers=foreign_headers
    )
    assert result.status_code == 400


async def test_audit_filters_detail_privacy_and_historical_rows_not_mutated(admin_env, db_session):
    env = admin_env
    rows, _ = await seed_events(env, db_session, 1)
    row = rows[0]
    secret = secrets.token_urlsafe(32)
    row.event_metadata = {
        "password": secret,
        "nested": {"access_token": secret},
        "changes": {"name": "safe"},
    }
    row.user_agent = "Bearer " + secret
    row.request_id = "trace-one"
    await db_session.commit()
    query = {
        "action": "test.event",
        "resource_type": "sensor",
        "resource_id": "0",
        "outcome": "SUCCESS",
        "actor_user_id": str(env.users[0].id),
        "request_id": "trace-one",
        "from_time": (row.created_at - timedelta(seconds=1)).isoformat(),
        "to_time": (row.created_at + timedelta(seconds=1)).isoformat(),
    }
    response = await env.client.get("/api/v1/audit-logs", params=query, headers=env.headers)
    assert [item["id"] for item in response.json()["items"]] == [row.id]
    detail = await env.client.get(
        f"/api/v1/audit-logs/{row.id}",
        headers={**env.headers, "X-Request-ID": "audit-detail-trace"},
    )
    assert detail.status_code == 200
    assert secret not in detail.text + response.text
    assert detail.json()["metadata"]["changes"]["name"] == "safe"
    assert detail.json()["metadata"]["password"] == "[redacted]"
    await db_session.refresh(row)
    assert row.event_metadata["password"] == secret  # Never rewrite audit history on read.
    read = (await events(db_session, env.tenants[0].id, "audit.read"))[0]
    assert read.request_id == "audit-detail-trace"
    assert read.actor_label == env.users[0].full_name
    assert read.resource_id == str(row.id)
    query["action"] = "test.%"
    assert (await env.client.get("/api/v1/audit-logs", params=query, headers=env.headers)).json()[
        "items"
    ] == []


@pytest.mark.parametrize(
    "params",
    [
        {"page_size": 0},
        {"page_size": 101},
        {"sort": "metadata"},
        {"tenant_id": str(uuid4())},
        {"outcome": "INVALID"},
        {"actor_user_id": "not-a-uuid"},
        {"from_time": "2026-09-29T00:00:00"},
        {"from_time": "2026-09-29T00:00:00Z", "to_time": "2026-09-28T00:00:00Z"},
        {"cursor": "malformed"},
    ],
)
async def test_invalid_audit_query_returns_400(admin_env, params):
    result = await admin_env.client.get(
        "/api/v1/audit-logs", params=params, headers=admin_env.headers
    )
    assert result.status_code == 400, result.text


async def test_foreign_and_missing_records_are_indistinguishable(admin_env, db_session):
    env = admin_env
    _, foreign = await seed_events(env, db_session, 1)
    foreign_tokens = (await login(env, 1)).json()
    for path in (
        f"/audit-logs/{foreign.id}",
        "/audit-logs/2147483647",
        f"/sessions?user_id={env.users[1].id}",
    ):
        assert (await env.client.get("/api/v1" + path, headers=env.headers)).status_code == 404
    for session_id in (foreign_tokens["session_id"], str(uuid4())):
        assert (
            await env.client.delete(f"/api/v1/sessions/{session_id}", headers=env.headers)
        ).status_code == 404
    assert (
        await env.client.post(
            f"/api/v1/users/{env.users[1].id}/sessions/revoke-all", headers=env.headers
        )
    ).status_code == 404
    assert (
        await env.client.get("/api/v1/auth/me", headers=bearer(foreign_tokens))
    ).status_code == 200


async def test_session_list_pagination_state_filters_and_credentials_absent(admin_env, db_session):
    env = admin_env
    original = (await login(env, email=env.colleague.email)).json()
    rotated = (await refresh(env, original)).json()
    expired = (await login(env, email=env.colleague.email)).json()
    row = await db_session.get(Session, UUID(expired["session_id"]))
    row.expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    for state, ids in (
        ("active", [rotated["session_id"]]),
        ("revoked", [original["session_id"]]),
        ("expired", [expired["session_id"]]),
    ):
        response = await env.client.get(
            "/api/v1/sessions",
            params={"user_id": str(env.colleague.id), "state": state},
            headers=env.headers,
        )
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert [row["id"] for row in response.json()["items"]] == ids
        assert "refresh_token_hash" not in response.text
        assert rotated["access_token"] not in response.text
        assert original["refresh_token"] not in response.text
    params = {"user_id": str(env.colleague.id), "state": "all", "page_size": 1}
    first = (await env.client.get("/api/v1/sessions", params=params, headers=env.headers)).json()
    second = (
        await env.client.get("/api/v1/sessions", params={**params, "page": 2}, headers=env.headers)
    ).json()
    assert first["meta"]["total_items"] == 3
    assert first["items"][0]["id"] != second["items"][0]["id"]
    for invalid in (
        {"state": "invalid"},
        {"page_size": 101},
        {"page": 0},
        {"tenant_id": str(uuid4())},
    ):
        assert (
            await env.client.get("/api/v1/sessions", params=invalid, headers=env.headers)
        ).status_code == 400


async def test_admin_revokes_descendant_using_old_session_id_but_not_other_device(
    admin_env, db_session
):
    env = admin_env
    old = (await login(env, email=env.colleague.email)).json()
    new = (await refresh(env, old)).json()
    other = (await login(env, email=env.colleague.email)).json()
    for _ in range(2):
        result = await env.client.delete(
            f"/api/v1/sessions/{old['session_id']}", headers=env.headers
        )
        assert result.status_code == 204
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(new))).status_code == 401
    assert (await refresh(env, new)).status_code == 401
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(other))).status_code == 200
    rows = await events(db_session, env.tenants[0].id, "session.admin_revoke")
    assert [row.event_metadata["revoked_sessions"] for row in rows] == [1, 0]
    assert (
        await db_session.get(Session, UUID(old["session_id"]))
    ).refresh_token_hash  # history retained


async def test_bulk_revoke_includes_all_devices_and_self_when_selected(admin_env, db_session):
    env = admin_env
    first = (await login(env, email=env.colleague.email)).json()
    second = (await login(env, email=env.colleague.email)).json()
    response = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/sessions/revoke-all", headers=env.headers
    )
    assert response.json() == {"revoked_sessions": 2}
    for token in (first, second):
        assert (await env.client.get("/api/v1/auth/me", headers=bearer(token))).status_code == 401
    response = await env.client.post(
        f"/api/v1/users/{env.users[0].id}/sessions/revoke-all", headers=env.headers
    )
    assert response.json()["revoked_sessions"] == 1
    assert (await env.client.get("/api/v1/auth/me", headers=env.headers)).status_code == 401
    assert (await login(env)).status_code == 200  # does not disable last recovery admin


async def test_revocation_serializes_with_refresh(admin_env, db_session):
    env = admin_env
    old = (await login(env, email=env.colleague.email)).json()
    revoke, rotation = await asyncio.wait_for(
        asyncio.gather(
            env.client.delete(f"/api/v1/sessions/{old['session_id']}", headers=env.headers),
            refresh(env, old),
        ),
        timeout=10,
    )
    assert revoke.status_code == 204
    assert rotation.status_code in (200, 401)
    if rotation.status_code == 200:
        assert (
            await env.client.get("/api/v1/auth/me", headers=bearer(rotation.json()))
        ).status_code == 401
    rows = (
        (await db_session.execute(select(Session).where(Session.user_id == env.colleague.id)))
        .scalars()
        .all()
    )
    assert all(row.revoked_at is not None for row in rows)


@pytest.mark.parametrize("operation", ["read", "revoke"])
async def test_audit_failure_prevents_disclosure_or_rolls_back_revocation(
    admin_env, db_session, monkeypatch, operation
):
    env = admin_env
    token = (await login(env, email=env.colleague.email)).json()

    async def broken(*args, **kwargs):
        raise RuntimeError("Audit storage failure")

    with monkeypatch.context() as context:
        context.setattr(AuditLogRepository, "record", broken)
        if operation == "read":
            response = await env.client.get("/api/v1/audit-logs", headers=env.headers)
        else:
            response = await env.client.delete(
                f"/api/v1/sessions/{token['session_id']}", headers=env.headers
            )
        assert response.status_code == 500
        assert "items" not in response.json()
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(token))).status_code == 200
    row = await db_session.get(Session, UUID(token["session_id"]))
    assert row.revoked_at is None


@pytest.mark.parametrize("role_code", [code for code in ROLE_DEFINITIONS if code != "SUPER_ADMIN"])
async def test_all_tenant_roles_against_new_route_permissions(admin_env, db_session, role_code):
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
        ("GET", "/audit-logs", "audit.read", 200),
        ("GET", "/audit-logs/2147483647", "audit.read", 404),
        ("GET", "/sessions", "sessions.read", 200),
        ("DELETE", f"/sessions/{uuid4()}", "sessions.revoke", 404),
        ("POST", f"/users/{uuid4()}/sessions/revoke-all", "sessions.revoke", 404),
    ]
    for method, path, permission, allowed in cases:
        result = await env.client.request(method, "/api/v1" + path, headers=headers)
        assert result.status_code == (
            allowed if permission in ROLE_DEFINITIONS[role_code].permissions else 403
        ), (role_code, path, result.text)


async def test_manager_cannot_sign_out_more_privileged_admin(admin_env, db_session):
    env = admin_env
    db_session.add(
        UserRole(
            user_id=env.colleague.id,
            tenant_id=env.colleague.tenant_id,
            role_id=env.roles[env.colleague.tenant_id, "OPERATIONS_MANAGER"].id,
        )
    )
    await db_session.commit()
    headers = bearer((await login(env, email=env.colleague.email)).json())
    admin = (await login(env)).json()
    assert (
        await env.client.delete(f"/api/v1/sessions/{admin['session_id']}", headers=headers)
    ).status_code == 403
    assert (
        await env.client.post(
            f"/api/v1/users/{env.users[0].id}/sessions/revoke-all", headers=headers
        )
    ).status_code == 403
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(admin))).status_code == 200


@pytest.mark.parametrize("operation", ["audit", "sessions", "revoke"])
async def test_services_recheck_revoked_grants_instead_of_trusting_stale_actor(
    admin_env, db_session, operation
):
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
        service = SecurityAdministrationService(session, actor)
        with pytest.raises(PermissionDeniedError):
            if operation == "audit":
                await service.audit_page(secret=env.settings.jwt_secret_key, filters={})
            elif operation == "sessions":
                await service.sessions_page()
            else:
                await service.revoke_user_sessions(env.colleague.id)


async def test_audit_repository_and_runtime_role_refuse_mutation(admin_env, db_session):
    from sqlalchemy import update
    from sqlalchemy.exc import ProgrammingError

    from app.db.rls import apply_tenant_context

    env = admin_env
    rows, _ = await seed_events(env, db_session, 1)
    async with env.factory() as session:
        await apply_tenant_context(session, env.tenants[0].id)
        repository = AuditLogRepository(session, env.tenants[0].id)
        with pytest.raises(PermissionDeniedError):
            await repository.update(rows[0], action="changed")
        with pytest.raises(PermissionDeniedError):
            await repository.soft_delete(rows[0])
        with pytest.raises(ProgrammingError):
            await session.execute(
                update(AuditLog).where(AuditLog.id == rows[0].id).values(action="changed")
            )
        await session.rollback()
        await apply_tenant_context(session, env.tenants[0].id)
        with pytest.raises(ProgrammingError):
            await session.execute(delete(AuditLog).where(AuditLog.id == rows[0].id))
        await session.rollback()
    await db_session.refresh(rows[0])
    assert rows[0].action == "test.event"


async def test_audit_writer_redacts_and_snapshots_actor_identity(admin_env, db_session):
    from app.db.rls import apply_tenant_context

    env = admin_env
    secret = secrets.token_urlsafe(24)
    actor = Actor(
        user_id=env.users[0].id,
        tenant_id=env.tenants[0].id,
        email=env.users[0].email,
        full_name="Original name",
    )
    async with env.factory() as session:
        await apply_tenant_context(session, actor.tenant_id)
        row = await AuditLogRepository(session, actor.tenant_id).record(
            action="test.safe_write",
            actor=actor,
            metadata={"password": secret, "changes": {"name": "safe"}},
            user_agent="Bearer " + secret,
        )
        row_id = row.id
        await session.commit()
    env.users[0].full_name = "Renamed later"
    await db_session.commit()
    row = await db_session.get(AuditLog, row_id)
    assert row.actor_label == "Original name"
    assert secret not in str(row.event_metadata) + row.user_agent
    result = await env.client.get(f"/api/v1/audit-logs/{row_id}", headers=env.headers)
    assert result.json()["actor_label"] == "Original name"


@pytest.mark.parametrize(
    "method,path",
    [
        ("GET", "/audit-logs"),
        ("GET", "/audit-logs/1"),
        ("GET", "/sessions"),
        ("DELETE", f"/sessions/{uuid4()}"),
        ("POST", f"/users/{uuid4()}/sessions/revoke-all"),
    ],
)
async def test_every_new_route_requires_authentication(auth_env, method, path):
    assert (await auth_env.client.request(method, "/api/v1" + path)).status_code == 401


async def test_custom_auditor_needs_only_audit_read_not_administration_permissions(admin_env):
    env = admin_env
    role = await env.client.post(
        "/api/v1/roles",
        headers=env.headers,
        json={"code": "AUDITOR_CUSTOM", "name": "Auditor", "permissions": ["audit.read"]},
    )
    assert role.status_code == 201
    assignment = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/roles",
        headers=env.headers,
        json={"role_id": role.json()["id"]},
    )
    assert assignment.status_code == 204
    headers = bearer((await login(env, email=env.colleague.email)).json())
    assert (await env.client.get("/api/v1/audit-logs", headers=headers)).status_code == 200
    assert (await env.client.get("/api/v1/sessions", headers=headers)).status_code == 403


async def test_audit_and_session_history_remain_visible_for_soft_deleted_user(
    admin_env, db_session
):
    env = admin_env
    tokens = (await login(env, email=env.colleague.email)).json()
    assert (
        await env.client.delete(f"/api/v1/users/{env.colleague.id}", headers=env.headers)
    ).status_code == 204
    result = await env.client.get(
        "/api/v1/sessions",
        headers=env.headers,
        params={"user_id": str(env.colleague.id), "state": "all"},
    )
    assert result.status_code == 200
    assert result.json()["items"][0]["id"] == tokens["session_id"]
    assert result.json()["items"][0]["revoked_at"] is not None
    audit = await env.client.get(
        "/api/v1/audit-logs",
        headers=env.headers,
        params={"actor_user_id": str(env.colleague.id), "action": "user.login"},
    )
    assert audit.status_code == 200
    assert audit.json()["items"]
    assert (
        await env.client.post(
            f"/api/v1/users/{env.colleague.id}/sessions/revoke-all", headers=env.headers
        )
    ).json() == {"revoked_sessions": 0}


async def test_mutual_admin_revocations_do_not_deadlock_or_authorize_revoked_caller(
    admin_env, db_session
):
    env = admin_env
    db_session.add(
        UserRole(
            user_id=env.colleague.id,
            tenant_id=env.colleague.tenant_id,
            role_id=env.roles[env.colleague.tenant_id, "TENANT_ADMIN"].id,
        )
    )
    await db_session.commit()
    other = (await login(env, email=env.colleague.email)).json()
    responses = await asyncio.wait_for(
        asyncio.gather(
            env.client.post(
                f"/api/v1/users/{env.colleague.id}/sessions/revoke-all", headers=env.headers
            ),
            env.client.post(
                f"/api/v1/users/{env.users[0].id}/sessions/revoke-all", headers=bearer(other)
            ),
        ),
        timeout=10,
    )
    codes = sorted(response.status_code for response in responses)
    assert codes in ([200, 401], [200, 403])
    assert len(await events(db_session, env.tenants[0].id, "user.sessions_revoke_all")) == 1


async def test_recovery_fk_checks_complete_while_admin_holds_tenant_mutex(admin_env, monkeypatch):
    """Force User -> Tenant FK checks against Tenant -> User administration.

    A FOR UPDATE tenant mutex deadlocks here; NO KEY UPDATE remains mutually
    exclusive for administrators but permits the recovery outbox INSERT's KEY SHARE.
    """
    from app.db.rls import apply_tenant_context

    env = admin_env
    tokens = (await login(env, email=env.colleague.email)).json()
    entering_user_lock = asyncio.Event()
    original = SecurityAdministrationService._session_user

    async def observe(self, user_id, *, lock=False):
        if lock:
            entering_user_lock.set()
        return await original(self, user_id, lock=lock)

    monkeypatch.setattr(SecurityAdministrationService, "_session_user", observe)
    async with env.factory() as holder:
        await apply_tenant_context(holder, env.tenants[0].id)
        await holder.execute(select(User).where(User.id == env.colleague.id).with_for_update())
        pending = asyncio.create_task(
            env.client.delete(f"/api/v1/sessions/{tokens['session_id']}", headers=env.headers)
        )
        try:
            await asyncio.wait_for(entering_user_lock.wait(), timeout=5)
            await asyncio.wait_for(
                service(holder, env.settings).request_password_reset_in(
                    env.tenants[0], email=env.colleague.email
                ),
                timeout=5,
            )
            await holder.commit()
            response = await asyncio.wait_for(pending, timeout=5)
            assert response.status_code == 204, response.text
        finally:
            await holder.rollback()
            if not pending.done():
                pending.cancel()
            await asyncio.gather(pending, return_exceptions=True)
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 401
