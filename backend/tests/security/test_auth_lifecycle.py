"""Real HTTP authentication against PostgreSQL as a NON-superuser.

No actor/session dependency is mocked. Only the database binding is replaced,
so token validation, the transaction error path and forced RLS all run for real.
"""

from __future__ import annotations

import asyncio
import secrets
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select

from app.authorization.context import Actor
from app.authorization.tokens import encode_access_token, hash_token
from app.core.errors import NotFoundError, PermissionDeniedError
from app.core.time import utc_now
from app.db.rls import apply_tenant_context
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import (
    AuditLog,
    Permission,
    Role,
    RolePermission,
    Session,
    UserRole,
)
from app.repositories.identity import (
    AuditLogRepository,
)
from app.services.auth import MAX_FAILED_LOGINS

from .support import bearer, login, refresh, service

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


async def test_login_me_and_audit_work_under_forced_rls(auth_env, db_session):
    env = auth_env
    for index in (0, 1):
        response = await login(env, index)
        assert response.status_code == 200, response.text
        tokens = response.json()
        me = await env.client.get("/api/v1/auth/me", headers=bearer(tokens))
        assert me.status_code == 200, me.text
        assert me.json()["id"] == str(env.users[index].id)
        assert me.json()["tenant_id"] == str(env.tenants[index].id)
        assert "password_hash" not in me.text
        row = await db_session.get(Session, UUID(tokens["session_id"]))
        assert row.refresh_token_hash == hash_token(tokens["refresh_token"])
        assert tokens["refresh_token"] not in row.refresh_token_hash
        audit = (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == env.tenants[index].id, AuditLog.action == "user.login"
                )
            )
        ).scalar_one()
        assert audit.actor_user_id == env.users[index].id
        assert audit.outcome == "SUCCESS"

    # A restricted fixture alone proves nothing if request code bypasses its
    # dependency. Both login and /me must actually use this binding each time.
    assert len(env.bindings) == 4


async def test_failed_logins_commit_counters_audit_and_lockout(auth_env, db_session):
    env = auth_env
    for _ in range(MAX_FAILED_LOGINS):
        response = await login(env, password="an incorrect credential")
        assert response.status_code == 401, response.text
    locked = await login(env)
    assert locked.status_code == 403
    assert locked.json()["error"]["code"] == "ACCOUNT_LOCKED"
    await db_session.refresh(env.users[0])
    assert env.users[0].locked_until > utc_now()
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.tenant_id == env.tenants[0].id)))
        .scalars()
        .all()
    )
    assert len(audits) == MAX_FAILED_LOGINS + 1
    assert all(a.outcome == "FAILURE" for a in audits)
    # Other tenant using the same email is unaffected.
    assert (await login(env, 1)).status_code == 200
    env.users[0].locked_until = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    assert (await login(env)).status_code == 200
    await db_session.refresh(env.users[0])
    assert env.users[0].failed_login_attempts == 0
    assert env.users[0].locked_until is None


async def test_concurrent_failures_do_not_lose_counter_updates(auth_env, db_session):
    responses = await asyncio.gather(
        *[login(auth_env, password="not the correct credential") for _ in range(MAX_FAILED_LOGINS)]
    )
    assert all(r.status_code == 401 for r in responses)
    await db_session.refresh(auth_env.users[0])
    assert auth_env.users[0].locked_until > utc_now()


async def test_unknown_user_and_tenant_have_same_credential_error(auth_env):
    missing_user = await login(auth_env, email="absent@example.test")
    missing_tenant = await login(auth_env, tenant_slug="absent-tenant")
    wrong = await login(auth_env, password="not the right credential")
    for response in (missing_user, missing_tenant, wrong):
        assert response.status_code == 401, response.text
        assert response.json()["error"]["code"] == "INVALID_CREDENTIALS"
        assert response.json()["error"]["message"] == "Email or password is incorrect."


async def test_rotation_retains_history_and_replay_revokes_only_that_family(auth_env, db_session):
    env = auth_env
    original = (await login(env)).json()
    unrelated = (await login(env)).json()
    first_response = await refresh(env, original)
    assert first_response.status_code == 200, first_response.text
    first = first_response.json()
    second_response = await refresh(env, first)
    assert second_response.status_code == 200, second_response.text
    second = second_response.json()
    assert len({t["session_id"] for t in (original, first, second)}) == 3
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(original))).status_code == 401
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(second))).status_code == 200
    replay = await refresh(env, original)
    assert replay.status_code == 401
    assert replay.json()["error"]["code"] == "REFRESH_TOKEN_REUSED"
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(second))).status_code == 401
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(unrelated))).status_code == 200
    rows = [
        (await db_session.get(Session, UUID(t["session_id"]))) for t in (original, first, second)
    ]
    assert all(r.revoked_at is not None for r in rows)
    assert len({r.family_id for r in rows}) == 1
    assert rows[1].previous_session_id == rows[0].id
    assert rows[2].previous_session_id == rows[1].id
    assert rows[0].refresh_token_hash == hash_token(original["refresh_token"])
    assert rows[2].revoked_reason == "refresh token replay detected"


async def test_simultaneous_refresh_cannot_fork_a_live_family(auth_env, db_session):
    original = (await login(auth_env)).json()
    responses = await asyncio.gather(refresh(auth_env, original), refresh(auth_env, original))
    assert sorted(r.status_code for r in responses) == [200, 401]
    winner = next(r.json() for r in responses if r.status_code == 200)
    assert (await auth_env.client.get("/api/v1/auth/me", headers=bearer(winner))).status_code == 401
    rows = (
        (await db_session.execute(select(Session).where(Session.user_id == auth_env.users[0].id)))
        .scalars()
        .all()
    )
    assert len(rows) == 2
    assert all(r.revoked_at is not None for r in rows)


async def test_replay_racing_descendant_rotation_leaves_no_live_family(auth_env, db_session):
    original = (await login(auth_env)).json()
    descendant = (await refresh(auth_env, original)).json()
    results = await asyncio.gather(refresh(auth_env, original), refresh(auth_env, descendant))
    assert results[0].status_code == 401
    assert results[1].status_code in (200, 401)
    live = (
        (
            await db_session.execute(
                select(Session).where(
                    Session.user_id == auth_env.users[0].id, Session.revoked_at.is_(None)
                )
            )
        )
        .scalars()
        .all()
    )
    assert live == []


async def test_refresh_routing_hint_cannot_switch_tenant(auth_env):
    tokens = (await login(auth_env)).json()
    tampered = dict(
        tokens,
        refresh_token=tokens["refresh_token"].replace(
            str(auth_env.tenants[0].id), str(auth_env.tenants[1].id)
        ),
    )
    response = await refresh(auth_env, tampered)
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_INVALID"
    assert (await refresh(auth_env, tokens)).status_code == 200


@pytest.mark.parametrize("mutation", ["tenant", "user", "session", "missing_session"])
async def test_signed_claims_must_match_session_and_user(auth_env, mutation):
    env = auth_env
    tokens = (await login(env)).json()
    other = (await login(env, email=env.colleague.email)).json()
    kwargs = {
        "subject": env.users[0].id,
        "tenant_id": env.tenants[0].id,
        "session_id": UUID(tokens["session_id"]),
    }
    if mutation == "tenant":
        kwargs["tenant_id"] = env.tenants[1].id
    elif mutation == "user":
        kwargs["subject"] = env.colleague.id
    elif mutation == "session":
        kwargs["session_id"] = UUID(other["session_id"])
    else:
        kwargs["session_id"] = None
    bad, _ = encode_access_token(
        secret_key=env.settings.jwt_secret_key,
        algorithm=env.settings.jwt_algorithm,
        lifetime=timedelta(minutes=5),
        **kwargs,
    )
    response = await env.client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {bad}"})
    assert response.status_code == 401, response.text


@pytest.mark.parametrize(
    "state", ["INVITED", "SUSPENDED", "LOCKED", "DISABLED", "deleted", "timed_lock"]
)
async def test_inactive_user_cannot_login_refresh_or_use_access(auth_env, db_session, state):
    env = auth_env
    tokens = (await login(env)).json()
    if state == "deleted":
        env.users[0].deleted_at = utc_now()
    elif state == "timed_lock":
        env.users[0].locked_until = utc_now() + timedelta(minutes=5)
    else:
        env.users[0].status = UserStatus(state)
    await db_session.commit()
    for response in (
        await login(env),
        await refresh(env, tokens),
        await env.client.get("/api/v1/auth/me", headers=bearer(tokens)),
    ):
        assert response.status_code in (401, 403), response.text


@pytest.mark.parametrize("state", ["SUSPENDED", "CANCELLED", "deleted"])
async def test_disabled_tenant_cannot_authenticate(auth_env, db_session, state):
    tokens = (await login(auth_env)).json()
    tenant = auth_env.tenants[0]
    if state == "deleted":
        tenant.deleted_at = utc_now()
    else:
        tenant.status = TenantStatus(state)
    await db_session.commit()
    for response in (
        await login(auth_env),
        await refresh(auth_env, tokens),
        await auth_env.client.get("/api/v1/auth/me", headers=bearer(tokens)),
    ):
        assert response.status_code in (401, 403), response.text


async def test_session_ownership_and_logout(auth_env):
    env = auth_env
    owner = (await login(env)).json()
    colleague = (await login(env, email=env.colleague.email)).json()
    foreign = (await login(env, 1)).json()
    for tokens in (colleague, foreign):
        response = await env.client.delete(
            f"/api/v1/auth/sessions/{tokens['session_id']}", headers=bearer(owner)
        )
        assert response.status_code == 404
        assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 200
    response = await env.client.post("/api/v1/auth/logout", headers=bearer(owner))
    assert response.status_code == 204, response.text
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(owner))).status_code == 401


async def test_password_change_revokes_other_sessions_and_reset_token(auth_env, db_session):
    env = auth_env
    first = (await login(env)).json()
    second = (await login(env)).json()
    env.users[0].password_reset_token_hash = hash_token(secrets.token_urlsafe(32))
    env.users[0].password_reset_expires_at = utc_now() + timedelta(hours=1)
    await db_session.commit()
    new_password = secrets.token_urlsafe(24)
    changed = await env.client.post(
        "/api/v1/auth/me/password",
        headers=bearer(first),
        json={"current_password": env.password, "new_password": new_password},
    )
    assert changed.status_code == 200, changed.text
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(first))).status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(second))).status_code == 401
    assert (await login(env)).status_code == 401
    assert (await login(env, password=new_password)).status_code == 200
    await db_session.refresh(env.users[0])
    assert env.users[0].password_reset_token_hash is None


async def test_reset_is_one_time_revokes_sessions_and_audits_correct_tenant(auth_env, db_session):
    env = auth_env
    tokens = (await login(env)).json()
    async with env.factory() as session:
        token = await service(session, env.settings).request_password_reset_in(
            env.tenants[0], email=env.users[0].email
        )
        await session.commit()
    assert token is not None
    new_password = secrets.token_urlsafe(24)
    payload = {"tenant_slug": env.tenants[0].slug, "token": token, "new_password": new_password}
    # Wrong tenant must not consume the token or revoke the real user's session.
    wrong = await env.client.post(
        "/api/v1/auth/password-reset/confirm", json=dict(payload, tenant_slug=env.tenants[1].slug)
    )
    assert wrong.status_code == 401
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 200
    response = await env.client.post("/api/v1/auth/password-reset/confirm", json=payload)
    assert response.status_code == 200, response.text
    assert (
        await env.client.post("/api/v1/auth/password-reset/confirm", json=payload)
    ).status_code == 401
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 401
    assert (await login(env, password=new_password)).status_code == 200
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.tenant_id == env.tenants[0].id, AuditLog.action == "user.password_reset"
            )
        )
    ).scalar_one()
    assert audit.actor_user_id == env.users[0].id


async def test_reset_request_is_neutral_and_labels_local_delivery(auth_env, db_session):
    bodies = []
    for slug, email in [
        (auth_env.tenants[0].slug, auth_env.users[0].email),
        (auth_env.tenants[0].slug, "absent@example.test"),
        ("missing-tenant", "absent@example.test"),
    ]:
        response = await auth_env.client.post(
            "/api/v1/auth/password-reset", json={"tenant_slug": slug, "email": email}
        )
        assert response.status_code == 202, response.text
        bodies.append(response.json())
    assert bodies[0] == bodies[1] == bodies[2]
    assert bodies[0]["delivery_status"] == "queued_if_eligible"
    assert bodies[0]["delivery_mode"] == "local_mailbox"
    assert "token" not in bodies[0]
    # Suspended tenants must not be enumerable through a distinct reset response.
    auth_env.tenants[0].status = TenantStatus.SUSPENDED
    await db_session.commit()
    response = await auth_env.client.post(
        "/api/v1/auth/password-reset",
        json={"tenant_slug": auth_env.tenants[0].slug, "email": auth_env.users[0].email},
    )
    assert response.json() == bodies[0]


async def test_invitation_requires_permission_and_does_not_create_session(auth_env, db_session):
    env = auth_env
    tokens = (await login(env)).json()
    payload = {"email": "invited@example.test", "password": env.password, "full_name": "Invited"}
    denied = await env.client.post("/api/v1/auth/users", headers=bearer(tokens), json=payload)
    assert denied.status_code == 403
    permission = (
        await db_session.execute(select(Permission).where(Permission.code == "users.write"))
    ).scalar_one()
    role = Role(id=uuid4(), tenant_id=env.tenants[0].id, code="TEST_INVITER", name="Inviter")
    db_session.add(role)
    await db_session.flush()
    db_session.add_all(
        [
            RolePermission(
                role_id=role.id, permission_id=permission.id, tenant_id=env.tenants[0].id
            ),
            UserRole(user_id=env.users[0].id, role_id=role.id, tenant_id=env.tenants[0].id),
        ]
    )
    await db_session.commit()
    response = await env.client.post("/api/v1/auth/users", headers=bearer(tokens), json=payload)
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "INVITED"
    assert "token" not in response.text
    rows = (
        (
            await db_session.execute(
                select(Session).where(Session.user_id == UUID(response.json()["id"]))
            )
        )
        .scalars()
        .all()
    )
    assert rows == []
    assert (await login(env, email=payload["email"])).status_code == 403


async def test_services_recheck_permission_and_session_ownership(auth_env):
    env = auth_env
    other = (await login(env, email=env.colleague.email)).json()
    actor = Actor(
        user_id=env.users[0].id,
        tenant_id=env.tenants[0].id,
        email=env.users[0].email,
        full_name="Test",
        roles=frozenset(),
        permissions=frozenset(),
    )
    async with env.factory() as session:
        await apply_tenant_context(session, actor.tenant_id)
        auth = service(session, env.settings, actor.tenant_id)
        with pytest.raises(PermissionDeniedError):
            await auth.register(
                email="denied@example.test", password=env.password, full_name="Denied", actor=actor
            )
        with pytest.raises(NotFoundError):
            await auth.logout(UUID(other["session_id"]), actor=actor)
        with pytest.raises(NotFoundError):
            await auth.logout_all(env.colleague.id, actor=actor)
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(other))).status_code == 200


async def test_invalid_password_change_rolls_back_and_keeps_sessions(auth_env, db_session):
    env = auth_env
    tokens = (await login(env)).json()
    response = await env.client.post(
        "/api/v1/auth/me/password",
        headers=bearer(tokens),
        json={"current_password": env.password, "new_password": "passwordpassword"},
    )
    assert response.status_code == 400, response.text
    assert (await login(env)).status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 200


@pytest.mark.parametrize(
    "token", ["x" * 64, "rt1.invalid." + "a" * 64, "rt1." + str(uuid4()) + ".short"]
)
async def test_legacy_or_malformed_refresh_is_rejected(auth_env, token):
    response = await refresh(auth_env, {"refresh_token": token})
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_INVALID"


async def test_wrong_password_change_persists_failure_count(auth_env, db_session):
    tokens = (await login(auth_env)).json()
    response = await auth_env.client.post(
        "/api/v1/auth/me/password",
        headers=bearer(tokens),
        json={
            "current_password": secrets.token_urlsafe(24),
            "new_password": secrets.token_urlsafe(24),
        },
    )
    assert response.status_code == 401
    await db_session.refresh(auth_env.users[0])
    assert auth_env.users[0].failed_login_attempts == 1


async def test_internal_failure_rolls_back_login_writes(auth_env, db_session, monkeypatch):
    async def fail_record(*args, **kwargs):
        raise RuntimeError("injected audit failure")

    monkeypatch.setattr(AuditLogRepository, "record", fail_record)
    response = await login(auth_env)
    assert response.status_code == 500
    assert response.json()["error"]["code"] == "INTERNAL_ERROR"
    assert "injected audit failure" not in response.text
    await db_session.refresh(auth_env.users[0])
    assert auth_env.users[0].last_login_at is None
    rows = (
        (await db_session.execute(select(Session).where(Session.user_id == auth_env.users[0].id)))
        .scalars()
        .all()
    )
    assert rows == []


async def test_logout_of_rotated_session_revokes_its_descendant(auth_env):
    """Models a logout whose authentication finished before a concurrent refresh."""
    env = auth_env
    original = (await login(env)).json()
    descendant = (await refresh(env, original)).json()
    actor = Actor(
        user_id=env.users[0].id,
        tenant_id=env.tenants[0].id,
        email=env.users[0].email,
        full_name="Test",
        roles=frozenset(),
        permissions=frozenset(),
        session_id=UUID(original["session_id"]),
    )
    async with env.factory() as session:
        await apply_tenant_context(session, actor.tenant_id)
        await service(session, env.settings, actor.tenant_id).logout(actor.session_id, actor=actor)
        await session.commit()
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(descendant))).status_code == 401


async def test_expired_session_cannot_refresh_or_authenticate(auth_env, db_session):
    tokens = (await login(auth_env)).json()
    row = await db_session.get(Session, UUID(tokens["session_id"]))
    row.expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    assert (await refresh(auth_env, tokens)).status_code == 401
    assert (await auth_env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 401


async def test_expired_reset_token_leaves_password_and_sessions_unchanged(auth_env, db_session):
    env = auth_env
    tokens = (await login(env)).json()
    token = secrets.token_urlsafe(32)
    env.users[0].password_reset_token_hash = hash_token(token)
    env.users[0].password_reset_expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    response = await env.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "tenant_slug": env.tenants[0].slug,
            "token": token,
            "new_password": secrets.token_urlsafe(24),
        },
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_EXPIRED"
    assert (await login(env)).status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(tokens))).status_code == 200
