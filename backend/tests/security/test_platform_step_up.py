"""Fresh password confirmation under real bearer auth, SQL transactions and RLS."""

from __future__ import annotations

import asyncio
import json
import secrets
from dataclasses import replace
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import PermissionDeniedError
from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.models.identity import AuditLog, Session, User
from app.repositories.identity import AuditLogRepository
from app.services.auth import MAX_FAILED_LOGINS
from app.services.platform_access import PlatformAccessService
from app.services.platform_step_up import PlatformStepUpService
from app.services.platform_tenants import PlatformTenantService

from .support import bearer, refresh
from .test_platform_tenants import BASE, REASON, payload
from .test_platform_tenants import platform_env as platform_env

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]
PATH = "/api/v1/platform/auth/step-up"


async def confirm(env, password=None, headers=None):
    return await env.client.post(
        PATH,
        headers=headers or env.operator_headers,
        json={"password": env.password if password is None else password},
    )


async def clear(env):
    result = await env.client.delete(PATH, headers=env.operator_headers)
    assert result.status_code == 204


async def current_session(db, env):
    return (
        await db.execute(
            select(Session)
            .where(Session.id == UUID(env.operator_tokens["session_id"]))
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


async def test_confirmation_is_explicit_private_and_session_bound(platform_env, db_session, caplog):
    env = platform_env
    await clear(env)
    denied = await env.client.post(BASE, headers=env.operator_headers, json=payload())
    assert denied.status_code == 403 and "step_up_required" in denied.text
    assert (await env.client.get(BASE, headers=env.operator_headers)).status_code == 200
    result = await confirm(env)
    assert result.status_code == 200
    assert set(result.json()) == {"method", "expires_at"}
    assert result.json()["method"] == "password"
    assert result.headers["cache-control"] == "no-store"
    assert env.password not in result.text + caplog.text
    row = await current_session(db_session, env)
    assert row.platform_reauthenticated_at is not None
    # A second ordinary password login does not inherit proof from the first.
    other = await env.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "ecomind-platform",
            "email": env.operator_email,
            "password": env.password,
        },
    )
    assert other.status_code == 200
    denied = await env.client.post(
        BASE + "/" + str(env.tenants[0].id) + "/suspend", headers=bearer(other.json()), json=REASON
    )
    assert denied.status_code == 403
    assert (
        await env.client.post(
            BASE + "/" + str(env.tenants[0].id) + "/suspend",
            headers=env.operator_headers,
            json=REASON,
        )
    ).status_code == 200
    await clear(env)
    await clear(env)
    assert (
        await env.client.get("/api/v1/auth/me", headers=env.operator_headers)
    ).status_code == 200
    events = list(
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == PLATFORM_SCOPE_ID,
                    AuditLog.action.like("platform.step_up.%"),
                )
            )
        ).scalars()
    )
    assert all(e.actor_user_id == env.operator_id for e in events)
    assert env.password not in json.dumps([e.event_metadata for e in events])


@pytest.mark.parametrize("mutation", ["create", "update", "suspend", "activate"])
async def test_every_platform_mutation_requires_proof_at_service_boundary(platform_env, mutation):
    env = platform_env
    await clear(env)
    async with env.factory() as session:
        service = PlatformTenantService(session, env.operator, env.settings)
        with pytest.raises(PermissionDeniedError):
            if mutation == "create":
                await service.create_tenant_platform(**payload())
            elif mutation == "update":
                await service.update_tenant_platform(
                    env.tenants[0].id, values={"name": "Denied"}, **REASON
                )
            else:
                await service.set_status_platform(
                    env.tenants[0].id, suspended=mutation == "suspend", **REASON
                )


@pytest.mark.parametrize("state", ["missing", "expired", "future", "pre_session"])
async def test_stored_confirmation_cannot_extend_or_backdate_authority(
    platform_env, db_session, state
):
    env = platform_env
    row = await current_session(db_session, env)
    row.platform_reauthenticated_at = {
        "missing": None,
        "expired": utc_now() - timedelta(minutes=6),
        "future": utc_now() + timedelta(minutes=1),
        "pre_session": row.issued_at - timedelta(seconds=1),
    }[state]
    await db_session.commit()
    result = await env.client.post(
        BASE + "/" + str(env.tenants[0].id) + "/suspend", headers=env.operator_headers, json=REASON
    )
    assert result.status_code == 403


async def test_wrong_password_clears_proof_and_commits_failure_evidence(
    platform_env, db_session, caplog
):
    env = platform_env
    wrong = secrets.token_urlsafe(24)
    result = await confirm(env, wrong)
    assert result.status_code == 401 and result.headers["cache-control"] == "no-store"
    row = await current_session(db_session, env)
    assert row.platform_reauthenticated_at is None
    user = await db_session.get(User, env.operator_id)
    assert user.failed_login_attempts == 1
    events = list(
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == PLATFORM_SCOPE_ID,
                    AuditLog.outcome == "DENIED",
                    AuditLog.action == "platform.step_up.confirm",
                )
            )
        ).scalars()
    )
    assert len(events) == 1
    assert wrong not in result.text + caplog.text + json.dumps(events[0].event_metadata)
    assert (await confirm(env)).status_code == 200
    await db_session.refresh(user)
    assert user.failed_login_attempts == 0


async def test_repeated_failure_locks_operator_and_blocks_prior_lease(platform_env, db_session):
    env = platform_env
    for _ in range(MAX_FAILED_LOGINS):
        assert (await confirm(env, secrets.token_urlsafe(24))).status_code == 401
    assert (await confirm(env)).status_code == 403
    user = await db_session.get(User, env.operator_id)
    assert user.locked_until > utc_now()
    assert (await env.client.get(BASE, headers=env.operator_headers)).status_code == 403


async def test_refresh_never_inherits_confirmation(platform_env, db_session):
    env = platform_env
    result = await refresh(env, env.operator_tokens)
    assert result.status_code == 200
    headers = bearer(result.json())
    assert (await env.client.post(BASE, headers=headers, json=payload())).status_code == 403
    assert (await confirm(env, headers=headers)).status_code == 200
    row = await db_session.get(Session, UUID(result.json()["session_id"]))
    assert row.platform_reauthenticated_at is not None
    assert (await confirm(env)).status_code == 401


async def test_password_change_clears_kept_session_confirmation(platform_env, db_session):
    env = platform_env
    new = secrets.token_urlsafe(24)
    changed = await env.client.post(
        "/api/v1/auth/me/password",
        headers=env.operator_headers,
        json={"current_password": env.password, "new_password": new},
    )
    assert changed.status_code == 200, changed.text
    assert (await current_session(db_session, env)).platform_reauthenticated_at is None
    assert (
        await env.client.get("/api/v1/auth/me", headers=env.operator_headers)
    ).status_code == 200
    assert (
        await env.client.post(BASE, headers=env.operator_headers, json=payload())
    ).status_code == 403
    assert (await confirm(env, new)).status_code == 200


@pytest.mark.parametrize("action", ["success", "failure", "clear", "commit"])
async def test_audit_or_commit_failure_cannot_change_confirmation(
    platform_env, db_session, monkeypatch, action
):
    env = platform_env
    if action in ("success", "commit"):
        await clear(env)
    before = (await current_session(db_session, env)).platform_reauthenticated_at

    async def fail(*args, **kwargs):
        raise RuntimeError("Controlled persistence failure")

    with monkeypatch.context() as patch:
        if action == "commit":
            patch.setattr(AsyncSession, "commit", fail)
        else:
            patch.setattr(AuditLogRepository, "record", fail)
        result = (
            (await env.client.delete(PATH, headers=env.operator_headers))
            if action == "clear"
            else await confirm(env, secrets.token_urlsafe(24) if action == "failure" else None)
        )
    assert result.status_code == 500
    assert "expires_at" not in result.text and env.password not in result.text
    assert (await current_session(db_session, env)).platform_reauthenticated_at == before
    user = await db_session.get(User, env.operator_id)
    assert user.failed_login_attempts == 0


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"password": None},
        {"password": ""},
        {"password": "x" * 129},
        {"password": "unused", "tenant_id": str(uuid4())},
        {"password": "unused", "method": "totp"},
        {"password": "unused", "expires_at": "2099-01-01T00:00:00Z"},
    ],
)
async def test_closed_confirmation_contract(platform_env, body):
    env = platform_env
    result = await env.client.post(PATH, headers=env.operator_headers, json=body)
    assert result.status_code == 400
    assert result.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("method", ["POST", "DELETE"])
async def test_anonymous_and_tenant_bearers_cannot_confirm(platform_env, method):
    env = platform_env
    kwargs = {"json": {"password": env.password}} if method == "POST" else {}
    assert (await env.client.request(method, PATH, **kwargs)).status_code == 401
    assert (
        await env.client.request(method, PATH, headers=env.headers, **kwargs)
    ).status_code == 403


@pytest.mark.parametrize(
    "change",
    [
        {"auth_type": "API_KEY"},
        {"auth_type": "SYSTEM"},
        {"tenant_id": uuid4()},
        {"is_platform_operator": False},
        {"session_id": None},
        {"session_id": uuid4()},
        {"permissions": frozenset()},
    ],
)
async def test_direct_confirmation_rejects_forged_actor(platform_env, change):
    env = platform_env
    async with env.factory() as session:
        with pytest.raises(PermissionDeniedError):
            await PlatformStepUpService(
                session, replace(env.operator, **change), env.settings
            ).confirm(env.password)


async def test_ip_budget_applies_before_body_validation(platform_env, app):
    env = platform_env
    app.state.auth_rate_limiter.counter.entries.clear()
    env.settings.auth_ip_limit = 1
    result = await env.client.post(
        PATH, content="invalid json", headers={"content-type": "application/json"}
    )
    assert result.status_code == 400
    result = await confirm(env)
    assert result.status_code == 429 and result.headers["cache-control"] == "no-store"


async def test_account_budget_spans_operator_sessions(platform_env, app):
    env = platform_env
    app.state.auth_rate_limiter.counter.entries.clear()
    env.settings.auth_account_limit = 1
    assert (await confirm(env)).status_code == 200
    result = await env.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "ecomind-platform",
            "email": env.operator_email,
            "password": env.password,
        },
    )
    assert result.status_code == 200
    assert (await confirm(env, headers=bearer(result.json()))).status_code == 429


async def test_limiter_unavailable_fails_closed(platform_env, app, monkeypatch):
    async def unavailable(*args):
        raise RuntimeError("Counter unavailable")

    monkeypatch.setattr(app.state.auth_rate_limiter.counter, "hit", unavailable)
    assert (await confirm(platform_env)).status_code == 503


async def test_cleared_lease_is_reloaded_despite_cached_session(platform_env, monkeypatch):
    env = platform_env
    # Keep a strong ORM reference while another transaction clears the lease.
    # SQLAlchemy's identity map alone only holds weak references.
    ready = asyncio.Event()
    release = asyncio.Event()
    original = PlatformAccessService._authorize_platform

    async def pause(self, permission):
        if isinstance(self, PlatformTenantService):
            cached = await self.session.get(Session, env.operator.session_id)
            assert cached.platform_reauthenticated_at is not None
            ready.set()
            await asyncio.wait_for(release.wait(), 10)
            return await original(self, permission)
        return await original(self, permission)

    monkeypatch.setattr(PlatformAccessService, "_authorize_platform", pause)
    task = asyncio.create_task(
        env.client.post(
            BASE + "/" + str(env.tenants[0].id) + "/suspend",
            headers=env.operator_headers,
            json=REASON,
        )
    )
    try:
        await asyncio.wait_for(ready.wait(), 5)
        await clear(env)
        release.set()
        result = await asyncio.wait_for(task, 5)
        assert result.status_code == 403
    finally:
        release.set()
        if not task.done():
            task.cancel()
        await asyncio.gather(task, return_exceptions=True)
