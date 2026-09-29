"""Operator custody changes under actual bearer auth, non-superuser SQL and RLS."""

from __future__ import annotations

import asyncio
import secrets
from copy import copy
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.time import utc_now
from app.db.base import PLATFORM_SCOPE_ID
from app.models.auth_mail import AuthMail
from app.models.identity import AuditLog, Session, User, UserRole
from app.repositories.identity import AuditLogRepository

from .support import bearer, refresh
from .test_platform_mfa import code, confirm, enroll, write
from .test_platform_mfa import mfa_env as mfa_env
from .test_platform_tenants import REASON, delivered_code
from .test_platform_tenants import platform_env as platform_env

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]
PATH = "/api/v1/platform/operators"


@pytest.fixture
async def operator_env(mfa_env):
    env = mfa_env
    env.seed, env.recovery = await enroll(env)
    assert (await confirm(env, totp_code=code(env, env.seed))).status_code == 200
    return env


async def invite(env, **overrides):
    return await env.client.post(
        PATH,
        headers=env.operator_headers,
        json={
            "email": "second.operator@example.test",
            "full_name": "Second operator",
            **REASON,
            **overrides,
        },
    )


async def action(env, user_id, action_name, **overrides):
    return await env.client.post(
        PATH + "/" + str(user_id) + "/" + action_name,
        headers=env.operator_headers,
        json={**REASON, **overrides},
    )


async def read_user(db, user_id):
    return (
        await db.execute(
            select(User).where(User.id == user_id).execution_options(populate_existing=True)
        )
    ).scalar_one()


async def mail_code(env, db, user_id, purpose):
    row = (
        await db.execute(
            select(AuthMail).where(
                AuthMail.user_id == user_id,
                AuthMail.status == "PENDING",
                AuthMail.purpose == purpose,
            )
        )
    ).scalar_one()
    return await delivered_code(env, row, expected_recipient="second.operator@example.test")


async def onboarding(env, db, *, enrolled=True):
    response = await invite(env)
    assert response.status_code == 201, response.text
    second = copy(env)
    second.operator_id = UUID(response.json()["id"])
    second.operator_email = response.json()["email"]
    token = await mail_code(env, db, second.operator_id, "EMAIL_VERIFICATION")
    verified = await env.client.post(
        "/api/v1/auth/email/verify-confirm",
        json={"tenant_slug": "ecomind-platform", "token": token},
    )
    assert verified.status_code == 200, verified.text
    reset = await env.client.post(
        "/api/v1/auth/password-reset",
        json={"tenant_slug": "ecomind-platform", "email": second.operator_email},
    )
    assert reset.status_code == 202
    token = await mail_code(env, db, second.operator_id, "PASSWORD_RESET")
    second.password = secrets.token_urlsafe(24)
    changed = await env.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"tenant_slug": "ecomind-platform", "token": token, "new_password": second.password},
    )
    assert changed.status_code == 200
    login = await env.client.post(
        "/api/v1/auth/login",
        json={
            "tenant_slug": "ecomind-platform",
            "email": second.operator_email,
            "password": second.password,
        },
    )
    assert login.status_code == 200
    second.operator_tokens = login.json()
    second.operator_headers = bearer(second.operator_tokens)
    if enrolled:
        second.seed, second.recovery = await enroll(second)
        assert (await confirm(second, totp_code=code(second, second.seed))).status_code == 200
    return second


async def test_invitation_delivered_onboarding_requires_mfa_before_writes(
    operator_env, db_session, caplog
):
    env = operator_env
    second = await onboarding(env, db_session, enrolled=False)
    assert (await confirm(second)).status_code == 200  # no MFA claim, still cannot write
    assert (await write(second)).status_code == 403
    assert (await invite(second, email="third@example.test")).status_code == 403
    own_status = await env.client.get("/api/v1/platform/auth/mfa", headers=second.operator_headers)
    assert own_status.json()["required_for_platform_actions"] is True
    second.seed, _ = await enroll(second)
    assert (await confirm(second, totp_code=code(second, second.seed))).status_code == 200
    assert (await write(second)).status_code == 200
    result = await env.client.get(PATH, headers=env.operator_headers)
    assert result.status_code == 200 and result.json()["meta"]["total_items"] == 2
    assert result.headers["cache-control"] == "no-store"
    assert all(item["email"] != env.users[0].email for item in result.json()["items"])
    assert (await invite(env)).status_code == 409
    row = await read_user(db_session, second.operator_id)
    for value in (
        row.password_hash,
        row.mfa_secret_encrypted,
        *row.mfa_recovery_hashes,
        env.seed,
        second.seed,
    ):
        assert value not in result.text + caplog.text
    assert (
        await env.client.get(PATH + "/" + str(env.users[0].id), headers=env.operator_headers)
    ).status_code == 404


async def test_lifecycle_never_accepts_password_only_even_for_legacy_operator(platform_env):
    env = platform_env
    assert (await invite(env)).status_code == 403
    for method in ("suspend", "activate", "require-mfa"):
        assert (await action(env, env.operator_id, method)).status_code == 403
    assert (await env.client.get(PATH, headers=env.operator_headers)).status_code == 200


async def test_last_operator_guard_then_self_suspension_with_mfa_successor(
    operator_env, db_session
):
    env = operator_env
    denied = await action(env, env.operator_id, "suspend")
    assert denied.status_code == 422 and "BR-PLATFORM-LAST-OPERATOR" in denied.text
    second = await onboarding(env, db_session)
    assert (await action(env, env.operator_id, "suspend")).status_code == 200
    assert (await confirm(env, recovery_code=env.recovery[0])).status_code == 401
    assert (await action(second, second.operator_id, "suspend")).status_code == 422
    # Bootstrap email was not verified, so reactivation cannot declare it verified.
    activated = await action(second, env.operator_id, "activate")
    assert activated.status_code == 200 and activated.json()["status"] == "INVITED"
    row = await read_user(db_session, env.operator_id)
    assert row.mfa_secret_encrypted is not None


async def test_suspension_revokes_sessions_pending_authority_and_codes_not_active_factor(
    operator_env, db_session
):
    env = operator_env
    second = await onboarding(env, db_session)
    from .test_platform_mfa import start

    assert (await start(second)).status_code == 201
    assert (
        await env.client.post(
            "/api/v1/auth/password-reset",
            json={"tenant_slug": "ecomind-platform", "email": second.operator_email},
        )
    ).status_code == 202
    before = await read_user(db_session, second.operator_id)
    factor, backups = before.mfa_secret_encrypted, list(before.mfa_recovery_hashes)
    result = await action(env, second.operator_id, "suspend")
    assert result.status_code == 200
    row = await read_user(db_session, second.operator_id)
    assert row.mfa_secret_encrypted == factor and row.mfa_recovery_hashes == backups
    assert row.platform_mfa_required is True
    assert row.mfa_pending_secret_encrypted is None and row.password_reset_token_hash is None
    assert row.email_verification_token_hash is None
    assert (await refresh(env, second.operator_tokens)).status_code == 401
    assert (await action(env, second.operator_id, "activate")).json()["status"] == "ACTIVE"
    assert (await write(second)).status_code == 401
    sessions = (
        (await db_session.execute(select(Session).where(Session.user_id == second.operator_id)))
        .scalars()
        .all()
    )
    assert all(s.revoked_at is not None and s.platform_mfa_verified_at is None for s in sessions)


async def test_require_mfa_is_one_way_and_clears_even_current_proof(operator_env, db_session):
    env = operator_env
    assert (await read_user(db_session, env.operator_id)).platform_mfa_required is False
    result = await action(env, env.operator_id, "require-mfa")
    assert result.status_code == 200 and result.json()["platform_mfa_required"] is True
    assert (await write(env)).status_code == 403
    assert (await confirm(env, totp_code=code(env, env.seed))).status_code == 200
    assert (await write(env)).status_code == 200
    assert (
        await action(env, env.operator_id, "require-mfa", platform_mfa_required=False)
    ).status_code == 400


@pytest.mark.parametrize(
    "state", ["unenrolled", "locked", "expired_grant", "temporary_grant", "bad_cipher", "disabled"]
)
async def test_unusable_or_temporary_successor_does_not_satisfy_last_operator(
    operator_env, db_session, state
):
    env = operator_env
    second = await onboarding(env, db_session, enrolled=state != "unenrolled")
    row = await read_user(db_session, second.operator_id)
    if state == "locked":
        row.locked_until = utc_now() + timedelta(minutes=5)
    elif state == "bad_cipher":
        row.mfa_secret_encrypted = "unreadable"
    elif state == "disabled":
        row.status = "DISABLED"
    elif state in {"expired_grant", "temporary_grant"}:
        await db_session.execute(
            update(UserRole)
            .where(UserRole.user_id == second.operator_id)
            .values(expires_at=utc_now() + timedelta(minutes=-1 if state == "expired_grant" else 5))
        )
    await db_session.commit()
    assert (await action(env, env.operator_id, "suspend")).status_code == 422


async def test_concurrent_cross_suspensions_leave_an_active_operator(operator_env, db_session):
    env = operator_env
    second = await onboarding(env, db_session)
    responses = await asyncio.wait_for(
        asyncio.gather(
            action(env, second.operator_id, "suspend"), action(second, env.operator_id, "suspend")
        ),
        timeout=15,
    )
    assert sum(r.status_code == 200 for r in responses) == 1
    assert all(r.status_code in {200, 401, 403} for r in responses)
    rows = (
        (
            await db_session.execute(
                select(User)
                .where(User.id.in_([env.operator_id, second.operator_id]))
                .execution_options(populate_existing=True)
            )
        )
        .scalars()
        .all()
    )
    assert sum(r.status.value == "ACTIVE" for r in rows) == 1


@pytest.mark.parametrize("failure", ["audit", "commit", "delivery"])
async def test_failed_invitation_has_no_user_grant_or_delivery(
    operator_env, db_session, monkeypatch, failure
):
    from app.services.auth_delivery import AuthDelivery

    env = operator_env

    async def fail(*args, **kwargs):
        raise RuntimeError("Controlled persistence failure")

    with monkeypatch.context() as patch:
        target, method = {
            "audit": (AuditLogRepository, "record"),
            "commit": (AsyncSession, "commit"),
            "delivery": (AuthDelivery, "enqueue"),
        }[failure]
        patch.setattr(target, method, fail)
        result = await invite(env)
    assert result.status_code == 500 and result.headers["cache-control"] == "no-store"
    assert (
        await db_session.execute(
            select(User.id).where(User.email == "second.operator@example.test")
        )
    ).first() is None
    assert (
        await db_session.execute(select(AuthMail.id).where(AuthMail.tenant_id == PLATFORM_SCOPE_ID))
    ).first() is None


@pytest.mark.parametrize("failure", ["audit", "commit"])
@pytest.mark.parametrize("operation", ["suspend", "activate", "require-mfa"])
async def test_mutation_audit_failure_rolls_back(
    operator_env, db_session, monkeypatch, operation, failure
):
    env = operator_env
    second = await onboarding(env, db_session)
    if operation == "activate":
        assert (await action(env, second.operator_id, "suspend")).status_code == 200
    target = await read_user(db_session, second.operator_id)
    before = target.status
    if operation == "require-mfa":
        target.platform_mfa_required = False
    await db_session.commit()

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(
            AsyncSession if failure == "commit" else AuditLogRepository,
            "commit" if failure == "commit" else "record",
            fail,
        )
        result = await action(env, second.operator_id, operation)
    assert result.status_code == 500
    row = await read_user(db_session, second.operator_id)
    assert row.status == before
    if operation == "require-mfa":
        assert row.platform_mfa_required is False
    if operation != "activate":
        assert (await write(second)).status_code == 200


@pytest.mark.parametrize("route", ["", "/suspend", "/activate", "/require-mfa"])
async def test_anonymous_and_tenant_accounts_cannot_manage_operators(operator_env, route):
    env = operator_env
    url = PATH + ("/" + str(env.operator_id) + route if route else "")
    body = REASON if route else {"email": "unused@example.test", "full_name": "Unused", **REASON}
    assert (await env.client.post(url, json=body)).status_code == 401
    assert (await env.client.post(url, headers=env.headers, json=body)).status_code == 403


@pytest.mark.parametrize(
    "field,value",
    [
        ("tenant_id", str(uuid4())),
        ("role", "SUPER_ADMIN"),
        ("password", "not-accepted"),
        ("platform_mfa_required", False),
        ("reason", "short"),
    ],
)
async def test_invitation_contract_is_closed(operator_env, field, value):
    result = await invite(operator_env, **{field: value})
    assert result.status_code == 400 and result.headers["cache-control"] == "no-store"


async def test_pending_invitation_can_be_suspended_without_bypassing_mailbox_proof(
    operator_env, db_session
):
    env = operator_env
    result = await invite(env)
    assert result.status_code == 201
    user_id = UUID(result.json()["id"])
    assert (await action(env, user_id, "suspend")).status_code == 200
    assert (await action(env, user_id, "activate")).json()["status"] == "INVITED"
    row = await read_user(db_session, user_id)
    assert row.email_verified_at is None and row.email_verification_token_hash is None


async def test_operator_rate_budget_is_shared_and_precedes_bad_body(operator_env, app):
    env = operator_env
    env.settings.auth_ip_limit = 1
    app.state.auth_rate_limiter.counter.entries.clear()
    for expected in (400, 429):
        response = await env.client.post(
            PATH, headers={**env.operator_headers, "Content-Type": "application/json"}, content="{"
        )
        assert response.status_code == expected and response.headers["cache-control"] == "no-store"
    env.settings.auth_ip_limit = 100
    env.settings.auth_account_limit = 1
    app.state.auth_rate_limiter.counter.entries.clear()
    result = await invite(env)
    assert result.status_code == 201
    assert (await action(env, UUID(result.json()["id"]), "suspend")).status_code == 429


@pytest.mark.parametrize("state", ["expired_proof", "wrong_factor", "revoked_grant"])
async def test_live_proof_and_grants_are_rechecked(operator_env, db_session, state):
    env = operator_env
    if state == "revoked_grant":
        await db_session.execute(
            update(UserRole)
            .where(UserRole.user_id == env.operator_id)
            .values(expires_at=utc_now() - timedelta(seconds=1))
        )
    elif state == "wrong_factor":
        await db_session.execute(
            update(Session)
            .where(Session.user_id == env.operator_id)
            .values(platform_mfa_factor_id=uuid4())
        )
    else:
        old = utc_now() - timedelta(minutes=6)
        await db_session.execute(
            update(Session)
            .where(Session.user_id == env.operator_id)
            .values(platform_reauthenticated_at=old, platform_mfa_verified_at=old)
        )
    await db_session.commit()
    assert (await invite(env)).status_code == 403


async def test_partial_operator_manager_cannot_issue_full_admin_role(operator_env, db_session):
    from sqlalchemy import delete

    from app.authorization.permissions import PLATFORM_PERMISSION_CODES
    from app.models.identity import Permission, Role, RolePermission

    env = operator_env
    role = Role(
        tenant_id=PLATFORM_SCOPE_ID,
        code="LIMITED_OPERATOR",
        name="Limited manager",
        is_system=False,
    )
    db_session.add(role)
    await db_session.flush()
    env.extra_roles.append(role.id)
    permissions = (
        (
            await db_session.execute(
                select(Permission).where(
                    Permission.code.in_(
                        PLATFORM_PERMISSION_CODES - {"platform.break_glass.activate"}
                    )
                )
            )
        )
        .scalars()
        .all()
    )
    db_session.add_all(
        [
            RolePermission(tenant_id=PLATFORM_SCOPE_ID, role_id=role.id, permission_id=p.id)
            for p in permissions
        ]
    )
    await db_session.execute(delete(UserRole).where(UserRole.user_id == env.operator_id))
    db_session.add(UserRole(tenant_id=PLATFORM_SCOPE_ID, user_id=env.operator_id, role_id=role.id))
    await db_session.commit()
    assert (await env.client.get(PATH, headers=env.operator_headers)).status_code == 200
    assert (await invite(env)).status_code == 403


@pytest.mark.parametrize("state", ["DISABLED", "LOCKED", "deleted"])
async def test_lifecycle_cannot_repair_disabled_locked_or_deleted_operators(
    operator_env, db_session, state
):
    env = operator_env
    result = await invite(env)
    user_id = UUID(result.json()["id"])
    user = await read_user(db_session, user_id)
    if state == "deleted":
        user.deleted_at = utc_now()
    else:
        user.status = state
    await db_session.commit()
    for verb in ("activate", "suspend", "require-mfa"):
        assert (await action(env, user_id, verb)).status_code == (
            404 if state == "deleted" else 409
        )
    assert (await invite(env)).status_code == 409  # email stays reserved


async def test_mandating_mfa_immediately_closes_legacy_password_window(operator_env, db_session):
    env = operator_env
    second = await onboarding(env, db_session, enrolled=False)
    # Simulate an existing legacy account, not a writable API option.
    user = await read_user(db_session, second.operator_id)
    user.platform_mfa_required = False
    await db_session.commit()
    assert (await confirm(second)).status_code == 200
    assert (await write(second)).status_code == 200
    assert (await action(env, second.operator_id, "require-mfa")).status_code == 200
    assert (await confirm(second)).status_code == 200
    assert (await write(second)).status_code == 403
    second.seed, _ = await enroll(second)
    assert (await confirm(second, totp_code=code(second, second.seed))).status_code == 200
    assert (await write(second)).status_code == 200


async def test_reads_are_audited_and_fail_closed_on_audit_error(
    operator_env, monkeypatch, db_session
):
    env = operator_env
    result = await env.client.get(PATH + "/" + str(env.operator_id), headers=env.operator_headers)
    assert result.status_code == 200
    events = (
        (
            await db_session.execute(
                select(AuditLog).where(AuditLog.action == "platform.operator.read")
            )
        )
        .scalars()
        .all()
    )
    assert events and events[-1].resource_id == str(env.operator_id)

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    monkeypatch.setattr(AuditLogRepository, "record", fail)
    failed = await env.client.get(PATH, headers=env.operator_headers)
    assert failed.status_code == 500 and env.operator_email not in failed.text


async def test_unavailable_operator_limiter_denies_before_mutation(operator_env, app, monkeypatch):
    async def unavailable(*args):
        raise RuntimeError("Counter unavailable")

    monkeypatch.setattr(app.state.auth_rate_limiter.counter, "hit", unavailable)
    response = await invite(operator_env)
    assert response.status_code == 503 and response.headers["cache-control"] == "no-store"


async def test_concurrent_self_suspensions_cannot_remove_both_managers(operator_env, db_session):
    env = operator_env
    second = await onboarding(env, db_session)
    results = await asyncio.wait_for(
        asyncio.gather(
            action(env, env.operator_id, "suspend"), action(second, second.operator_id, "suspend")
        ),
        timeout=15,
    )
    assert sorted(result.status_code for result in results) == [200, 422]


async def test_cached_user_cannot_ignore_new_mfa_policy_in_direct_service(operator_env, db_session):
    from dataclasses import replace

    from app.core.errors import PermissionDeniedError
    from app.services.platform_tenants import PlatformTenantService

    env = operator_env
    second = await onboarding(env, db_session, enrolled=False)
    row = await read_user(db_session, second.operator_id)
    row.platform_mfa_required = False
    await db_session.commit()
    assert (await confirm(second)).status_code == 200
    held_user = await read_user(db_session, second.operator_id)
    held_session = await db_session.get(Session, UUID(second.operator_tokens["session_id"]))
    assert held_user.platform_mfa_required is False and held_session.platform_reauthenticated_at
    assert (await action(env, second.operator_id, "require-mfa")).status_code == 200
    # A newly issued password-only confirmation must not revive old policy.
    assert (await confirm(second)).status_code == 200
    actor = replace(
        env.operator,
        user_id=second.operator_id,
        session_id=UUID(second.operator_tokens["session_id"]),
    )
    service = PlatformTenantService(db_session, actor, env.settings)
    with pytest.raises(PermissionDeniedError):
        await service.update_tenant_platform(
            env.tenants[0].id, reason=REASON["reason"], values={"name": "Not authorized"}
        )
    assert held_user.platform_mfa_required is True
    await db_session.rollback()


@pytest.mark.parametrize(
    "query", [{"page": 0}, {"page_size": 101}, {"tenant_id": str(uuid4())}, {"status": "ACTIVE"}]
)
async def test_operator_listing_is_bounded_and_rejects_selectors(operator_env, query):
    result = await operator_env.client.get(
        PATH, headers=operator_env.operator_headers, params=query
    )
    assert result.status_code == 400 and result.headers["cache-control"] == "no-store"
