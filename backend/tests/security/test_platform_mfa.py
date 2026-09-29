"""Enrolled operators cannot downgrade platform mutations to password-only auth."""

from __future__ import annotations

import asyncio
import json
import secrets
from datetime import timedelta
from types import SimpleNamespace
from uuid import uuid4

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.totp import generate_code
from app.core.time import utc_now
from app.models.identity import AuditLog, User
from app.repositories.identity import AuditLogRepository
from app.services.platform_mfa import decrypt_seed

from .support import bearer, refresh
from .test_platform_step_up import PATH as STEP_UP
from .test_platform_tenants import BASE, REASON
from .test_platform_tenants import platform_env as platform_env

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]
MFA = "/api/v1/platform/auth/mfa"


@pytest.fixture
async def mfa_env(platform_env, monkeypatch):
    env = platform_env
    env.clock = SimpleNamespace(now=utc_now())
    monkeypatch.setattr("app.services.platform_mfa.utc_now", lambda: env.clock.now)
    return env


def code(env, seed, *, advance=True):
    if advance:
        env.clock.now += timedelta(seconds=30)
    return generate_code(seed, int(env.clock.now.timestamp()) // 30)


async def start(env, **overrides):
    return await env.client.post(
        MFA + "/enrollment",
        headers=env.operator_headers,
        json={"password": env.password, **overrides},
    )


async def activate(env, seed, headers=None):
    return await env.client.post(
        MFA + "/enrollment/confirm",
        headers=headers or env.operator_headers,
        json={"password": env.password, "totp_code": code(env, seed)},
    )


async def enroll(env):
    response = await start(env)
    assert response.status_code == 201, response.text
    seed = response.json()["secret"]
    confirmed = await activate(env, seed)
    assert confirmed.status_code == 200, confirmed.text
    return seed, confirmed.json()["recovery_codes"]


async def confirm(env, **fields):
    return await env.client.post(
        STEP_UP, headers=env.operator_headers, json={"password": env.password, **fields}
    )


async def user_row(env, db):
    return (
        await db.execute(
            select(User).where(User.id == env.operator_id).execution_options(populate_existing=True)
        )
    ).scalar_one()


async def write(env):
    return await env.client.patch(
        BASE + "/" + str(env.tenants[0].id),
        headers=env.operator_headers,
        json={**REASON, "name": "MFA authorized update"},
    )


async def test_enrollment_enforces_second_factor_and_hides_material(mfa_env, db_session, caplog):
    env = mfa_env
    response = await start(env)
    assert response.status_code == 201 and response.headers["cache-control"] == "no-store"
    seed = response.json()["secret"]
    assert "otpauth://totp/" in response.json()["otpauth_uri"]
    row = await user_row(env, db_session)
    assert seed not in row.mfa_pending_secret_encrypted
    assert decrypt_seed(env.settings, row, row.mfa_pending_secret_encrypted)[0] == seed
    activated = await activate(env, seed)
    assert activated.status_code == 200
    codes = activated.json()["recovery_codes"]
    assert len(codes) == len(set(codes)) == 10
    row = await user_row(env, db_session)
    assert all(value not in row.mfa_recovery_hashes for value in codes)
    assert seed not in row.mfa_secret_encrypted
    assert row.mfa_pending_secret_encrypted is None
    assert (await write(env)).status_code == 403  # prior password proof cleared
    denied = await confirm(env)
    assert denied.status_code == 401
    verified = await confirm(env, totp_code=code(env, seed))
    assert verified.status_code == 200 and verified.json()["method"] == "password+totp"
    assert (await write(env)).status_code == 200
    status = await env.client.get(MFA, headers=env.operator_headers)
    assert status.json() == {
        "enabled": True,
        "required_for_platform_actions": False,
        "pending_expires_at": None,
        "recovery_codes_remaining": 10,
    }
    events = list(
        (
            await db_session.execute(select(AuditLog).where(AuditLog.tenant_id == row.tenant_id))
        ).scalars()
    )
    evidence = (
        json.dumps([e.event_metadata for e in events]) + caplog.text + status.text + verified.text
    )
    assert all(value not in evidence for value in [seed, *codes])


async def test_codes_are_single_use_across_sessions_and_concurrent_requests(mfa_env):
    env = mfa_env
    seed, recovery = await enroll(env)
    totp = code(env, seed)
    results = await asyncio.gather(confirm(env, totp_code=totp), confirm(env, totp_code=totp))
    assert sorted(r.status_code for r in results) == [200, 401]
    results = await asyncio.gather(
        confirm(env, recovery_code=recovery[0]), confirm(env, recovery_code=recovery[0])
    )
    assert sorted(r.status_code for r in results) == [200, 401]
    rotated = await refresh(env, env.operator_tokens)
    assert rotated.status_code == 200
    env.operator_headers = bearer(rotated.json())
    assert (await write(env)).status_code == 403
    assert (await confirm(env, recovery_code=recovery[0])).status_code == 401
    assert (await confirm(env, recovery_code=recovery[1])).status_code == 200


async def test_recovery_can_replace_lost_factor_without_disabling_mfa(mfa_env, db_session):
    env = mfa_env
    old_seed, old_codes = await enroll(env)
    assert (await start(env)).status_code == 403  # no strong proof yet
    assert (await confirm(env, recovery_code=old_codes[0])).status_code == 200
    pending = await start(env)
    assert pending.status_code == 201
    assert (await confirm(env, totp_code=code(env, old_seed))).status_code == 200
    new_seed = pending.json()["secret"]
    result = await activate(env, new_seed)
    assert result.status_code == 200
    assert (await write(env)).status_code == 403
    assert (await confirm(env, recovery_code=old_codes[1])).status_code == 401
    assert (await confirm(env, totp_code=code(env, new_seed))).status_code == 200
    assert (await write(env)).status_code == 200
    assert (await user_row(env, db_session)).mfa_secret_encrypted is not None


async def test_cancel_never_removes_active_factor(mfa_env):
    env = mfa_env
    seed, _ = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200
    assert (await start(env)).status_code == 201
    for _ in range(2):
        assert (
            await env.client.delete(MFA + "/enrollment", headers=env.operator_headers)
        ).status_code == 204
    assert (await env.client.get(MFA, headers=env.operator_headers)).json()["enabled"] is True
    assert (await confirm(env)).status_code == 401
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200


async def test_recovery_rotation_invalidates_old_codes_and_all_proofs(mfa_env):
    env = mfa_env
    seed, old_codes = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200
    rotated = await env.client.post(
        MFA + "/recovery-codes", headers=env.operator_headers, json={"password": env.password}
    )
    assert rotated.status_code == 200
    assert set(rotated.json()["recovery_codes"]).isdisjoint(old_codes)
    assert (await write(env)).status_code == 403
    assert (await confirm(env, recovery_code=old_codes[0])).status_code == 401
    assert (
        await confirm(env, recovery_code=rotated.json()["recovery_codes"][0])
    ).status_code == 200


@pytest.mark.parametrize("state", ["expired", "other_session", "refreshed", "restarted"])
async def test_pending_enrollment_is_bounded_and_session_specific(mfa_env, state):
    env = mfa_env
    pending = await start(env)
    seed = pending.json()["secret"]
    headers = env.operator_headers
    if state == "expired":
        env.clock.now += timedelta(minutes=11)
    elif state == "other_session":
        other = await env.client.post(
            "/api/v1/auth/login",
            json={
                "tenant_slug": "ecomind-platform",
                "email": env.operator_email,
                "password": env.password,
            },
        )
        headers = bearer(other.json())
    elif state == "refreshed":
        headers = bearer((await refresh(env, env.operator_tokens)).json())
    else:
        assert (await start(env)).status_code == 201
    result = await activate(env, seed, headers)
    assert result.status_code == (401 if state == "restarted" else 409)


@pytest.mark.parametrize(
    "failure", ["start_audit", "start_commit", "confirm_audit", "confirm_commit"]
)
async def test_issuance_is_atomic_and_does_not_disclose_on_failure(
    mfa_env, db_session, monkeypatch, failure
):
    env = mfa_env
    seed = None
    if failure.startswith("confirm"):
        seed = (await start(env)).json()["secret"]

    async def fail(*args, **kwargs):
        raise RuntimeError("Controlled persistence failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            AsyncSession if failure.endswith("commit") else AuditLogRepository,
            "commit" if failure.endswith("commit") else "record",
            fail,
        )
        result = await activate(env, seed) if seed else await start(env)
    assert result.status_code == 500
    assert result.headers["cache-control"] == "no-store"
    assert '"secret":' not in result.text and '"recovery_codes":' not in result.text
    user = await user_row(env, db_session)
    assert user.mfa_factor_id is None and user.mfa_secret_encrypted is None
    if seed:
        assert user.mfa_pending_secret_encrypted is not None
    else:
        assert user.mfa_pending_secret_encrypted is None


async def test_factor_consumption_rolls_back_with_failed_audit(mfa_env, monkeypatch):
    env = mfa_env
    seed, codes = await enroll(env)

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    for fields in ({"totp_code": code(env, seed)}, {"recovery_code": codes[0]}):
        with monkeypatch.context() as patch:
            patch.setattr(AuditLogRepository, "record", fail)
            assert (await confirm(env, **fields)).status_code == 500
        assert (await confirm(env, **fields)).status_code == 200


@pytest.mark.parametrize(
    "kind", ["key_missing", "key_changed", "ciphertext_corrupt", "bound_identity", "partial_state"]
)
async def test_enrolled_state_never_falls_back_to_password(mfa_env, db_session, monkeypatch, kind):
    env = mfa_env
    seed, _ = await enroll(env)
    row = await user_row(env, db_session)
    if kind == "key_missing":
        monkeypatch.setattr(env.settings, "mfa_encryption_key", "")
    elif kind == "key_changed":
        from cryptography.fernet import Fernet

        monkeypatch.setattr(env.settings, "mfa_encryption_key", Fernet.generate_key().decode())
    elif kind == "ciphertext_corrupt":
        row.mfa_secret_encrypted = "unreadable"
    elif kind == "bound_identity":
        from app.services.platform_mfa import encrypt_seed

        row.mfa_secret_encrypted = encrypt_seed(
            env.settings, User(id=uuid4(), tenant_id=row.tenant_id), seed, row.mfa_factor_id
        )
    else:
        row.mfa_secret_encrypted = None
    await db_session.commit()
    assert (await confirm(env)).status_code == 401
    result = await confirm(env, totp_code=code(env, seed))
    assert result.status_code in (401, 503)
    assert (await write(env)).status_code == 403


async def test_password_change_keeps_active_factor_but_cancels_pending_and_proofs(
    mfa_env, db_session
):
    env = mfa_env
    seed, _ = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200
    assert (await start(env)).status_code == 201
    changed = secrets.token_urlsafe(24)
    result = await env.client.post(
        "/api/v1/auth/me/password",
        headers=env.operator_headers,
        json={"current_password": env.password, "new_password": changed},
    )
    assert result.status_code == 200
    env.password = changed
    row = await user_row(env, db_session)
    assert row.mfa_secret_encrypted is not None and row.mfa_pending_secret_encrypted is None
    assert (await write(env)).status_code == 403
    assert (await confirm(env)).status_code == 401
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200


async def test_bad_totp_uses_durable_lockout(mfa_env, db_session):
    env = mfa_env
    seed, _ = await enroll(env)
    for _ in range(5):
        # Enrollment counter has already been consumed, so this code is guaranteed invalid.
        result = await confirm(env, totp_code=code(env, seed, advance=False))
        assert result.status_code == 401
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 403
    assert (await user_row(env, db_session)).locked_until > utc_now()


@pytest.mark.parametrize(
    "method,suffix",
    [
        ("GET", ""),
        ("POST", "/enrollment"),
        ("POST", "/enrollment/confirm"),
        ("DELETE", "/enrollment"),
        ("POST", "/recovery-codes"),
    ],
)
async def test_mfa_surface_rejects_anonymous_and_tenant_actors(mfa_env, method, suffix):
    env = mfa_env
    kwargs = (
        {
            "json": {
                "password": env.password,
                **({"totp_code": "000000"} if suffix.endswith("confirm") else {}),
            }
        }
        if method == "POST"
        else {}
    )
    assert (await env.client.request(method, MFA + suffix, **kwargs)).status_code == 401
    assert (
        await env.client.request(method, MFA + suffix, headers=env.headers, **kwargs)
    ).status_code == 403


@pytest.mark.parametrize(
    "body",
    [
        {"password": None},
        {"password": ""},
        {"password": "x" * 129},
        {"password": "unused", "tenant_id": str(uuid4())},
        {"password": "unused", "secret": "untrusted"},
    ],
)
async def test_enrollment_inputs_are_closed(mfa_env, body):
    result = await mfa_env.client.post(
        MFA + "/enrollment", headers=mfa_env.operator_headers, json=body
    )
    assert result.status_code == 400
    assert result.headers["cache-control"] == "no-store"


async def test_mfa_routes_share_fail_closed_budgets(mfa_env, app, monkeypatch):
    env = mfa_env
    env.settings.auth_account_limit = 1
    app.state.auth_rate_limiter.counter.entries.clear()
    assert (await start(env)).status_code == 201
    result = await env.client.post(
        MFA + "/enrollment/confirm",
        headers=env.operator_headers,
        json={"password": env.password, "totp_code": "000000"},
    )
    assert result.status_code == 429

    async def unavailable(*args):
        raise RuntimeError("Unavailable counter")

    monkeypatch.setattr(app.state.auth_rate_limiter.counter, "hit", unavailable)
    assert (await start(env)).status_code == 503


async def test_password_reset_retains_factor_and_codes_but_revokes_pending_authority(
    mfa_env, db_session
):
    from app.db.base import PLATFORM_SCOPE_ID
    from app.models.auth_mail import AuthMail

    from .test_platform_tenants import delivered_code

    env = mfa_env
    seed, codes = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200
    assert (await start(env)).status_code == 201
    requested = await env.client.post(
        "/api/v1/auth/password-reset",
        json={"tenant_slug": "ecomind-platform", "email": env.operator_email},
    )
    assert requested.status_code == 202
    mail = (
        await db_session.execute(
            select(AuthMail).where(
                AuthMail.tenant_id == PLATFORM_SCOPE_ID, AuthMail.status == "PENDING"
            )
        )
    ).scalar_one()
    token = await delivered_code(env, mail, expected_recipient=env.operator_email)
    changed = secrets.token_urlsafe(24)
    result = await env.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={"tenant_slug": "ecomind-platform", "token": token, "new_password": changed},
    )
    assert result.status_code == 200
    assert (await write(env)).status_code == 401
    env.password = changed
    logged = await env.client.post(
        "/api/v1/auth/login",
        json={"tenant_slug": "ecomind-platform", "email": env.operator_email, "password": changed},
    )
    env.operator_headers = bearer(logged.json())
    row = await user_row(env, db_session)
    assert row.mfa_pending_secret_encrypted is None and row.mfa_secret_encrypted is not None
    assert len(row.mfa_recovery_hashes) == 10
    assert (await confirm(env)).status_code == 401
    assert (await confirm(env, recovery_code=codes[0])).status_code == 200
    assert (await write(env)).status_code == 200


async def test_both_factors_are_rejected_without_consuming_either(mfa_env):
    env = mfa_env
    seed, codes = await enroll(env)
    totp = code(env, seed)
    assert (await confirm(env, totp_code=totp, recovery_code=codes[0])).status_code == 401
    assert (await confirm(env, totp_code=totp)).status_code == 200
    assert (await confirm(env, recovery_code=codes[0])).status_code == 200


@pytest.mark.parametrize("failure", ["audit", "commit"])
async def test_failed_recovery_rotation_retains_old_codes_and_proof(mfa_env, monkeypatch, failure):
    env = mfa_env
    seed, codes = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200

    async def fail(*args, **kwargs):
        raise RuntimeError("Controlled persistence failure")

    with monkeypatch.context() as patch:
        patch.setattr(
            AsyncSession if failure == "commit" else AuditLogRepository,
            "commit" if failure == "commit" else "record",
            fail,
        )
        result = await env.client.post(
            MFA + "/recovery-codes", headers=env.operator_headers, json={"password": env.password}
        )
    assert result.status_code == 500
    assert result.headers["cache-control"] == "no-store"
    assert '"recovery_codes":' not in result.text
    assert (await write(env)).status_code == 200
    assert (await confirm(env, recovery_code=codes[0])).status_code == 200


async def test_failed_denial_audit_preserves_counter_and_proof(mfa_env, monkeypatch, db_session):
    env = mfa_env
    seed, _ = await enroll(env)
    assert (await confirm(env, totp_code=code(env, seed))).status_code == 200

    async def fail(*args, **kwargs):
        raise RuntimeError("Audit unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(AuditLogRepository, "record", fail)
        assert (await confirm(env)).status_code == 500
    assert (await user_row(env, db_session)).failed_login_attempts == 0
    assert (await write(env)).status_code == 200


@pytest.mark.parametrize("operation", ["start", "activate", "regenerate"])
async def test_slow_password_check_cannot_outlive_session(
    mfa_env, monkeypatch, db_session, operation
):
    from app.services.auth import AuthService

    env = mfa_env
    seed = None
    if operation == "activate":
        seed = (await start(env)).json()["secret"]
    elif operation == "regenerate":
        seed, _ = await enroll(env)
        assert (await confirm(env, totp_code=code(env, seed))).status_code == 200
    original = AuthService.verify_password

    def delayed(self, *args):
        result = original(self, *args)
        env.clock.now += timedelta(days=365)
        return result

    monkeypatch.setattr(AuthService, "verify_password", delayed)
    if operation == "start":
        response = await start(env)
    elif operation == "activate":
        response = await activate(env, seed)
    else:
        response = await env.client.post(
            MFA + "/recovery-codes", headers=env.operator_headers, json={"password": env.password}
        )
    assert response.status_code == 403
    row = await user_row(env, db_session)
    if operation == "start":
        assert row.mfa_pending_secret_encrypted is None
    elif operation == "activate":
        assert row.mfa_factor_id is None
    else:
        assert len(row.mfa_recovery_hashes) == 10


async def test_step_up_and_mfa_share_the_same_account_budget(mfa_env, app):
    env = mfa_env
    env.settings.auth_account_limit = 1
    app.state.auth_rate_limiter.counter.entries.clear()
    assert (await confirm(env)).status_code == 200
    assert (await start(env)).status_code == 429


@pytest.mark.parametrize("suffix", ["/enrollment", "/enrollment/confirm", "/recovery-codes"])
async def test_credential_ip_budget_precedes_malformed_body(mfa_env, app, suffix):
    env = mfa_env
    env.settings.auth_ip_limit = 1
    app.state.auth_rate_limiter.counter.entries.clear()
    for expected in (400, 429):
        result = await env.client.post(
            MFA + suffix,
            headers={**env.operator_headers, "Content-Type": "application/json"},
            content="{",
        )
        assert result.status_code == expected
        assert result.headers["cache-control"] == "no-store"
