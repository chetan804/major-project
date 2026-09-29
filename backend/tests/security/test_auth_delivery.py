"""Encrypted queue -> actual private MIME mailbox -> single-use HTTP confirmation."""

from __future__ import annotations

import asyncio
import json
import secrets
import stat
from datetime import timedelta
from email import policy
from email.parser import BytesParser
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import select

from app.core.time import utc_now
from app.db.rls import apply_tenant_context
from app.integrations.auth_mail import transport_for
from app.models._enums import UserStatus
from app.models.auth_mail import AuthMail
from app.models.identity import AuditLog
from app.services.auth_delivery import AuthDelivery

from .support import bearer, login, service

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


async def request_code(env, purpose="PASSWORD_RESET", index=0):
    path = "/password-reset" if purpose == "PASSWORD_RESET" else "/email/verify-request"
    response = await env.client.post(
        "/api/v1/auth" + path,
        json={
            "tenant_slug": env.tenants[index].slug,
            "email": env.users[index].email,
        },
    )
    assert response.status_code == 202, response.text
    assert response.json()["delivery_status"] == "queued_if_eligible"
    assert response.headers["cache-control"] == "no-store"
    return response


async def pending(db_session, env, index=0):
    return (
        await db_session.execute(
            select(AuthMail)
            .where(
                AuthMail.tenant_id == env.tenants[index].id,
                AuthMail.status == "PENDING",
            )
            .execution_options(populate_existing=True)
        )
    ).scalar_one()


def decrypt(env, row):
    return json.loads(
        Fernet(env.settings.auth_mail_encryption_key.encode()).decrypt(
            row.encrypted_payload.encode()
        )
    )


async def deliver(env, transport=None, index=0):
    async with env.factory() as session:
        result = await AuthDelivery(session, env.settings).deliver_batch(
            env.tenants[index].id,
            transport or transport_for(env.settings),
        )
        await session.commit()
        return result


def mailbox_token(env, row):
    path = Path(env.settings.auth_mailbox_root) / str(row.tenant_id) / f"{row.id}.eml"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    message = BytesParser(policy=policy.default).parsebytes(path.read_bytes())
    assert message["To"] == env.users[0].email
    return message.get_content().splitlines()[0].split(": ", 1)[1]


async def test_reset_is_delivered_then_consumed_without_secret_leakage(
    auth_env, db_session, caplog
):
    env = auth_env
    old = (await login(env)).json()
    response = await request_code(env)
    row = await pending(db_session, env)
    token = decrypt(env, row)["token"]
    assert token not in response.text
    assert token not in row.encrypted_payload
    assert env.users[0].email not in row.encrypted_payload
    assert (await deliver(env))["sent"] == 1
    assert mailbox_token(env, row) == token
    await db_session.refresh(row)
    assert row.encrypted_payload is None
    assert row.status == "SENT"
    assert row.attempts == 1
    new_password = secrets.token_urlsafe(24)
    body = {"tenant_slug": env.tenants[0].slug, "token": token, "new_password": new_password}
    confirmed = await env.client.post("/api/v1/auth/password-reset/confirm", json=body)
    assert confirmed.status_code == 200
    assert (await env.client.get("/api/v1/auth/me", headers=bearer(old))).status_code == 401
    assert (await login(env, password=new_password)).status_code == 200
    assert (
        await env.client.post("/api/v1/auth/password-reset/confirm", json=body)
    ).status_code == 401
    assert token not in caplog.text
    audits = (
        (await db_session.execute(select(AuditLog).where(AuditLog.tenant_id == row.tenant_id)))
        .scalars()
        .all()
    )
    assert token not in json.dumps([a.event_metadata for a in audits])


async def test_invited_user_can_verify_real_mailbox_code_then_login(auth_env, db_session):
    env = auth_env
    env.users[0].status = UserStatus.INVITED
    await db_session.commit()
    assert (await login(env)).status_code == 403
    await request_code(env, "EMAIL_VERIFICATION")
    row = await pending(db_session, env)
    assert (await deliver(env))["sent"] == 1
    token = mailbox_token(env, row)
    body = {"tenant_slug": env.tenants[0].slug, "token": token}
    foreign = await env.client.post(
        "/api/v1/auth/email/verify-confirm", json={**body, "tenant_slug": env.tenants[1].slug}
    )
    assert foreign.status_code == 401
    confirmed = await env.client.post("/api/v1/auth/email/verify-confirm", json=body)
    assert confirmed.status_code == 200
    assert (await login(env)).status_code == 200
    await db_session.refresh(env.users[0])
    assert env.users[0].email_verified_at is not None
    assert env.users[0].email_verification_token_hash is None
    assert (
        await env.client.post("/api/v1/auth/email/verify-confirm", json=body)
    ).status_code == 401


@pytest.mark.parametrize("change", ["expiry", "suspended", "deleted", "consumed"])
async def test_invalidated_mail_is_not_sent_and_payload_is_erased(auth_env, db_session, change):
    env = auth_env
    await request_code(env)
    row = await pending(db_session, env)
    if change == "expiry":
        row.expires_at = utc_now() - timedelta(seconds=1)
    elif change == "suspended":
        env.users[0].status = UserStatus.SUSPENDED
    elif change == "deleted":
        env.users[0].deleted_at = utc_now()
    else:
        env.users[0].password_reset_token_hash = None
    await db_session.commit()
    result = await deliver(env)
    assert result["sent"] == 0
    assert result["cancelled"] == 1
    await db_session.refresh(row)
    assert row.encrypted_payload is None
    assert list(Path(env.settings.auth_mailbox_root).rglob("*.eml")) == []


async def test_supersession_and_expired_verification(auth_env, db_session):
    env = auth_env
    await request_code(env, "EMAIL_VERIFICATION")
    old = await pending(db_session, env)
    old_token = decrypt(env, old)["token"]
    await request_code(env, "EMAIL_VERIFICATION")
    await db_session.refresh(old)
    assert old.status == "CANCELLED"
    assert old.encrypted_payload is None
    newest = await pending(db_session, env)
    token = decrypt(env, newest)["token"]
    response = await env.client.post(
        "/api/v1/auth/email/verify-confirm",
        json={"tenant_slug": env.tenants[0].slug, "token": old_token},
    )
    assert response.status_code == 401
    env.users[0].email_verification_expires_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    response = await env.client.post(
        "/api/v1/auth/email/verify-confirm",
        json={"tenant_slug": env.tenants[0].slug, "token": token},
    )
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "TOKEN_EXPIRED"


async def test_uncommitted_or_rolled_back_queue_cannot_be_delivered(auth_env, db_session):
    env = auth_env
    async with env.factory() as session:
        await service(session, env.settings).request_password_reset_in(
            env.tenants[0], email=env.users[0].email
        )
        assert (await deliver(env))["sent"] == 0
        await session.rollback()
    assert (
        await db_session.execute(select(AuthMail).where(AuthMail.tenant_id == env.tenants[0].id))
    ).scalars().all() == []
    await db_session.refresh(env.users[0])
    assert env.users[0].password_reset_token_hash is None


async def test_provider_failure_retries_and_never_records_exception_content(
    auth_env, db_session, caplog, monkeypatch
):
    env = auth_env
    env.settings.auth_mail_max_attempts = 2
    await request_code(env)
    row = await pending(db_session, env)
    token = decrypt(env, row)["token"]

    clock = [utc_now()]
    monkeypatch.setattr("app.services.auth_delivery.utc_now", lambda: clock[0])

    class Broken:
        async def send(self, mail):
            # Earlier rows/slow SMTP must not consume this message's backoff.
            clock[0] += timedelta(seconds=120)
            raise RuntimeError(mail.body)

    assert (await deliver(env, Broken()))["retry"] == 1
    await db_session.refresh(row)
    assert row.attempts == 1
    assert row.encrypted_payload is not None
    assert row.next_attempt_at > clock[0]
    assert row.last_error == "transport_failure"
    assert (await deliver(env, Broken()))["retry"] == 0  # backoff is honored
    row.next_attempt_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    assert (await deliver(env, Broken()))["failed"] == 1
    await db_session.refresh(row)
    assert row.encrypted_payload is None
    assert row.attempts == 2
    assert token not in caplog.text


async def test_retry_can_succeed_and_local_delivery_is_idempotent(
    auth_env, db_session, monkeypatch
):
    env = auth_env
    await request_code(env)
    row = await pending(db_session, env)
    transport = transport_for(env.settings)
    original = transport.send
    attempts = 0

    async def fail_after_write(mail):
        nonlocal attempts
        await original(mail)
        attempts += 1
        if attempts == 1:
            raise RuntimeError("connection lost after transport success")

    monkeypatch.setattr(transport, "send", fail_after_write)
    assert (await deliver(env, transport))["retry"] == 1
    await db_session.refresh(row)
    row.next_attempt_at = utc_now() - timedelta(seconds=1)
    await db_session.commit()
    assert (await deliver(env, transport))["sent"] == 1
    assert len(list(Path(env.settings.auth_mailbox_root).rglob("*.eml"))) == 1


async def test_two_workers_do_not_send_same_pending_row(auth_env, db_session):
    env = auth_env
    await request_code(env)
    entered = asyncio.Event()
    release = asyncio.Event()

    class Paused:
        calls = 0

        async def send(self, mail):
            self.calls += 1
            entered.set()
            await release.wait()

    transport = Paused()
    first = asyncio.create_task(deliver(env, transport))
    try:
        await asyncio.wait_for(entered.wait(), timeout=5)
        second = await asyncio.wait_for(deliver(env, transport), timeout=5)
        assert second["sent"] == 0
    finally:
        release.set()
        result = await asyncio.wait_for(first, timeout=5)
    assert result["sent"] == 1
    assert transport.calls == 1


async def test_outbox_rls_hides_other_tenants_even_for_raw_queries(auth_env, db_session):
    env = auth_env
    await request_code(env, index=0)
    await request_code(env, index=1)
    async with env.factory() as session:
        assert (await session.execute(select(AuthMail))).scalars().all() == []
        await apply_tenant_context(session, env.tenants[0].id)
        rows = (await session.execute(select(AuthMail))).scalars().all()
        assert len(rows) == 1
        assert rows[0].tenant_id == env.tenants[0].id
    assert (await deliver(env, index=0))["sent"] == 1
    assert (await pending(db_session, env, index=1)).status == "PENDING"


async def test_bad_encryption_key_fails_safely_and_erases_payload(auth_env, db_session):
    await request_code(auth_env)
    row = await pending(db_session, auth_env)
    auth_env.settings.auth_mail_encryption_key = Fernet.generate_key().decode()
    assert (await deliver(auth_env))["failed"] == 1
    await db_session.refresh(row)
    assert row.last_error == "payload_unreadable"
    assert row.encrypted_payload is None


async def test_delivery_disabled_returns_same_failure_for_known_unknown(auth_env):
    env = auth_env
    env.settings.auth_delivery_enabled = False
    for email in (env.users[0].email, "absent@example.test"):
        response = await env.client.post(
            "/api/v1/auth/password-reset", json={"tenant_slug": env.tenants[0].slug, "email": email}
        )
        assert response.status_code == 503
        assert response.json()["error"]["details"]["dependency"] == "auth_delivery"


async def test_verified_unknown_and_disabled_verification_requests_are_neutral(
    auth_env, db_session
):
    env = auth_env
    env.users[0].email_verified_at = utc_now()
    env.users[1].status = UserStatus.DISABLED
    await db_session.commit()
    bodies = []
    for slug, email in [
        (env.tenants[0].slug, env.users[0].email),
        (env.tenants[1].slug, env.users[1].email),
        ("absent", "absent@example.test"),
    ]:
        response = await env.client.post(
            "/api/v1/auth/email/verify-request", json={"tenant_slug": slug, "email": email}
        )
        assert response.status_code == 202
        bodies.append(response.json())
    assert bodies[0] == bodies[1] == bodies[2]
    assert (
        await db_session.execute(
            select(AuthMail).where(AuthMail.tenant_id.in_([t.id for t in env.tenants]))
        )
    ).scalars().all() == []


async def test_concurrent_verification_consumes_code_once(auth_env, db_session):
    env = auth_env
    await request_code(env, "EMAIL_VERIFICATION")
    row = await pending(db_session, env)
    payload = {"tenant_slug": env.tenants[0].slug, "token": decrypt(env, row)["token"]}
    results = await asyncio.gather(
        *[env.client.post("/api/v1/auth/email/verify-confirm", json=payload) for _ in range(2)]
    )
    assert sorted(response.status_code for response in results) == [200, 401]
    events = (
        (
            await db_session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == env.tenants[0].id,
                    AuditLog.action == "user.email_verified",
                )
            )
        )
        .scalars()
        .all()
    )
    assert len(events) == 1


async def test_recovery_credentials_cannot_be_used_for_other_purpose(auth_env, db_session):
    env = auth_env
    await request_code(env)
    reset = await pending(db_session, env)
    reset_token = decrypt(env, reset)["token"]
    await request_code(env, "EMAIL_VERIFICATION")
    verification = (
        await db_session.execute(
            select(AuthMail).where(
                AuthMail.tenant_id == env.tenants[0].id,
                AuthMail.purpose == "EMAIL_VERIFICATION",
            )
        )
    ).scalar_one()
    verify_token = decrypt(env, verification)["token"]
    first = await env.client.post(
        "/api/v1/auth/email/verify-confirm",
        json={"tenant_slug": env.tenants[0].slug, "token": reset_token},
    )
    second = await env.client.post(
        "/api/v1/auth/password-reset/confirm",
        json={
            "tenant_slug": env.tenants[0].slug,
            "token": verify_token,
            "new_password": secrets.token_urlsafe(24),
        },
    )
    assert first.status_code == second.status_code == 401
