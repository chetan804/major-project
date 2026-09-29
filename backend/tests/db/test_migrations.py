"""
Migration integrity.

Section 16 forbids destructive or manual schema changes, and section 35 requires
Alembic to be the only path that changes the schema. These tests enforce the two
properties that keep that true over time:

* the revision graph is linear (a second head is a fork that silently skips
  migrations on deploy);
* the models and the migrations agree, so nobody can add an entity and forget the
  migration — the failure mode that produces a ``ProgrammingError`` in production
  rather than in CI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.db


def _alembic(*args: str, database_url: str | None = None) -> subprocess.CompletedProcess[str]:
    """Run an Alembic command in a subprocess against the test database."""
    from tests.conftest import TEST_JWT_SECRET

    env = {
        **os.environ,
        # The same generated value the suite uses, so `env.py` sees a valid
        # configuration without a credential-shaped literal in the source.
        "JWT_SECRET_KEY": TEST_JWT_SECRET,
        "ENVIRONMENT": "test",
    }
    if database_url:
        env["ALEMBIC_DATABASE_URL"] = database_url
    return subprocess.run(  # noqa: S603 - fixed argv, no shell
        [sys.executable, "-m", "alembic", *args],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def test_revision_graph_has_a_single_head(test_database_sync_url: str) -> None:
    """
    There must be exactly one head revision.

    Multiple heads mean a branched history: ``upgrade head`` then applies only one
    of the branches, so a deploy silently skips part of the schema. Alembic
    tolerates this, which is what makes it dangerous.
    """
    result = _alembic("heads", database_url=test_database_sync_url)

    assert result.returncode == 0, result.stderr
    heads = [line for line in result.stdout.splitlines() if line.strip() and "(head)" in line]
    assert len(heads) == 1, f"expected a single head revision, found: {heads}"


def test_models_match_the_migrations(test_database_sync_url: str) -> None:
    """
    The ORM metadata and the migrated schema must agree.

    ``alembic check`` compares them and exits non-zero when a difference is found,
    so an entity added without its migration fails the build. This is the
    automated answer to "did anyone forget a migration?".
    """
    result = _alembic("check", database_url=test_database_sync_url)

    assert result.returncode == 0, (
        "The models and migrations have diverged. Create a migration for the "
        f"change.\nstdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
    assert "No new upgrade operations detected" in result.stdout + result.stderr


def test_downgrade_and_upgrade_round_trip(test_database_sync_url: str) -> None:
    """
    Migrations must be reversible.

    A migration that cannot be reverted is a one-way door: a failed deploy cannot
    be rolled back, and a restore rehearsal cannot be performed. Reversibility is
    proven here rather than assumed.
    """
    sync_url = test_database_sync_url

    downgrade = _alembic("downgrade", "base", database_url=sync_url)
    assert downgrade.returncode == 0, downgrade.stderr

    upgrade = _alembic("upgrade", "head", database_url=sync_url)
    assert upgrade.returncode == 0, upgrade.stderr

    # And the schema is back where it started.
    check = _alembic("check", database_url=sync_url)
    assert check.returncode == 0, check.stderr


def test_offline_sql_can_be_generated_for_review(test_database_sync_url: str) -> None:
    """
    ``--sql`` must produce reviewable statements.

    This is the mechanism behind section 16's "no destructive migrations without
    explicit safeguards": an operator can read the exact DDL before it runs
    against a real environment.
    """
    result = _alembic("upgrade", "head", "--sql", database_url=test_database_sync_url)

    assert result.returncode == 0, result.stderr
    assert "BEGIN;" in result.stdout


def test_migration_environment_reports_the_target_database(test_database_sync_url: str) -> None:
    """
    The migration log must state which database it targets, with credentials removed.

    Without this, a mistyped URL applies a migration to the wrong environment with
    nothing in the log to show it happened.
    """
    result = _alembic("current", database_url=test_database_sync_url)

    assert result.returncode == 0, result.stderr
    combined = result.stdout + result.stderr
    assert "[alembic] target:" in combined
    assert "postgresql+psycopg2" in combined


def test_model_discovery_finds_the_package() -> None:
    """
    Model discovery must work even while the package is empty.

    An empty package is the correct state for Phase 1, and discovery must not
    raise: ``migrations/env.py`` calls it on every invocation, so a failure here
    would break migrations entirely.
    """
    from app.models import import_all_models, model_module_names

    names = model_module_names()

    # Discovery must exclude the package initialiser and any private helper
    # module, since importing a helper as if it were a model would either fail or
    # register nothing while appearing successful.
    assert "__init__" not in names
    assert all(not name.startswith("_") for name in names)
    # Deterministic order: autogenerate output must not depend on filesystem order.
    assert names == sorted(names)

    imported = import_all_models()
    assert imported == names


def test_url_encoded_socket_path_survives_configparser(test_database_sync_url: str) -> None:
    from sqlalchemy.engine import make_url

    encoded = make_url(test_database_sync_url).render_as_string(hide_password=False)
    assert "%2F" in encoded
    result = _alembic("current", database_url=encoded)
    assert result.returncode == 0, result.stderr
    assert "e1c3617bfb4c" in result.stdout


async def test_machine_actor_attribution_survives_schema_rollback(
    db_session, test_database_sync_url
):
    """Downgrade must not silently discard the identity behind machine evidence."""
    from uuid import uuid4

    from sqlalchemy import delete, text

    from app.authorization.api_keys import generate_api_key
    from app.authorization.tokens import hash_token
    from app.models.identity import ApiKey, AuditLog, Tenant

    tenants = [
        Tenant(
            id=uuid4(),
            slug="migration-" + uuid4().hex,
            name="Migration probe",
            type="MUNICIPALITY",
            status="ACTIVE",
        )
        for _ in range(2)
    ]
    db_session.add_all(tenants)
    await db_session.flush()
    keys = []
    rows = []
    for tenant in tenants:
        prefix, secret = generate_api_key()
        key = ApiKey(
            tenant_id=tenant.id,
            name="Migration probe",
            key_prefix=prefix,
            key_hash=hash_token(secret),
            scopes=["bins.telemetry.ingest"],
        )
        db_session.add(key)
        await db_session.flush()
        keys.append(key)
        row = AuditLog(
            tenant_id=tenant.id,
            actor_type="API_KEY",
            actor_api_key_id=key.id,
            action="test.machine",
            event_metadata={"evidence": "preserved"},
        )
        db_session.add(row)
        rows.append(row)
    await db_session.commit()
    tenant_ids = [tenant.id for tenant in tenants]
    restored = False
    try:
        down = _alembic("downgrade", "ca9642749b58", database_url=test_database_sync_url)
        assert down.returncode == 0, down.stderr
        for row, key in zip(rows, keys, strict=True):
            metadata = (
                await db_session.execute(
                    text("SELECT metadata FROM audit_logs WHERE id=:id"), {"id": row.id}
                )
            ).scalar_one()
            assert metadata["_machine_actor_ref_v1"] == str(key.id)
            assert metadata["evidence"] == "preserved"
        await db_session.commit()  # release SELECT locks before ALTER TABLE
        up = _alembic("upgrade", "head", database_url=test_database_sync_url)
        assert up.returncode == 0, up.stderr
        restored = True
        for row, key in zip(rows, keys, strict=True):
            await db_session.refresh(row)
            assert row.actor_api_key_id == key.id
            assert row.actor_user_id is None
            assert row.event_metadata["evidence"] == "preserved"
    finally:
        await db_session.rollback()
        if not restored:
            result = _alembic("upgrade", "head", database_url=test_database_sync_url)
            assert result.returncode == 0, result.stderr
        await db_session.execute(delete(AuditLog).where(AuditLog.tenant_id.in_(tenant_ids)))
        await db_session.execute(delete(ApiKey).where(ApiKey.tenant_id.in_(tenant_ids)))
        await db_session.execute(delete(Tenant).where(Tenant.id.in_(tenant_ids)))
        await db_session.commit()


async def test_step_up_downgrade_drops_authority_not_audit_evidence(
    db_session, test_database_sync_url
):
    from datetime import timedelta
    from uuid import uuid4

    from sqlalchemy import delete

    from app.core.time import utc_now
    from app.db.base import PLATFORM_SCOPE_ID
    from app.models.identity import AuditLog, Session, User

    user_id, session_id = uuid4(), uuid4()
    now = utc_now()
    user = User(
        id=user_id,
        tenant_id=PLATFORM_SCOPE_ID,
        email=f"migration-{user_id}@example.test",
        full_name="Migration proof",
        password_hash="not-a-login-hash",
        status="ACTIVE",
    )
    db_session.add(user)
    await db_session.flush()
    session = Session(
        id=session_id,
        tenant_id=PLATFORM_SCOPE_ID,
        user_id=user_id,
        refresh_token_hash=uuid4().hex,
        family_id=uuid4(),
        issued_at=now - timedelta(seconds=1),
        expires_at=now + timedelta(hours=1),
        platform_reauthenticated_at=now,
    )
    event = AuditLog(
        tenant_id=PLATFORM_SCOPE_ID,
        actor_user_id=user_id,
        actor_type="USER",
        action="platform.step_up.confirm",
        resource_type="session",
        resource_id=str(session_id),
        event_metadata={"method": "password"},
    )
    db_session.add_all([session, event])
    await db_session.commit()
    event_id = event.id
    restored = False
    try:
        down = _alembic("downgrade", "600bc6193a23", database_url=test_database_sync_url)
        assert down.returncode == 0, down.stderr
        up = _alembic("upgrade", "head", database_url=test_database_sync_url)
        assert up.returncode == 0, up.stderr
        restored = True
        await db_session.refresh(session)
        assert session.platform_reauthenticated_at is None
        await db_session.refresh(event)
        assert event.event_metadata == {"method": "password"}
        assert event.actor_user_id == user_id
    finally:
        await db_session.rollback()
        if not restored:
            up = _alembic("upgrade", "head", database_url=test_database_sync_url)
            assert up.returncode == 0, up.stderr
        await db_session.execute(delete(AuditLog).where(AuditLog.id == event_id))
        up = _alembic("upgrade", "head", database_url=test_database_sync_url)
        assert up.returncode == 0, up.stderr
        await db_session.execute(delete(Session).where(Session.id == session_id))
        await db_session.execute(delete(User).where(User.id == user_id))
        await db_session.commit()


@pytest.mark.parametrize("state", ["active", "pending", "counter", "session_proof"])
async def test_mfa_downgrade_refuses_to_erase_security_state(
    db_session, test_database_sync_url, state
):
    from datetime import timedelta
    from uuid import uuid4

    from sqlalchemy import delete

    from app.core.time import utc_now
    from app.db.base import PLATFORM_SCOPE_ID
    from app.models.identity import Session, User

    user_id, session_id = uuid4(), uuid4()
    user = User(
        id=user_id,
        tenant_id=PLATFORM_SCOPE_ID,
        email=f"mfa-migration-{user_id}@example.test",
        full_name="MFA migration probe",
        password_hash="not-a-login-hash",
        status="ACTIVE",
    )
    if state == "active":
        user.mfa_secret_encrypted = "legacy-probe"
    elif state == "pending":
        user.mfa_pending_secret_encrypted = "pending-probe"
    elif state == "counter":
        user.mfa_last_counter = 123
    db_session.add(user)
    await db_session.flush()
    if state == "session_proof":
        db_session.add(
            Session(
                id=session_id,
                tenant_id=PLATFORM_SCOPE_ID,
                user_id=user_id,
                refresh_token_hash=uuid4().hex,
                family_id=uuid4(),
                issued_at=utc_now(),
                expires_at=utc_now() + timedelta(hours=1),
                platform_mfa_factor_id=uuid4(),
            )
        )
    await db_session.commit()
    try:
        result = _alembic("downgrade", "1eb8da7c2793", database_url=test_database_sync_url)
        assert result.returncode != 0
        assert "MFA state exists" in result.stderr
        current = _alembic("current", database_url=test_database_sync_url)
        # Alembic commits each revision. The policy downgrade (all flags false)
        # completed, then the older MFA guard refused to discard factor state.
        assert "c4195297efc7" in current.stdout
        up = _alembic("upgrade", "head", database_url=test_database_sync_url)
        assert up.returncode == 0, up.stderr
        await db_session.refresh(user)
        if state == "active":
            assert user.mfa_secret_encrypted == "legacy-probe"
        elif state == "pending":
            assert user.mfa_pending_secret_encrypted == "pending-probe"
        elif state == "counter":
            assert user.mfa_last_counter == 123
        else:
            assert (await db_session.get(Session, session_id)).platform_mfa_factor_id is not None
    finally:
        await db_session.rollback()
        up = _alembic("upgrade", "head", database_url=test_database_sync_url)
        assert up.returncode == 0, up.stderr
        await db_session.execute(delete(Session).where(Session.id == session_id))
        await db_session.execute(delete(User).where(User.id == user_id))
        await db_session.commit()


async def test_required_mfa_policy_blocks_downgrade_without_erasing_data(
    db_session, test_database_sync_url
):
    from uuid import uuid4

    from sqlalchemy import delete, select

    from app.db.base import PLATFORM_SCOPE_ID
    from app.models.identity import Permission, User

    user_id = uuid4()
    user = User(
        id=user_id,
        tenant_id=PLATFORM_SCOPE_ID,
        email=f"policy-migration-{user_id}@example.test",
        full_name="Policy migration probe",
        password_hash="not-a-login-hash",
        status="INVITED",
        platform_mfa_required=True,
    )
    db_session.add(user)
    await db_session.commit()
    try:
        down = _alembic("downgrade", "c4195297efc7", database_url=test_database_sync_url)
        assert down.returncode != 0 and "Required MFA policy exists" in down.stderr
        current = _alembic("current", database_url=test_database_sync_url)
        assert "e1c3617bfb4c" in current.stdout
        await db_session.refresh(user)
        assert user.platform_mfa_required is True
        assert (
            await db_session.execute(
                select(Permission.id).where(Permission.code == "platform.operators.write")
            )
        ).first() is not None
    finally:
        await db_session.rollback()
        await db_session.execute(delete(User).where(User.id == user_id))
        await db_session.commit()
