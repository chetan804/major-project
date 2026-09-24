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
