"""Baseline: assert a supported server version and establish the revision chain.

This migration intentionally creates **no tables**. Phase 1 delivers the
application skeleton and infrastructure; the first entities arrive in Phase 2
with the identity and tenancy tables (see ``docs/database/erd.md`` Appendix A).

Establishing an empty baseline is still valuable:

* the revision chain exists, so the first real migration has a parent and the
  history is linear from the very first day;
* ``alembic upgrade head`` and ``alembic downgrade base`` are exercisable
  immediately, so CI proves migration reversibility from the start rather than
  discovering a broken chain months later;
* the version assertion below turns "we require PostgreSQL 13+" from a comment
  into a check that fails the deploy.

Revision ID: 0001_baseline
Revises:
Create Date: 2026-09-24
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import context, op

revision: str = "0001_baseline"
down_revision: str | None = None
branch_labels: str | None = None
depends_on: str | None = None

#: gen_random_uuid() became a built-in in PostgreSQL 13. Below that the schema
#: would need the pgcrypto extension, which is not available in every
#: environment (see docs/environment.md). Every primary key in this schema
#: defaults to gen_random_uuid(), so an older server would fail at runtime on the
#: first insert — far better to refuse at migration time.
MINIMUM_SERVER_VERSION_NUM = 130000


def upgrade() -> None:
    # The version guard needs a live connection, and offline mode (``--sql``) has
    # none: ``op.get_bind()`` returns None there and querying it raises
    # ``AttributeError: 'NoneType' object has no attribute 'scalar_one'``. Offline
    # mode only renders SQL for review or for a DBA to run later, so there is
    # nothing to check at render time; the guard below runs whenever the migration
    # is actually applied. ``tests/db/test_migrations.py`` exercises both paths.
    if context.is_offline_mode():
        # Nothing to emit for the baseline itself; the revision chain is the
        # migration. A marker statement keeps the generated SQL self-describing.
        op.execute(sa.text("SELECT 'EcoMind-AI baseline (offline render)' AS notice"))
        return

    connection = op.get_bind()

    version_num = int(connection.execute(sa.text("SHOW server_version_num")).scalar_one())
    server_version = connection.execute(sa.text("SHOW server_version")).scalar_one()

    if version_num < MINIMUM_SERVER_VERSION_NUM:
        raise RuntimeError(
            "EcoMind-AI requires PostgreSQL 13 or newer because every primary key "
            "defaults to gen_random_uuid(), a built-in from version 13. "
            f"Connected server reports {server_version} "
            f"(server_version_num={version_num})."
        )

    # Report the version so a deploy log records exactly what the schema was
    # applied against — useful when diagnosing environment drift.
    op.execute(
        sa.text(
            "DO $$ BEGIN RAISE NOTICE "
            "'EcoMind-AI baseline applied on PostgreSQL %', current_setting('server_version');"
            " END $$;"
        )
    )


def downgrade() -> None:
    """
    Revert the baseline.

    Deliberately empty: there is nothing to undo, and a no-op downgrade keeps
    ``alembic downgrade base`` from failing so the reversibility check in CI is
    meaningful from the first revision.
    """
