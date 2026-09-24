"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Design notes for the reviewer:

* Tenant-owned tables must carry ``tenant_id`` with a foreign key to
  ``tenants.id`` and acquire a row-level security policy (see
  ``docs/security/security-model.md`` §4). A table without either is a
  cross-tenant disclosure waiting to happen, and
  ``tests/db/test_rls_coverage.py`` fails the build when one is missing.
* Measured quantities use ``NUMERIC`` via the aliases in ``app.db.types`` —
  never a floating-point type (master directive, sections 7 and 36).
* Indexes are added for query patterns that exist. Composite indexes follow the
  column order of those queries; an index on the wrong column order is not used.
* A destructive change (dropping a column or table holding operational history)
  requires an explicit data-migration step and a documented rollback plan.
"""

from __future__ import annotations

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
${imports if imports else ""}

revision: str = ${repr(up_revision)}
down_revision: str | None = ${repr(down_revision)}
branch_labels: str | Sequence[str] | None = ${repr(branch_labels)}
depends_on: str | Sequence[str] | None = ${repr(depends_on)}


def upgrade() -> None:
    ${upgrades if upgrades else "pass"}


def downgrade() -> None:
    ${downgrades if downgrades else "pass"}
