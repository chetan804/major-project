"""${message}

Revision ID: ${up_revision}
Revises: ${down_revision | comma,n}
Create Date: ${create_date}

Design notes for the reviewer:

* Tenant-owned tables require a non-null ``tenant_id`` and forced row-level
  security (``docs/security/security-model.md`` §4). TenantScopedMixin adds
  a registry FK; TenantKeyMixin intentionally omits it for shared-scope rows
  such as sessions and audit logs. Do not infer FK locking from a column name.
  ``tests/db/test_rls_coverage.py`` checks the isolation policies, not universal FKs.
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
