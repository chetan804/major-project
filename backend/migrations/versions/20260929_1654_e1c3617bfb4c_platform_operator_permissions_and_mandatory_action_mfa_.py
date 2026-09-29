"""platform operator permissions and mandatory action MFA policy

Revision ID: e1c3617bfb4c
Revises: c4195297efc7
Create Date: 2026-09-29 16:54:57.803508+00:00

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


revision: str = 'e1c3617bfb4c'
down_revision: str | None = 'c4195297efc7'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('users', sa.Column('platform_mfa_required', sa.Boolean(), server_default=sa.text('false'), nullable=False))
    # Frozen seed definitions, not imports of a future application catalogue.
    op.execute(sa.text("""INSERT INTO permissions (id, code, resource, action, scope, description, is_dangerous)
        VALUES ('88eb72e0-69e8-5390-89ea-72e16af260fa', 'platform.operators.read', 'platform', 'operators.read', 'PLATFORM', 'Read platform operator metadata.', false) ON CONFLICT (code) DO NOTHING"""))
    op.execute(sa.text("""INSERT INTO permissions (id, code, resource, action, scope, description, is_dangerous)
        VALUES ('b363a042-9ccb-5b1e-9abe-278ffb7a61b8', 'platform.operators.write', 'platform', 'operators.write', 'PLATFORM', 'Invite and contain platform operators; require action MFA.', true) ON CONFLICT (code) DO NOTHING"""))
    op.execute(sa.text("""
        DO $grant_operators$
        DECLARE previous_scope text := current_setting('app.tenant_id', true);
        BEGIN
          PERFORM set_config('app.tenant_id', '00000000-0000-0000-0000-000000000000', true);
          INSERT INTO role_permissions (tenant_id, role_id, permission_id)
          SELECT r.tenant_id, r.id, p.id FROM roles r CROSS JOIN permissions p
          WHERE r.tenant_id = '00000000-0000-0000-0000-000000000000' AND r.code = 'SUPER_ADMIN'
            AND r.is_system AND p.code IN ('platform.operators.read', 'platform.operators.write')
          ON CONFLICT DO NOTHING;
          PERFORM set_config('app.tenant_id', coalesce(previous_scope, ''), true);
        END $grant_operators$;
    """))


def downgrade() -> None:
    # Drain old/new API writers. Preserve policy rather than silently allowing
    # password-only writes; guard and removal share one locked transaction.
    op.execute(sa.text("LOCK TABLE users IN ACCESS EXCLUSIVE MODE"))
    op.execute(sa.text("""
        DO $policy_guard$
        DECLARE tenant_scope uuid;
                previous_scope text := current_setting('app.tenant_id', true);
        BEGIN
          FOR tenant_scope IN SELECT id FROM tenants LOOP
            PERFORM set_config('app.tenant_id', tenant_scope::text, true);
            IF EXISTS (SELECT 1 FROM users WHERE tenant_id = tenant_scope AND platform_mfa_required) THEN
              RAISE EXCEPTION 'Required MFA policy exists; downgrade requires a reviewed compatible migration';
            END IF;
            DELETE FROM role_permissions WHERE tenant_id = tenant_scope AND permission_id IN
              (SELECT id FROM permissions WHERE code IN ('platform.operators.read', 'platform.operators.write'));
          END LOOP;
          PERFORM set_config('app.tenant_id', coalesce(previous_scope, ''), true);
        END $policy_guard$;
        DELETE FROM permissions WHERE code IN ('platform.operators.read', 'platform.operators.write');
    """))
    op.drop_column('users', 'platform_mfa_required')
