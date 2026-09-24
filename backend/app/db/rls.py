"""
Row-level security (RLS) for tenant isolation.

Tenant isolation is enforced in three independent layers (ADR-0003), because a
single missed ``WHERE tenant_id = ...`` in application code is a cross-tenant data
breach and code review does not catch every one of them:

1. **Schema** - every tenant-owned table carries ``tenant_id`` and a foreign key
   (:class:`app.db.base.TenantScopedMixin`).
2. **Query** - repositories always constrain by tenant.
3. **Policy** - PostgreSQL itself refuses to return or accept rows belonging to
   another tenant, whatever the query says. This module generates that policy.

Layer 3 is the one that holds when layers 1 and 2 are bypassed by a mistake, a
raw SQL query or a future contributor who did not know the rule. It is therefore
generated from one place rather than hand-written per migration, so it cannot be
forgotten for a table.

How the policy works
--------------------
Every request runs inside a transaction that sets ``app.tenant_id`` to the
authenticated tenant. The policy compares each row's ``tenant_id`` against that
setting. Two clauses are required, and omitting either opens a real hole:

* ``USING`` filters rows *read* (SELECT, UPDATE, DELETE).
* ``WITH CHECK`` filters rows *written* (INSERT, UPDATE). Without it a tenant can
  insert a row owned by another tenant: the row is invisible to them afterwards,
  but it exists in the other tenant's data.

The setting is read with ``current_setting('app.tenant_id', true)`` and wrapped in
``NULLIF(..., '')``, so an unset or empty value yields ``NULL``. ``NULL``
comparison is never true, so an unconfigured connection sees zero rows instead of
raising or, far worse, seeing everything. The policy fails closed.

Honest limitations
------------------
These are properties of PostgreSQL, not of this implementation, and they must be
understood before relying on RLS in production:

* **Table owners bypass RLS unless ``FORCE ROW LEVEL SECURITY`` is set.** This
  module emits ``FORCE`` for exactly that reason.
* **Superusers and roles with ``BYPASSRLS`` always bypass RLS**, even with
  ``FORCE``. The application must therefore connect as an ordinary role: a
  superuser connection would silently disable this entire layer.
* ``app.tenant_id`` is transaction-local when set through
  :func:`apply_tenant_context` (``set_config(..., true)``). It is cleared at
  commit or rollback, which is what prevents a tenant's context from leaking into
  the next request that reuses the pooled connection.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import TYPE_CHECKING
from uuid import UUID

from sqlalchemy import text

if TYPE_CHECKING:  # pragma: no cover - typing only
    from sqlalchemy import MetaData
    from sqlalchemy.ext.asyncio import AsyncSession

__all__ = [
    "GLOBAL_TABLES",
    "IDENTIFIER_MAX_LENGTH",
    "TENANT_COLUMN",
    "TENANT_SETTING",
    "apply_tenant_context",
    "clear_tenant_context",
    "policy_name",
    "rls_coverage_report",
    "tenant_isolation_ddl",
    "tenant_scoped_table_names",
]

#: The transaction-local setting the policies compare against.
TENANT_SETTING = "app.tenant_id"

#: The column every tenant-owned table carries.
TENANT_COLUMN = "tenant_id"

#: PostgreSQL truncates identifiers to 63 bytes (NAMEDATALEN - 1).
IDENTIFIER_MAX_LENGTH = 63

#: Tables that are deliberately *not* tenant-scoped, each with the reason it is
#: global. This is an allowlist: a table that is neither in this mapping nor
#: tenant-scoped is a modelling decision someone has not made yet, and
#: ``tests/db/test_rls_coverage.py`` fails rather than assuming an answer.
GLOBAL_TABLES: dict[str, str] = {
    "alembic_version": (
        "Migration bookkeeping. Rows are not tenant data; one revision applies to "
        "the whole database."
    ),
    "tenants": (
        "The tenant registry itself. A row is not owned by a tenant, it *is* a "
        "tenant. Access to it is decided by platform-level authorization, not RLS."
    ),
    "waste_categories": (
        "Platform-wide waste taxonomy shared by all tenants, so that analytics and "
        "carbon factors are comparable between municipalities. Tenants may add "
        "local categories by extending rather than replacing it."
    ),
    "emission_factors": (
        "Published environmental factors (for example grid carbon intensity). They "
        "are shared reference data with a citation and a version, not tenant data."
    ),
    "unit_conversions": ("Physical unit conversion constants. Global by definition."),
}


def policy_name(table_name: str) -> str:
    """
    The RLS policy name for ``table_name``.

    PostgreSQL silently truncates identifiers at 63 bytes, so two long table names
    sharing a 50-character prefix would collide on the same policy name — and
    ``CREATE POLICY`` would then attach the second table's policy to the first,
    leaving one table unprotected while the migration reported success. Long names
    therefore carry a deterministic hash instead of being truncated.
    """
    candidate = f"tenant_isolation_{table_name}"
    if len(candidate) <= IDENTIFIER_MAX_LENGTH:
        return candidate

    digest = hashlib.sha256(table_name.encode("utf-8")).hexdigest()[:10]
    keep = IDENTIFIER_MAX_LENGTH - len("tenant_isolation__") - len(digest)
    return f"tenant_isolation_{table_name[:keep]}_{digest}"


def _predicate(column: str) -> str:
    """
    The SQL predicate a row must satisfy to belong to the current tenant.

    ``NULLIF`` guards the empty string that ``current_setting`` returns when the
    setting was configured but blank; ``::uuid`` would otherwise raise a cast
    error on every query.
    """
    return f"{column} = NULLIF(current_setting('{TENANT_SETTING}', true), '')::uuid"


def tenant_isolation_ddl(
    table_name: str,
    *,
    column: str = TENANT_COLUMN,
) -> list[str]:
    """
    The statements that put ``table_name`` under tenant-isolating RLS.

    Idempotent: the policy is dropped before being created, so re-running a
    migration, or adding the DDL to a table provisioned by an earlier migration,
    converges on the same end state instead of failing on a duplicate name.

    The statements are returned rather than executed so a migration owns its own
    transaction and this module stays usable from tests and from a review script
    that only prints the SQL.
    """
    if column != TENANT_COLUMN:
        # A different column is legal (an association table keyed on a tenant
        # reference of another name), but it must be a decision, not a typo.
        raise ValueError(
            f"unexpected tenant column {column!r}; tenant-owned tables use "
            f"{TENANT_COLUMN!r}. Pass column= explicitly to override."
        )

    predicate = _predicate(column)
    quoted = f'"{table_name}"'
    name = policy_name(table_name)

    return [
        f"ALTER TABLE {quoted} ENABLE ROW LEVEL SECURITY",
        # Without FORCE, the table *owner* bypasses every policy above. The
        # migration role typically owns the tables it creates, so omitting this
        # would leave the layer inert during any administrative connection.
        f"ALTER TABLE {quoted} FORCE ROW LEVEL SECURITY",
        f"DROP POLICY IF EXISTS {name} ON {quoted}",
        (f"CREATE POLICY {name} ON {quoted} USING ({predicate}) WITH CHECK ({predicate})"),
    ]


def tenant_scoped_table_names(metadata: MetaData) -> list[str]:
    """
    Names of the tables in ``metadata`` that carry a ``tenant_id`` column.

    Detection is by column, not by mixin: a table that declares ``tenant_id``
    without the mixin is still tenant data, and introspection is what the database
    itself will enforce.
    """
    return sorted(
        table.name for table in metadata.tables.values() if TENANT_COLUMN in table.columns
    )


def rls_coverage_report(metadata: MetaData) -> dict[str, list[str]]:
    """
    Classify every table in ``metadata`` as tenant-scoped, global, or unclassified.

    ``unclassified`` must be empty: every table is either tenant-owned, or global
    for a written reason. A table in neither group means someone added a table
    without deciding whether it holds tenant data, and the safe assumption at that
    point is neither answer.
    """
    tenant_scoped: list[str] = []
    global_tables: list[str] = []
    unclassified: list[str] = []

    for name in sorted(metadata.tables):
        table = metadata.tables[name]
        if TENANT_COLUMN in table.columns:
            tenant_scoped.append(name)
        elif name in GLOBAL_TABLES:
            global_tables.append(name)
        else:
            unclassified.append(name)

    return {
        "tenant_scoped": tenant_scoped,
        "global": global_tables,
        "unclassified": unclassified,
    }


def planned_ddl(metadata: MetaData) -> list[str]:
    """
    Every RLS statement the schema requires, in a stable order.

    Used by a review script to show a DBA exactly what isolation will be applied,
    and by the coverage test to assert each tenant-owned table is covered.
    """
    statements: list[str] = []
    for name in tenant_scoped_table_names(metadata):
        statements.extend(tenant_isolation_ddl(name))
    return statements


# ---------------------------------------------------------------------------
# Session context
# ---------------------------------------------------------------------------
async def apply_tenant_context(session: AsyncSession, tenant_id: UUID | str) -> None:
    """
    Bind the current transaction to ``tenant_id`` so RLS policies can see it.

    ``set_config(..., is_local=true)`` scopes the value to the transaction, so it
    is discarded at commit or rollback. That matters because connections are
    pooled: a session-scoped setting would survive into the next request, and the
    next tenant would inherit the previous tenant's context.

    The identifier is validated here rather than left to PostgreSQL, because
    ``set_config`` stores whatever string it is given — the ``::uuid`` cast in the
    policy only runs when a row is evaluated. A malformed value therefore sits in
    the session unnoticed, and the failure surfaces later as a cast error from
    inside an unrelated query, or as an empty result set where the policy never got
    that far. Validating at the point of binding converts that into an immediate,
    precise error at the call site.

    Passing ``None`` is rejected too, and deliberately. "No tenant" is expressed by
    simply not calling this function, which leaves the policy denying all rows;
    accepting ``None`` would make an unset context look like a successful binding.
    """
    if tenant_id is None:
        raise ValueError(
            "tenant_id must not be None. To run without a tenant context, omit "
            "the call: the policy then denies every row."
        )

    try:
        canonical = str(UUID(str(tenant_id)))
    except (ValueError, AttributeError, TypeError) as exc:
        raise ValueError(
            f"tenant_id must be a UUID; got {tenant_id!r}. PostgreSQL would accept "
            "the malformed value silently and fail later, somewhere unrelated."
        ) from exc

    await session.execute(
        text(f"SELECT set_config('{TENANT_SETTING}', :tenant_id, true)"),
        {"tenant_id": canonical},
    )


async def clear_tenant_context(session: AsyncSession) -> None:
    """Remove the tenant binding for the current transaction (deny-all until set)."""
    await session.execute(text(f"SELECT set_config('{TENANT_SETTING}', '', true)"))


async def tables_without_rls(
    session: AsyncSession,
    *,
    schema: str = "public",
    exempt: Iterable[str] = (),
) -> list[str]:
    """
    Live tables in ``schema`` that lack RLS or lack a policy.

    Metadata says what *should* exist; this asks the database what *does*. The two
    can disagree when a migration was skipped, hand-edited, or run against an
    environment that had drifted — which is precisely when an isolation guarantee
    is least safe to assume.

    Reports tables with ``relrowsecurity`` false, and tables where RLS is enabled
    but no policy exists (which denies every row and is a functional outage rather
    than a leak, but still a misconfiguration).
    """
    result = await session.execute(
        text(
            """
            SELECT c.relname AS table_name,
                   c.relrowsecurity AS rls_enabled,
                   count(p.policyname) AS policy_count
              FROM pg_class c
              JOIN pg_namespace n ON n.oid = c.relnamespace
              LEFT JOIN pg_policies p
                     ON p.schemaname = n.nspname AND p.tablename = c.relname
             WHERE n.nspname = :schema
               AND c.relkind = 'r'
             GROUP BY c.relname, c.relrowsecurity
             ORDER BY c.relname
            """
        ),
        {"schema": schema},
    )

    exempt_set = set(exempt) | set(GLOBAL_TABLES)
    return [
        row.table_name
        for row in result
        if row.table_name not in exempt_set and (not row.rls_enabled or row.policy_count == 0)
    ]


def describe_coverage(report: dict[str, list[str]]) -> str:
    """Human-readable summary, used in the gate report and in CI output."""
    lines: list[str] = []
    for group in ("tenant_scoped", "global", "unclassified"):
        names = report[group]
        lines.append(f"{group}: {len(names)}")
        for name in names:
            reason = GLOBAL_TABLES.get(name, "")
            suffix = f" - {reason}" if reason and group == "global" else ""
            lines.append(f"  - {name}{suffix}")
    return "\n".join(lines)
