"""
Row-level security: the third layer of tenant isolation.

The important test in this module does not inspect metadata or compare strings. It
provisions two tenants, inserts rows for both, sets ``app.tenant_id`` to one of
them, and then asks PostgreSQL — not the application, not the ORM — what it will
return. If the policies are wrong, the database itself returns the other tenant's
row and the test fails.

That distinction matters because the whole point of layer 3 is to hold when the
application layer is wrong. A test that only checked the generated SQL would
verify the thing that had already been reviewed and miss the thing that had not.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import pytest
from sqlalchemy import text

from app.db import rls

pytestmark = pytest.mark.db

TENANT_A = UUID("11111111-1111-4111-8111-111111111111")
TENANT_B = UUID("22222222-2222-4222-8222-222222222222")


# ---------------------------------------------------------------------------
# The generated SQL
# ---------------------------------------------------------------------------
def test_generated_ddl_covers_both_read_and_write_clauses() -> None:
    """
    ``USING`` alone would let a tenant *write* another tenant's row.

    Without ``WITH CHECK`` a tenant can INSERT a row carrying a foreign
    ``tenant_id``. The row is invisible to them afterwards, so nothing looks wrong
    from their side, while the other tenant's dataset has silently gained a forged
    record. Both clauses are therefore required, not optional.
    """
    statements = rls.tenant_isolation_ddl("bins")
    joined = "\n".join(statements)

    assert 'ALTER TABLE "bins" ENABLE ROW LEVEL SECURITY' in joined
    assert 'ALTER TABLE "bins" FORCE ROW LEVEL SECURITY' in joined
    assert "USING (" in joined
    assert "WITH CHECK (" in joined
    assert statements[-1].startswith("CREATE POLICY ")


def test_policy_fails_closed_when_the_tenant_setting_is_unset() -> None:
    """
    An unconfigured connection must see nothing, not everything.

    ``current_setting(..., true)`` returns NULL when the setting was never set,
    and ``NULLIF`` folds a blank setting to NULL as well. A comparison against NULL
    is never true, so the predicate excludes every row. The alternative — a
    predicate that is true when the setting is absent — would expose the whole
    table to any connection that forgot to set the context, which is the exact
    failure RLS exists to prevent.
    """
    statement = rls.tenant_isolation_ddl("bins")[-1]

    assert "current_setting('app.tenant_id', true)" in statement
    assert "NULLIF(" in statement, "a blank setting would fail the ::uuid cast"
    assert "::uuid" in statement


def test_policy_names_stay_within_the_identifier_limit() -> None:
    """
    A 63-byte name limit can silently merge two tables' policies.

    PostgreSQL truncates identifiers. Two long table names sharing a prefix would
    produce the same truncated policy name, and ``CREATE POLICY`` would attach the
    second policy to the first table — which then has two policies while the second
    table has none, and the migration still exits 0.
    """
    short = rls.policy_name("bins")
    assert short == "tenant_isolation_bins"
    assert len(short) <= rls.IDENTIFIER_MAX_LENGTH

    long_a = "waste_" + "a" * 60
    long_b = "waste_" + "a" * 59 + "b"
    name_a, name_b = rls.policy_name(long_a), rls.policy_name(long_b)

    assert len(name_a) <= rls.IDENTIFIER_MAX_LENGTH
    assert len(name_b) <= rls.IDENTIFIER_MAX_LENGTH
    assert name_a != name_b, "distinct tables must not collide on a policy name"
    # Deterministic, so re-running a migration reproduces the same name.
    assert rls.policy_name(long_a) == name_a


def test_ddl_is_idempotent() -> None:
    """Re-running must converge, not fail on an existing policy."""
    joined = "\n".join(rls.tenant_isolation_ddl("bins"))
    assert "DROP POLICY IF EXISTS" in joined


def test_an_unexpected_tenant_column_is_rejected() -> None:
    """
    A mistyped column would generate a policy that protects nothing.

    A policy on a non-existent column still creates successfully in some cases and
    would match ``NULL``, silently denying or admitting everything. Rejecting the
    call is the only safe response.
    """
    with pytest.raises(ValueError, match="unexpected tenant column"):
        rls.tenant_isolation_ddl("bins", column="tenantId")


def test_coverage_report_flags_an_unclassified_table() -> None:
    """
    Every table must be tenant-owned or global-by-decision.

    A table in neither group means someone added a table without deciding whether
    it holds tenant data. Neither default is safe — treating it as global leaks
    tenant rows, treating it as tenant-scoped breaks a legitimate lookup — so the
    report surfaces it and the caller fails.
    """
    from sqlalchemy import Column, Integer, MetaData, Table
    from sqlalchemy.dialects.postgresql import UUID as PGUUID

    metadata = MetaData()
    Table(
        "bins",
        metadata,
        Column("id", Integer, primary_key=True),
        Column("tenant_id", PGUUID(as_uuid=True), nullable=False),
    )
    Table("tenants", metadata, Column("id", Integer, primary_key=True))
    Table("mystery_table", metadata, Column("id", Integer, primary_key=True))

    report = rls.rls_coverage_report(metadata)

    assert report["tenant_scoped"] == ["bins"]
    assert report["global"] == ["tenants"]
    assert report["unclassified"] == ["mystery_table"]


# ---------------------------------------------------------------------------
# The policy, enforced by PostgreSQL
# ---------------------------------------------------------------------------
PROBE_TABLE = "rls_probe"


async def _provision(rls_session, *, create: bool = True) -> None:
    """
    Create a tenant-owned probe table and put it under RLS, as the RLS role.

    The table is created *by the non-superuser role* so that the role owns it, and
    ``FORCE ROW LEVEL SECURITY`` is then what makes the owner subject to the
    policy. The DDL under test is the module's own output, so this exercises the
    real artefact rather than a hand-written copy that could drift away from it.

    Provisioning runs as the role rather than as ``postgres`` because a table
    created by a superuser is not the situation the policy is meant to protect.
    """
    if create:
        # A test that commits leaves the probe behind, and the next test's
        # transaction cannot see it unless the session is reset first. Clearing
        # explicitly makes each test independent of the order it ran in.
        await rls_session.rollback()
        await rls_session.execute(text(f"DROP TABLE IF EXISTS {PROBE_TABLE}"))
    await rls_session.execute(
        text(
            f"CREATE TABLE {PROBE_TABLE} ("
            "  id serial PRIMARY KEY,"
            "  tenant_id uuid NOT NULL,"
            "  label text NOT NULL"
            ")"
        )
    )
    for statement in rls.tenant_isolation_ddl(PROBE_TABLE):
        await rls_session.execute(text(statement))


async def _insert_as(rls_session, tenant, label: str) -> None:
    """
    Insert one row *as* ``tenant``.

    The tenant context is bound first, and it has to be: the ``WITH CHECK`` clause
    rejects an insert whose ``tenant_id`` does not match the session setting, so
    writing without a bound tenant raises "new row violates row-level security
    policy". That is the intended production pattern too — a request binds its
    tenant at the start of its transaction and every write in that transaction
    carries it.
    """
    await rls.apply_tenant_context(rls_session, tenant)
    await rls_session.execute(
        text("INSERT INTO rls_probe (tenant_id, label) VALUES (:t, :label)"),
        {"t": str(tenant), "label": label},
    )


async def test_a_tenant_sees_only_its_own_rows(rls_session) -> None:
    """
    The core guarantee: the database withholds another tenant's rows.

    The SELECT below has no ``WHERE`` clause at all, deliberately. If the policy is
    doing its job the row is gone; if isolation depends on the query being written
    correctly, this test fails — which is the point.
    """
    await _provision(rls_session)

    await _insert_as(rls_session, TENANT_A, "bin-a")
    await _insert_as(rls_session, TENANT_B, "bin-b")

    await rls.apply_tenant_context(rls_session, TENANT_A)
    rows_a = (
        (await rls_session.execute(text("SELECT label FROM rls_probe ORDER BY label")))
        .scalars()
        .all()
    )
    assert rows_a == ["bin-a"]

    # The other tenant, same transaction shape, different setting.
    await rls.apply_tenant_context(rls_session, TENANT_B)
    rows_b = (
        (await rls_session.execute(text("SELECT label FROM rls_probe ORDER BY label")))
        .scalars()
        .all()
    )
    assert rows_b == ["bin-b"]


async def test_no_tenant_context_returns_no_rows(rls_session) -> None:
    """
    With the setting cleared, the table reads as empty.

    This is what a connection that forgot to bind a tenant looks like: no rows, not
    all rows. An empty result may still be a bug, but it is a *safe* bug — it
    cannot disclose another tenant's data, and it is apparent in the first test
    that exercises the endpoint.
    """
    await _provision(rls_session)
    await _insert_as(rls_session, TENANT_A, "bin-a")

    # The row exists and is committed to this transaction; the question is only
    # whether a connection with no tenant binding can see it.
    await rls.clear_tenant_context(rls_session)
    assert (await rls_session.execute(text("SELECT count(*) FROM rls_probe"))).scalar_one() == 0


async def test_a_tenant_cannot_write_a_row_for_another_tenant(rls_session) -> None:
    """
    ``WITH CHECK`` blocks the forged INSERT.

    Without it this statement succeeds, and the second tenant's dataset gains a
    record they never created. The inserted row is invisible to the writer, so
    nothing appears wrong until someone reconciles the other tenant's data.
    """
    from sqlalchemy.exc import ProgrammingError

    await _provision(rls_session)
    await rls.apply_tenant_context(rls_session, TENANT_A)

    with pytest.raises(ProgrammingError) as excinfo:
        await rls_session.execute(
            text("INSERT INTO rls_probe (tenant_id, label) VALUES (:b, 'forged')"),
            {"b": str(TENANT_B)},
        )

    assert "row-level security" in str(excinfo.value).lower()
    await rls_session.rollback()


async def test_a_tenant_may_write_a_row_for_itself(rls_session) -> None:
    """
    The positive control for the test above.

    Without this, a policy that rejected *every* insert would satisfy the forged-row
    test while making the table unusable. A restriction is only demonstrated by
    showing the permitted case still works.
    """
    await _provision(rls_session)

    await _insert_as(rls_session, TENANT_A, "mine")

    assert (await rls_session.execute(text("SELECT count(*) FROM rls_probe"))).scalar_one() == 1


async def test_tenant_context_does_not_survive_a_transaction(rls_session) -> None:
    """
    The setting is transaction-local, so a pooled connection cannot leak it.

    ``set_config(..., true)`` is scoped to the transaction. A session-scoped
    setting would outlive the commit, and the next request to check out the same
    connection — possibly for a different tenant — would inherit the previous
    tenant's identity while believing it had set its own.
    """
    await _provision(rls_session)
    await _insert_as(rls_session, TENANT_A, "bin-a")
    # Sanity check inside the same transaction: the write is visible while the
    # context holds, so the assertion after the commit tests the boundary and not
    # a failed insert.
    assert (await rls_session.execute(text("SELECT count(*) FROM rls_probe"))).scalar_one() == 1

    await rls_session.commit()

    # A fresh transaction on the same session: the setting must be gone.
    visible = (await rls_session.execute(text("SELECT count(*) FROM rls_probe"))).scalar_one()

    assert visible == 0, (
        "tenant context survived the transaction boundary, so it would leak to "
        "whatever runs next on this pooled connection"
    )


UNPROTECTED_TABLE = "rls_unprotected_probe"


async def test_the_live_database_reports_tables_without_rls(db_session) -> None:
    """
    The introspection query must detect an unprotected table.

    ``tables_without_rls`` asks the database what is actually true rather than
    trusting that migrations ran, so it is verified against a table that genuinely
    has no policy — and against a protected one that must *not* be reported.

    The table must live in the ``public`` schema. A temporary table would sit in
    ``pg_temp_N`` and the query, which scopes to one schema, would not see it —
    so the test would pass or fail for a reason unrelated to what it claims to
    check.
    """
    await _provision_as_postgres(db_session)
    await db_session.execute(
        text(
            f"CREATE TABLE IF NOT EXISTS {UNPROTECTED_TABLE} ("
            "  id serial PRIMARY KEY, tenant_id uuid"
            ")"
        )
    )

    try:
        unprotected = await rls.tables_without_rls(db_session)
    finally:
        await db_session.rollback()
        await db_session.execute(text(f"DROP TABLE IF EXISTS {UNPROTECTED_TABLE}"))
        await db_session.execute(text(f"DROP TABLE IF EXISTS {PROBE_TABLE}"))
        await db_session.commit()

    assert UNPROTECTED_TABLE in unprotected, (
        "a table with no RLS policy must be reported; this query is the deploy-time "
        "check, so a false negative here means an unprotected table ships silently"
    )
    # The positive control: a table carrying the generated policy must not appear.
    assert PROBE_TABLE not in unprotected, (
        "a table with RLS enabled and a policy must not be reported, or the check "
        "can never pass and will be ignored"
    )


async def _provision_as_postgres(db_session) -> None:
    """
    Provision the probe table as ``postgres``.

    Used only by the introspection test, which checks the *database's* reported
    state rather than the enforcing behaviour, so RLS does not need to be active
    for the querying role.
    """
    await db_session.rollback()
    await db_session.execute(text(f"DROP TABLE IF EXISTS {PROBE_TABLE}"))
    await db_session.execute(
        text(
            f"CREATE TABLE {PROBE_TABLE} ("
            "  id serial PRIMARY KEY,"
            "  tenant_id uuid NOT NULL,"
            "  label text NOT NULL"
            ")"
        )
    )
    for statement in rls.tenant_isolation_ddl(PROBE_TABLE):
        await db_session.execute(text(statement))
    await db_session.commit()


async def test_tables_without_rls_exempts_global_tables(db_session) -> None:
    """
    Global tables are expected to have no policy and must not be reported.

    Otherwise every deployment check would fail on ``alembic_version``, the check
    would be muted, and the real finding would be lost among the noise.
    """
    unchecked = await rls.tables_without_rls(db_session, exempt=["anything_else"])

    assert "alembic_version" not in unchecked, (
        "alembic_version is bookkeeping, not tenant data; reporting it would make "
        "the deploy-time check fail on every environment until it was muted"
    )


async def test_apply_tenant_context_rejects_a_malformed_identifier(rls_session) -> None:
    """
    A malformed tenant id must raise at the call site, not later.

    Measured behaviour, which is why the check is in Python rather than delegated:
    ``set_config`` stores any string it is handed. The ``::uuid`` cast appears only
    in the policy predicate, so a malformed value is accepted here and fails when a
    row is next evaluated — which may be never, in a request that only writes to
    tables whose policies are not reached. The test below asserts both halves: that
    PostgreSQL accepts the bad value, and that our binding rejects it anyway.
    """
    with pytest.raises(ValueError, match="must be a UUID"):
        await rls.apply_tenant_context(rls_session, "not-a-uuid")

    with pytest.raises(ValueError, match="must not be None"):
        await rls.apply_tenant_context(rls_session, None)  # type: ignore[arg-type]

    await rls_session.rollback()


async def test_postgres_alone_would_accept_a_malformed_tenant_setting(rls_session) -> None:
    """
    Evidence for the check above, so it is not removed as redundant.

    If ``set_config`` rejected a non-UUID, the Python validation would be
    unnecessary. It does not, and this records that so a future reader does not
    delete the guard on the assumption that the database enforces it.
    """
    await rls_session.execute(text("SELECT set_config('app.tenant_id', 'not-a-uuid', true)"))

    stored = (
        await rls_session.execute(text("SELECT current_setting('app.tenant_id', true)"))
    ).scalar_one()

    assert stored == "not-a-uuid", (
        "PostgreSQL accepted a non-UUID tenant setting without complaint; the "
        "validation in apply_tenant_context is therefore load-bearing"
    )
    await rls_session.rollback()


async def test_tenant_isolation_survives_a_second_tenant(rls_session) -> None:
    """
    Isolation must hold for arbitrary tenants, not one hard-coded pair.

    A policy that compared against a literal rather than the session setting would
    pass a single-tenant test and fail in production.
    """
    await _provision(rls_session)
    tenant_c = uuid4()
    tenant_d = uuid4()

    await _insert_as(rls_session, tenant_c, "c-bin")
    await _insert_as(rls_session, tenant_d, "d-bin")

    await rls.apply_tenant_context(rls_session, tenant_c)
    assert ((await rls_session.execute(text("SELECT label FROM rls_probe"))).scalars().all()) == [
        "c-bin"
    ]

    await rls.apply_tenant_context(rls_session, tenant_d)
    assert ((await rls_session.execute(text("SELECT label FROM rls_probe"))).scalars().all()) == [
        "d-bin"
    ]
