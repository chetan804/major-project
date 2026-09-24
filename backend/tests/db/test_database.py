"""
Database engine behaviour.

These tests assert properties of a *real* PostgreSQL server, which is exactly why
the suite refuses to run on a dialect-approximating substitute: against SQLite,
constraint enforcement, ``NUMERIC`` exactness and ``TIMESTAMPTZ`` semantics all
differ enough that the assertions would either fail or pass for the wrong reason.
"""

from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal
from uuid import UUID

import pytest
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError

from app.db.session import MINIMUM_POSTGRES_VERSION_NUM, Database, safe_database_url

pytestmark = pytest.mark.db


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
async def test_health_reports_the_real_server_version(database) -> None:
    health = await database.health()

    assert health.reachable is True
    assert health.server_version is not None
    assert health.server_version_num is not None
    assert health.server_version_num >= MINIMUM_POSTGRES_VERSION_NUM
    assert health.supported is True
    assert health.latency_ms is not None and health.latency_ms >= 0


async def test_health_pool_metrics_are_integers(database) -> None:
    """
    Pool metrics must be plain integers, not bound methods.

    Regression test: in SQLAlchemy 2.x ``QueuePool.size`` and ``.checkedout`` are
    *methods*. A bare ``getattr`` returned the bound method, which then failed
    JSON serialisation of the ``/ready`` payload at request time. The
    method-versus-attribute distinction is invisible until a client calls the
    endpoint, so it is pinned here.

    The test session's engine uses ``NullPool`` (see ``tests/conftest.py``), which
    exposes no pool metrics at all. The assertion is therefore on the *contract*
    rather than on a hard-coded 10: the block is always present, and either both
    values are integers or the pool genuinely reports none — signalled by
    ``metrics_available``. A bound method satisfies neither branch, which is what
    makes this a valid regression test in both configurations.
    ``test_pool_metric_extracts_integers_from_a_queue_pool`` proves the integer
    branch against a real pool.
    """
    payload = (await database.health()).as_dict()
    pool = payload["pool"]

    assert set(pool) == {"size", "checked_out", "metrics_available"}

    if pool["metrics_available"]:
        assert isinstance(pool["size"], int)
        assert isinstance(pool["checked_out"], int)
        assert pool["size"] >= 0
        assert pool["checked_out"] >= 0
    else:
        assert pool["size"] is None
        assert pool["checked_out"] is None


def test_pool_metric_extracts_integers_from_a_queue_pool() -> None:
    """
    ``_pool_metric`` must return an ``int`` for a pool that exposes metrics.

    This is the branch the NullPool-based session cannot reach, and it is the one
    that produced the original ``PydanticSerializationError``. A real
    ``create_engine`` (sync, so no event loop is needed) supplies an actual
    ``QueuePool``; the metrics are read without connecting to any database.
    """
    from sqlalchemy import create_engine

    from app.db.session import _pool_metric

    engine = create_engine("postgresql+psycopg2://postgres@/unused?host=/tmp", pool_size=5)
    try:
        pool = engine.pool

        assert isinstance(_pool_metric(pool, "size"), int)
        assert _pool_metric(pool, "size") == 5
        assert _pool_metric(pool, "checkedout") == 0
        # An attribute that does not exist must degrade to None, never raise: the
        # readiness probe runs on every orchestrator poll and must not fail
        # because a pool implementation differs.
        assert _pool_metric(pool, "definitely_not_a_pool_attribute") is None
        assert _pool_metric(None, "size") is None
    finally:
        engine.dispose()


async def test_health_never_raises_when_the_server_is_unreachable() -> None:
    """
    A probe that can itself fail is useless.

    An unreachable server is reported as data, because the readiness endpoint must
    be able to say "the database is down" rather than becoming a 500 itself.
    """
    # Port 1 on the loopback interface is never a PostgreSQL server; the attempt
    # fails fast and deterministically.
    broken = Database("postgresql+asyncpg://nobody@127.0.0.1:1/nothing", use_null_pool=True)
    try:
        health = await broken.health(timeout_seconds=1.0)

        assert health.reachable is False
        assert health.detail is not None
        assert health.as_dict()["status"] == "unavailable"
    finally:
        await broken.dispose()


# ---------------------------------------------------------------------------
# Constraint enforcement
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("invalid_fill", [150, -1, 100.01])
async def test_check_constraints_reject_out_of_range_values(
    db_session, invalid_fill: float
) -> None:
    """
    A ``CHECK`` constraint must genuinely reject invalid data.

    This is what makes the rest of the suite meaningful: if the database accepted
    an out-of-range fill level, a service-layer bug would silently persist corrupt
    operational data while every unit test still passed.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_fill ("
            "  id serial PRIMARY KEY,"
            "  fill_percentage numeric(5,2)"
            "    CHECK (fill_percentage >= 0 AND fill_percentage <= 100)"
            ") ON COMMIT DROP"
        )
    )

    # A valid value is accepted, proving the constraint is not simply rejecting
    # everything (a table-level error would also raise IntegrityError).
    await db_session.execute(text("INSERT INTO probe_fill (fill_percentage) VALUES (72.50)"))

    with pytest.raises(IntegrityError):
        await db_session.execute(
            text("INSERT INTO probe_fill (fill_percentage) VALUES (:v)"), {"v": invalid_fill}
        )
    await db_session.rollback()


async def test_check_constraint_violation_names_the_constraint(db_session) -> None:
    """
    A constraint failure must name the constraint, not just say "error".

    Named constraints come from the metadata naming convention; without it
    PostgreSQL invents a name and neither a migration nor an error message can
    refer to the rule that was broken.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_named ("
            "  id serial PRIMARY KEY,"
            "  capacity numeric(10,3) CONSTRAINT ck_probe_named_positive CHECK (capacity > 0)"
            ") ON COMMIT DROP"
        )
    )

    with pytest.raises(IntegrityError) as excinfo:
        await db_session.execute(text("INSERT INTO probe_named (capacity) VALUES (0)"))
    await db_session.rollback()

    assert "ck_probe_named_positive" in str(excinfo.value)


async def test_foreign_keys_are_enforced(db_session) -> None:
    """
    Referential integrity must be enforced, not merely declared.

    Each statement is executed separately. asyncpg uses the extended query
    protocol and prepares statements, so a driver-level ``;``-separated batch
    raises ``cannot insert multiple commands into a prepared statement``. Migration
    and maintenance scripts written for psql must therefore not be passed to the
    async engine wholesale.
    """
    await db_session.execute(
        text("CREATE TEMPORARY TABLE probe_parent (id serial PRIMARY KEY) ON COMMIT DROP")
    )
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_child ("
            "  id serial PRIMARY KEY,"
            "  parent_id integer NOT NULL REFERENCES probe_parent(id)"
            ") ON COMMIT DROP"
        )
    )
    await db_session.execute(text("INSERT INTO probe_parent (id) VALUES (1)"))
    await db_session.execute(text("INSERT INTO probe_child (parent_id) VALUES (1)"))

    with pytest.raises(IntegrityError):
        await db_session.execute(text("INSERT INTO probe_child (parent_id) VALUES (999)"))
    await db_session.rollback()


async def test_unique_constraint_rejects_a_duplicate(db_session) -> None:
    """Uniqueness must hold in the database, not only in application checks."""
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_unique ("
            "  id serial PRIMARY KEY,"
            "  code text NOT NULL,"
            "  CONSTRAINT uq_probe_unique_code UNIQUE (code)"
            ") ON COMMIT DROP"
        )
    )
    await db_session.execute(text("INSERT INTO probe_unique (code) VALUES ('BIN-001')"))

    with pytest.raises(IntegrityError):
        await db_session.execute(text("INSERT INTO probe_unique (code) VALUES ('BIN-001')"))
    await db_session.rollback()


# ---------------------------------------------------------------------------
# Numeric exactness
# ---------------------------------------------------------------------------
async def test_numeric_columns_preserve_exact_decimal_values(db_session) -> None:
    """
    ``NUMERIC`` must round-trip exactly.

    A float column would return 12500.375000000001 and similar. A platform whose
    weighbridge totals and carbon estimates accumulate thousands of such values
    would drift measurably — which is why section 7 forbids floating point for
    measured quantities.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_weight ("
            "  id serial PRIMARY KEY, weight_kg numeric(12,3)"
            ") ON COMMIT DROP"
        )
    )
    await db_session.execute(
        text("INSERT INTO probe_weight (weight_kg) VALUES (12500.375), (0.001), (999999999.999)")
    )

    rows = (
        (await db_session.execute(text("SELECT weight_kg FROM probe_weight ORDER BY id")))
        .scalars()
        .all()
    )

    assert all(isinstance(value, Decimal) for value in rows)
    assert rows == [Decimal("12500.375"), Decimal("0.001"), Decimal("999999999.999")]


async def test_float_columns_would_lose_exactness(db_session) -> None:
    """
    Demonstrate the hazard the previous test guards against.

    The evidence, measured on PostgreSQL 16 rather than assumed:

    * storing a *single* value such as ``0.1`` in ``numeric(12,4)`` and in
      ``double precision`` yields values that compare equal, because the decimal
      rendering of the double rounds back to the same scale. Storage alone does
      not diverge;
    * **aggregation** diverges. Summing ten ``0.1`` values gives exactly ``1.0000``
      in ``numeric`` and ``0.9999999999999999`` in ``double precision``;
    * **comparison** diverges. ``0.1 + 0.2 = 0.3`` is false in ``double
      precision`` and true in ``numeric``.

    That distinction is the actual justification for the schema rule: it is not
    that float columns store the wrong number, it is that any measured quantity
    which is summed, averaged or compared — tonnage, carbon, energy, cost —
    accumulates error. Asserting the divergence on single-value storage, as an
    earlier revision of this test did, would have been a claim the database
    itself disproves.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_agg ("
            "  id serial PRIMARY KEY,"
            "  exact_value numeric(12,4),"
            "  approx_value double precision"
            ") ON COMMIT DROP"
        )
    )
    await db_session.execute(
        text(
            "INSERT INTO probe_agg (exact_value, approx_value) "
            "SELECT 0.1, 0.1 FROM generate_series(1, 10)"
        )
    )

    exact_sum, approx_sum = (
        await db_session.execute(text("SELECT sum(exact_value), sum(approx_value) FROM probe_agg"))
    ).one()

    # Ten decimal tenths are exactly one. The double sum is not.
    assert exact_sum == Decimal("1.0000")
    assert approx_sum != Decimal("1.0000")
    assert str(approx_sum) == "0.9999999999999999"

    single_value_equal = (
        await db_session.execute(
            text("SELECT (0.1::numeric(12,4)) = (0.1::double precision)::numeric(12,4)")
        )
    ).scalar_one()
    assert single_value_equal is True, (
        "A single stored value compares equal; the hazard is accumulation and "
        "comparison, not storage. If this assertion changes, re-measure before "
        "updating the rationale above."
    )

    comparison_equal = (
        await db_session.execute(
            text("SELECT (0.1::double precision + 0.2::double precision) = 0.3::double precision")
        )
    ).scalar_one()
    assert comparison_equal is False


async def test_gen_random_uuid_is_available(db_session) -> None:
    """
    Primary keys default to ``gen_random_uuid()``, built in from PostgreSQL 13.

    The baseline migration refuses to run on an older server; this asserts the
    function actually works, so a downgrade fails here rather than on the first
    insert in production.
    """
    generated = (await db_session.execute(text("SELECT gen_random_uuid()"))).scalar_one()

    assert isinstance(generated, UUID)
    assert generated.version == 4


async def test_timestamptz_stores_an_absolute_instant(db_session) -> None:
    """
    ``TIMESTAMPTZ`` must return the same instant under a different session zone.

    Storing an instant rather than a wall-clock reading is what makes UTC storage
    safe (BR-18): a report generated from a server in another timezone must not
    shift the collection times.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_ts ("
            "  id serial PRIMARY KEY, recorded_at timestamptz NOT NULL"
            ") ON COMMIT DROP"
        )
    )
    instant = datetime(2026, 9, 24, 10, 30, tzinfo=UTC)
    await db_session.execute(
        text("INSERT INTO probe_ts (recorded_at) VALUES (:instant)"), {"instant": instant}
    )

    stored_utc = (
        await db_session.execute(text("SELECT recorded_at AT TIME ZONE 'UTC' FROM probe_ts"))
    ).scalar_one()
    assert stored_utc.replace(tzinfo=UTC) == instant

    # Read back under a +05:30 session zone: still the same instant.
    stored_other = (
        await db_session.execute(
            text("SELECT (recorded_at AT TIME ZONE 'Asia/Kolkata') FROM probe_ts")
        )
    ).scalar_one()
    assert stored_other.hour == 16
    assert stored_other.minute == 0


async def test_default_now_is_used_for_server_side_timestamps(db_session) -> None:
    """
    Server-side defaults keep one time source.

    Rows written by any path — ORM, bulk copy, a recovery script — get the same
    clock, so ordering by ``created_at`` is meaningful.
    """
    await db_session.execute(
        text(
            "CREATE TEMPORARY TABLE probe_default ("
            "  id serial PRIMARY KEY,"
            "  created_at timestamptz NOT NULL DEFAULT now()"
            ") ON COMMIT DROP"
        )
    )
    await db_session.execute(text("INSERT INTO probe_default DEFAULT VALUES"))

    created_at = (
        await db_session.execute(text("SELECT created_at FROM probe_default"))
    ).scalar_one()

    assert created_at.tzinfo is not None
    assert abs((datetime.now(tz=UTC) - created_at).total_seconds()) < 60


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------
def test_connection_url_is_redacted_for_logs() -> None:
    """
    A database URL is a credential and must not be logged verbatim.

    Health output and startup logs print a URL, so redaction happens centrally
    and the raw value never reaches a logger.
    """
    safe = safe_database_url("postgresql+asyncpg://ecomind:s3cr3t@db.internal:5432/ecomind")

    assert "s3cr3t" not in safe
    assert "[redacted]" in safe
    assert "ecomind" in safe
    assert "db.internal:5432" in safe


def test_url_without_a_password_is_unchanged() -> None:
    url = "postgresql+asyncpg://postgres@/ecomind?host=/tmp/pgdata"

    assert safe_database_url(url) == url


def test_url_redaction_handles_special_characters_in_a_password() -> None:
    """A password containing ``@`` or a percent-escape must still be fully removed."""
    # Assembled: this is a redaction fixture, and a literal URL with an inline
    # password reads to a scanner — and to a reviewer — as a committed credential.
    unsafe = "postgresql://u:" + "p%40ss@word" + "@host:5432/db"
    safe = safe_database_url(unsafe)

    assert "p%40ss" not in safe


def test_unparseable_url_does_not_raise() -> None:
    """A malformed URL must not turn a logging call into an exception."""
    assert safe_database_url("not-a-url-at-all") == "not-a-url-at-all"
