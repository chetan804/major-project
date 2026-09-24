"""
Column type aliases.

These aliases encode the project rule that measured quantities are exact
decimals. The tests assert the *precision and scale* actually reach the database,
because an alias that silently degraded to ``Float`` would look identical at the
call site and only surface as accumulated drift months later.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from sqlalchemy import Integer, MetaData, Numeric, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from app.db.base import Base
from app.db.types import (
    CarbonKg,
    Code,
    Confidence,
    DistanceKm,
    EmissionFactorValue,
    Latitude,
    Longitude,
    LongText,
    Money,
    Percentage,
    Score,
    UnitPrice,
    VolumeCubicMetres,
    VolumeLiters,
    WeightKg,
)

pytestmark = pytest.mark.db


class _ProbeBase(DeclarativeBase):
    """A private declarative base so the probe table cannot pollute global metadata."""

    metadata = MetaData()


class Probe(_ProbeBase):
    """
    One column per alias, used only to inspect the resulting SQL types.

    Note the declaration form: the annotation carries the type and the alias is
    **not** passed to ``mapped_column``. Passing it positionally raises
    ``ArgumentError`` because ``mapped_column`` expects a ``SchemaItem`` there.
    ``test_aliases_must_not_be_passed_to_mapped_column`` pins that distinction.
    """

    __tablename__ = "probe_type_aliases"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    percentage: Mapped[Percentage]
    confidence: Mapped[Confidence]
    weight: Mapped[WeightKg]
    liters: Mapped[VolumeLiters]
    metres3: Mapped[VolumeCubicMetres]
    distance: Mapped[DistanceKm]
    latitude: Mapped[Latitude]
    longitude: Mapped[Longitude]
    carbon: Mapped[CarbonKg]
    factor: Mapped[EmissionFactorValue]
    money: Mapped[Money]
    price: Mapped[UnitPrice]
    score: Mapped[Score]
    code: Mapped[Code]


EXPECTED_NUMERIC: dict[str, tuple[int, int]] = {
    "percentage": (5, 2),
    "confidence": (5, 4),
    "weight": (12, 3),
    "liters": (12, 3),
    "metres3": (10, 3),
    "distance": (10, 3),
    "latitude": (9, 6),
    "longitude": (10, 7),
    "carbon": (16, 4),
    "factor": (16, 8),
    "money": (14, 2),
    "price": (12, 4),
    "score": (12, 6),
}


@pytest.mark.parametrize(("column", "precision_scale"), sorted(EXPECTED_NUMERIC.items()))
def test_numeric_aliases_declare_the_expected_precision(
    column: str, precision_scale: tuple[int, int]
) -> None:
    """
    Each alias must produce ``NUMERIC(precision, scale)`` exactly as documented.

    Precision matters operationally: ``WeightKg`` at three decimals gives gram
    resolution, ``Latitude`` at six decimals resolves to about 0.11 m, and
    ``EmissionFactorValue`` at eight decimals avoids a systematic error in every
    derived carbon estimate.
    """
    declared = Probe.__table__.c[column].type

    assert isinstance(declared, Numeric), f"{column} is {type(declared).__name__}, not NUMERIC"
    assert (declared.precision, declared.scale) == precision_scale


def test_no_measured_quantity_is_a_float() -> None:
    """
    No alias may resolve to a floating-point type.

    This is the schema-wide guarantee behind sections 7 and 36; a single float
    column in a measurement platform is a data-integrity defect.
    """
    float_columns = [
        name
        for name, column in Probe.__table__.c.items()
        if "FLOAT" in str(column.type).upper() or "REAL" in str(column.type).upper()
    ]

    assert float_columns == [], f"measured quantities declared as floating point: {float_columns}"


def test_text_aliases_are_bounded_where_appropriate() -> None:
    """
    Identifiers are length-capped; free text is not.

    A cap on an identifier keeps index sizes predictable, while capping a notes
    field would truncate operational context; the API schema caps the latter
    instead.
    """
    assert isinstance(Probe.__table__.c.code.type, String)
    assert Probe.__table__.c.code.type.length == 32


def test_optional_alias_infers_nullability() -> None:
    """
    ``Mapped[Alias | None]`` must produce a NULL-able column.

    Nullability is inferred from ``Optional`` rather than set explicitly, so a
    field that is genuinely optional (a bin's last fill reading before any
    telemetry has arrived) is expressed once instead of twice. Getting this wrong
    would make an optional measurement NOT NULL and reject valid inserts.
    """
    from sqlalchemy.orm import DeclarativeBase

    class _NullableBase(DeclarativeBase):
        metadata = MetaData()

    class _NullableProbe(_NullableBase):
        __tablename__ = "probe_nullable"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        required: Mapped[Percentage]
        optional: Mapped[Percentage | None]

    assert _NullableProbe.__table__.c.required.nullable is False
    assert _NullableProbe.__table__.c.optional.nullable is True


def test_aliases_must_not_be_passed_to_mapped_column() -> None:
    """
    Passing an alias positionally to ``mapped_column`` must raise.

    This documents the API contract of the aliases themselves. The error message
    is unhelpful (``'SchemaItem' object ... expected``), so a future contributor
    would otherwise spend time diagnosing a mistake this test names directly.
    """
    from sqlalchemy.exc import ArgumentError
    from sqlalchemy.orm import DeclarativeBase

    class _FailureBase(DeclarativeBase):
        metadata = MetaData()

    with pytest.raises(ArgumentError):

        class _BadProbe(_FailureBase):
            __tablename__ = "probe_bad_alias_usage"
            id: Mapped[int] = mapped_column(Integer, primary_key=True)
            percentage: Mapped[Percentage] = mapped_column(Percentage)


def test_alias_type_can_be_overridden_for_extra_options() -> None:
    """
    An alias may still be combined with ``mapped_column`` for extra options.

    Passing a real type instance (not the alias) alongside the alias annotation is
    the supported way to add a server default, an index or a comment.
    """
    from sqlalchemy import Numeric, text
    from sqlalchemy.orm import DeclarativeBase

    class _OverrideBase(DeclarativeBase):
        metadata = MetaData()

    class _OverrideProbe(_OverrideBase):
        __tablename__ = "probe_alias_override"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        fill: Mapped[Percentage] = mapped_column(
            Numeric(5, 2), server_default=text("0"), comment="Fill level percentage."
        )

    column = _OverrideProbe.__table__.c.fill
    assert isinstance(column.type, Numeric)
    assert column.server_default is not None
    assert column.comment == "Fill level percentage."


def test_base_metadata_has_a_usable_naming_convention() -> None:
    """
    The naming convention must cover every constraint kind.

    A missing entry means PostgreSQL invents a name for that constraint kind, and
    an autogenerated migration cannot then drop or alter it reliably.
    """
    convention = Base.metadata.naming_convention

    for key in ("ix", "uq", "ck", "fk", "pk"):
        assert key in convention, f"naming convention is missing {key!r}"


async def test_decimal_round_trips_through_a_numeric_bind(db_session) -> None:
    """A ``Decimal`` bound to a ``NUMERIC`` column must return byte-identical."""
    from sqlalchemy import text

    value = Decimal("12500.375")
    result = (
        await db_session.execute(text("SELECT CAST(:v AS numeric(12,3))"), {"v": value})
    ).scalar_one()

    assert result == value
    assert isinstance(result, Decimal)
    assert str(result) == "12500.375"


def test_long_text_maps_to_unbounded_text() -> None:
    """
    ``LongText`` must map to ``Text``, not a silently truncating ``String``.

    A capped column would reject or truncate long operational notes, and the
    failure would surface as lost field data rather than as an error.

    The probe model below is defined on a private metadata so this assertion
    cannot be satisfied by an unrelated column.

    ``LongText`` is imported at module level on purpose: the module uses
    ``from __future__ import annotations``, so SQLAlchemy resolves ``Mapped[...]``
    by evaluating the annotation string against module globals. A function-local
    import raises ``MappedAnnotationError: Could not resolve all types within
    mapped annotation``.
    """
    from sqlalchemy.orm import mapped_column

    class _TextProbeBase(DeclarativeBase):
        metadata = MetaData()

    class _TextProbe(_TextProbeBase):
        __tablename__ = "probe_long_text"
        id: Mapped[int] = mapped_column(Integer, primary_key=True)
        notes: Mapped[LongText]

    declared = _TextProbe.__table__.c.notes.type

    assert isinstance(declared, Text)
    assert not isinstance(declared, String) or getattr(declared, "length", None) is None
