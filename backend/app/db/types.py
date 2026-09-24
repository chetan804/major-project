"""
Reusable column types.

Centralising precision here prevents the single most damaging class of data bug
in a measurement platform: a weight, volume, carbon quantity or money amount
stored as a floating-point number and silently losing exactness. Every measured
quantity in this schema is ``NUMERIC`` (master directive, sections 7 and 36), and
these aliases are how models express that without repeating magic numbers.

Usage — declare the annotation and **do not** pass the alias to
``mapped_column``::

    from app.db.types import WeightKg, Percentage, VolumeLiters

    class Bin(Base):
        # NUMERIC(12,3) NOT NULL
        capacity_kg: Mapped[WeightKg]
        # NUMERIC(5,2) NULL — nullability is inferred from Optional
        last_fill_percentage: Mapped[Percentage | None]
        # Override something the alias does not set, e.g. a server default:
        volume: Mapped[VolumeLiters] = mapped_column(server_default=text("0"))

Why the alias is not passed positionally: ``mapped_column()`` expects a
``SchemaItem`` (a ``Column``, ``Constraint``, …) in that position, and an
``Annotated`` alias is not one. Passing it raises
``ArgumentError: 'SchemaItem' object ... expected``. The ``Annotated`` form is
resolved by SQLAlchemy's annotation map instead, which is also what lets it infer
``nullable`` from ``Optional``. Both facts are pinned by
``tests/db/test_types.py`` so the documented pattern cannot silently rot.
"""

from __future__ import annotations

from decimal import Decimal
from typing import Annotated

from sqlalchemy import Numeric, String, Text
from sqlalchemy.orm import mapped_column

__all__ = [
    "CarbonKg",
    "Code",
    "Confidence",
    "DistanceKm",
    "EmissionFactorValue",
    "Latitude",
    "LongText",
    "Longitude",
    "Money",
    "Percentage",
    "Score",
    "ShortText",
    "UnitPrice",
    "VolumeCubicMetres",
    "VolumeLiters",
    "WeightKg",
]

# ---------------------------------------------------------------------------
# Percentages and bounded ratios
# ---------------------------------------------------------------------------
#: A 0-100 percentage with two decimal places (fill level, battery, humidity).
#: The 0-100 bound is additionally enforced by a CHECK constraint per column,
#: because a range the database enforces cannot be bypassed by a code path.
Percentage = Annotated[Decimal, mapped_column(Numeric(5, 2))]

#: A unit-interval probability or confidence (0.0000-1.0000).
Confidence = Annotated[Decimal, mapped_column(Numeric(5, 4))]

# ---------------------------------------------------------------------------
# Measured quantities
# ---------------------------------------------------------------------------
#: Mass in kilograms. Three decimals gives gram resolution, which comfortably
#: exceeds weighbridge and onboard-scale accuracy.
WeightKg = Annotated[Decimal, mapped_column(Numeric(12, 3))]

#: Volume in litres.
VolumeLiters = Annotated[Decimal, mapped_column(Numeric(12, 3))]

#: Volume in cubic metres.
VolumeCubicMetres = Annotated[Decimal, mapped_column(Numeric(10, 3))]

#: Distance in kilometres.
DistanceKm = Annotated[Decimal, mapped_column(Numeric(10, 3))]

# ---------------------------------------------------------------------------
# Geospatial (ADR-0005 — no PostGIS requirement)
# ---------------------------------------------------------------------------
#: Latitude in decimal degrees (-90..90), six decimals (~0.11 m at the equator).
Latitude = Annotated[Decimal, mapped_column(Numeric(9, 6))]

#: Longitude in decimal degrees (-180..180), seven decimals (~0.011 m).
Longitude = Annotated[Decimal, mapped_column(Numeric(10, 7))]

# ---------------------------------------------------------------------------
# Environmental accounting
# ---------------------------------------------------------------------------
#: Carbon dioxide equivalent in kilograms, four decimals.
CarbonKg = Annotated[Decimal, mapped_column(Numeric(16, 4))]

#: An emission factor value. Eight decimals because factors are published at
#: high precision (e.g. 2.63910 kgCO2e/litre) and rounding them would introduce
#: a systematic error into every derived estimate.
EmissionFactorValue = Annotated[Decimal, mapped_column(Numeric(16, 8))]

# ---------------------------------------------------------------------------
# Money
# ---------------------------------------------------------------------------
#: A monetary amount, two decimals.
Money = Annotated[Decimal, mapped_column(Numeric(14, 2))]

#: A unit price (per kg, per litre, per kWh), four decimals.
UnitPrice = Annotated[Decimal, mapped_column(Numeric(12, 4))]

# ---------------------------------------------------------------------------
# Scores
# ---------------------------------------------------------------------------
#: A model or risk score, six decimals.
Score = Annotated[Decimal, mapped_column(Numeric(12, 6))]

# ---------------------------------------------------------------------------
# Text conventions
# ---------------------------------------------------------------------------
#: A short identifier or name (60 characters).
ShortText = Annotated[str, mapped_column(String(60))]

#: A human-facing code such as ``BIN-00042`` (32 characters).
Code = Annotated[str, mapped_column(String(32))]

#: Free text without a database-level length cap; the API schema caps it.
LongText = Annotated[str, mapped_column(Text)]
