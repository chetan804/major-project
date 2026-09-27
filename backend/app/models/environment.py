"""
Environmental intelligence: emission factors, carbon estimates, metric rollups.

``emission_factors`` is **global** reference data (see ``app/models/taxonomy.py``
for why the shared/tenant split is two tables rather than one nullable column).
It is versioned by effective date and carries its source and methodology, because
an emission number without a citation is not a measurement (BR-11).

``carbon_estimates`` freezes ``factor_value_snapshot`` — the factor exactly as it
was used. If a factor is later corrected, historical estimates stay explainable:
you can see which value produced which number.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import Base, TenantScopedMixin, TimestampMixin, UUIDPrimaryKeyMixin
from app.db.types import CarbonKg, EmissionFactorValue, ShortText
from app.models._enums import (
    CarbonEstimateType,
    EmissionActivityType,
    PeriodType,
    ProvenanceKind,
    ScopeType,
    pg_enum,
)

__all__ = ["CarbonEstimate", "EmissionFactor", "EnvironmentalMetric"]


class EmissionFactor(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """A published emission factor with a citation, a version and effective dates."""

    __tablename__ = "emission_factors"
    __table_args__ = (
        UniqueConstraint("factor_code", "effective_from", name="uq_emission_factors_code_from"),
        Index("ix_emission_factors_activity", "activity_type"),
        Index("ix_emission_factors_active", "is_active"),
        CheckConstraint("factor_value >= 0", name="ck_emission_factors_value"),
    )

    factor_code: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    activity_type: Mapped[EmissionActivityType] = mapped_column(
        pg_enum(EmissionActivityType, "emission_activity_type"),
        nullable=False,
    )
    activity_unit: Mapped[str] = mapped_column(Text, nullable=False)
    factor_value: Mapped[EmissionFactorValue] = mapped_column(nullable=False)
    result_unit: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="KG_CO2E, KG_CO2E_PER_KG, KG_CO2E_PER_LITER or KG_CO2E_PER_KWH.",
    )
    source: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc='e.g. "IPCC 2006 Guidelines, Vol 5". Required, never optional.',
    )
    source_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    geography: Mapped[str] = mapped_column(Text, nullable=False, server_default="GLOBAL")
    methodology: Mapped[str | None] = mapped_column(Text, nullable=True)
    effective_from: Mapped[dt.date] = mapped_column(Date, nullable=False)
    effective_to: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    superseded_by_id: Mapped[UUID | None] = mapped_column(nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class CarbonEstimate(Base, TenantScopedMixin, TimestampMixin):
    """One carbon calculation, with the factor snapshot it used. Append-only."""

    __tablename__ = "carbon_estimates"
    __table_args__ = (
        Index(
            "ix_carbon_estimates_subject",
            "tenant_id",
            "subject_type",
            "subject_id",
            text("period_start DESC"),
        ),
        CheckConstraint("activity_quantity >= 0", name="ck_carbon_estimates_quantity"),
        CheckConstraint("emitted_kgco2e >= 0", name="ck_carbon_estimates_emitted"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    estimate_type: Mapped[CarbonEstimateType] = mapped_column(
        pg_enum(CarbonEstimateType, "carbon_estimate_type"),
        nullable=False,
    )
    subject_type: Mapped[ScopeType] = mapped_column(
        pg_enum(ScopeType, "scope_type"),
        nullable=False,
    )
    subject_id: Mapped[UUID | None] = mapped_column(nullable=True)
    period_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    activity_quantity: Mapped[Decimal] = mapped_column(Numeric(16, 4), nullable=False)
    activity_unit: Mapped[str] = mapped_column(Text, nullable=False)
    emission_factor_id: Mapped[UUID] = mapped_column(
        ForeignKey("emission_factors.id", ondelete="RESTRICT"),
        nullable=False,
    )
    factor_value_snapshot: Mapped[EmissionFactorValue] = mapped_column(
        nullable=False,
        doc="The factor exactly as used, frozen at calculation time.",
    )
    emitted_kgco2e: Mapped[CarbonKg] = mapped_column(nullable=False)
    avoided_kgco2e: Mapped[CarbonKg | None] = mapped_column(nullable=True)
    net_kgco2e: Mapped[CarbonKg] = mapped_column(nullable=False)
    calculation_method: Mapped[str] = mapped_column(Text, nullable=False)
    assumptions: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    provenance: Mapped[ProvenanceKind] = mapped_column(
        pg_enum(ProvenanceKind, "provenance_kind"),
        nullable=False,
        server_default=ProvenanceKind.ESTIMATED.value,
    )
    calculated_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class EnvironmentalMetric(Base, TenantScopedMixin, TimestampMixin):
    """
    A period rollup of one metric.

    ``computation_definition_version`` is what stops a reader from comparing two
    numbers computed under different definitions — for example before and after
    the tenant changes what counts as "diverted".
    """

    __tablename__ = "environmental_metrics"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "period_type",
            "period_start",
            "scope_type",
            "scope_id",
            "metric_code",
            name="uq_environmental_metrics",
        ),
        Index("ix_environmental_metrics_scope", "tenant_id", "scope_type", "scope_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    period_type: Mapped[PeriodType] = mapped_column(
        pg_enum(PeriodType, "period_type"),
        nullable=False,
    )
    period_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    period_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    scope_type: Mapped[ScopeType] = mapped_column(
        pg_enum(ScopeType, "scope_type"),
        nullable=False,
    )
    scope_id: Mapped[UUID | None] = mapped_column(nullable=True)
    metric_code: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="References the metric definition registry (analytics module).",
    )
    metric_value: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    unit: Mapped[str] = mapped_column(Text, nullable=False)
    provenance: Mapped[ProvenanceKind] = mapped_column(
        pg_enum(ProvenanceKind, "provenance_kind"),
        nullable=False,
    )
    computation_definition_version: Mapped[str] = mapped_column(Text, nullable=False)
    is_partial_period: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    computed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    inputs: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="The aggregates the value was computed from, for auditability.",
    )
