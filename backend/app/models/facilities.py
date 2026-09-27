"""
Facilities and their capabilities (``erd.md`` §7.1-7.4).

``facility_capabilities`` is what makes BR-10 enforceable: a waste load may only
be sent to a facility that has declared it can accept that category. The check
is a database lookup, not a convention, so a new integration cannot bypass it by
forgetting a rule.
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
    ForeignKey,
    Index,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    AuditActorMixin,
    Base,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    VersionMixin,
)
from app.db.types import Code, Latitude, Longitude, ShortText, UnitPrice, WeightKg
from app.models._enums import FacilityCategory, FacilityStatus, OperatingEntity, pg_enum

__all__ = [
    "Facility",
    "FacilityCapability",
    "FacilityCapacityUtilization",
    "FacilityType",
]


class FacilityType(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A class of facility. Seeded per tenant from the platform baseline."""

    __tablename__ = "facility_types"
    __table_args__ = (UniqueConstraint("tenant_id", "code", name="uq_facility_types_tenant_code"),)

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[FacilityCategory] = mapped_column(
        pg_enum(FacilityCategory, "facility_category"),
        nullable=False,
        server_default=FacilityCategory.TRANSFER_STATION.value,
    )


class Facility(
    Base,
    UUIDPrimaryKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    SoftDeleteMixin,
    VersionMixin,
    AuditActorMixin,
):
    """A site that receives, transfers or processes waste."""

    __tablename__ = "facilities"
    __table_args__ = (
        UniqueConstraint("tenant_id", "facility_code", name="uq_facilities_tenant_code"),
        Index("ix_facilities_tenant_status", "tenant_id", "status"),
        Index("ix_facilities_tenant_type", "tenant_id", "facility_type_id"),
        CheckConstraint("latitude BETWEEN -90 AND 90", name="ck_facilities_latitude"),
        CheckConstraint("longitude BETWEEN -180 AND 180", name="ck_facilities_longitude"),
        CheckConstraint(
            "daily_capacity_kg IS NULL OR daily_capacity_kg >= 0",
            name="ck_facilities_capacity",
        ),
    )

    facility_code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    facility_type_id: Mapped[UUID] = mapped_column(
        ForeignKey("facility_types.id", ondelete="RESTRICT"),
        nullable=False,
    )
    operating_entity: Mapped[OperatingEntity] = mapped_column(
        pg_enum(OperatingEntity, "operating_entity"),
        nullable=False,
        server_default=OperatingEntity.TENANT.value,
    )
    address_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("addresses.id", ondelete="SET NULL"),
        nullable=True,
    )
    latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    status: Mapped[FacilityStatus] = mapped_column(
        pg_enum(FacilityStatus, "facility_status"),
        nullable=False,
        server_default=FacilityStatus.OPERATIONAL.value,
    )
    daily_capacity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    daily_capacity_m3: Mapped[Decimal | None] = mapped_column(Numeric(14, 3), nullable=True)
    current_utilization_kg: Mapped[WeightKg | None] = mapped_column(
        nullable=True,
        doc="Derived; refreshed when a load is received.",
    )
    operating_hours: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc='e.g. {"mon": {"open": "06:00", "close": "20:00"}, ...}',
    )
    contact_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    contact_phone: Mapped[str | None] = mapped_column(Text, nullable=True)
    contact_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    permit_number: Mapped[str | None] = mapped_column(Text, nullable=True)
    permit_expiry: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    weighbridge_available: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="false"
    )
    acceptance_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class FacilityCapability(Base, TenantScopedMixin, TimestampMixin):
    """Which waste a facility accepts, at what rate and cost."""

    __tablename__ = "facility_capabilities"
    __table_args__ = (
        UniqueConstraint(
            "facility_id",
            "waste_category_id",
            "waste_material_id",
            name="uq_facility_capabilities",
        ),
        Index("ix_facility_capabilities_category", "waste_category_id"),
        CheckConstraint(
            "max_daily_kg IS NULL OR max_daily_kg >= 0",
            name="ck_facility_capabilities_max",
        ),
        CheckConstraint(
            "processing_cost_per_kg IS NULL OR processing_cost_per_kg >= 0",
            name="ck_facility_capabilities_cost",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    waste_material_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_materials.id", ondelete="SET NULL"),
        nullable=True,
    )
    max_daily_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    processing_cost_per_kg: Mapped[UnitPrice | None] = mapped_column(nullable=True)
    is_primary_route: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")


class FacilityCapacityUtilization(Base, TenantScopedMixin):
    """Daily rollup of what a facility received, processed and rejected."""

    __tablename__ = "facility_capacity_utilization"
    __table_args__ = (
        UniqueConstraint("facility_id", "date", name="uq_facility_capacity_utilization"),
        CheckConstraint(
            "utilization_pct IS NULL OR utilization_pct BETWEEN 0 AND 1000",
            name="ck_facility_capacity_utilization_pct",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="CASCADE"),
        nullable=False,
    )
    date: Mapped[dt.date] = mapped_column(Date, nullable=False)
    received_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    processed_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    capacity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    utilization_pct: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    rejected_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
