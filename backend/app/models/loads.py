"""
Waste loads, chain of custody and processing outcomes (``erd.md`` §7.5–7.8).

This is the traceability spine. A load starts life when a collection produces
waste, travels to a facility, and ends in one of four outcomes: recovered,
composted, treated or disposed. ``chain_of_custody`` is an append-only array of
handoffs, so "where did this waste go?" is answerable by replaying the load
rather than by inference.

The four outcome tables are deliberately separate rather than one polymorphic
table: each carries genuinely distinct attributes and meaningful CHECK
constraints, and a single table with half-null columns cannot enforce either.
``v_processing_outcomes`` (a database view created by the migration) unifies
them for analytics.
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    VersionMixin,
)
from app.db.types import Code, Percentage, VolumeCubicMetres, WeightKg
from app.models._enums import (
    CompositionSource,
    ContaminationLevel as ContaminationEnum,
    ProvenanceKind,
    DisposalType,
    LoadOriginType,
    LoadStatus,
    RecoveryType,
    TreatmentType,
    pg_enum,
)

__all__ = [
    "CompostingEvent",
    "DisposalEvent",
    "RecoveryEvent",
    "TreatmentEvent",
    "WasteLoad",
    "WasteLoadItem",
    "WasteTransfer",
]


class WasteLoad(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, VersionMixin):
    """A quantity of waste moving through the system, with its custody trail."""

    __tablename__ = "waste_loads"
    __table_args__ = (
        UniqueConstraint("tenant_id", "load_code", name="uq_waste_loads_code"),
        Index("ix_waste_loads_tenant_status", "tenant_id", "status"),
        Index("ix_waste_loads_origin_task", "origin_task_id"),
        Index("ix_waste_loads_destination", "destination_facility_id"),
        CheckConstraint(
            "measured_weight_kg IS NULL OR measured_weight_kg >= 0",
            name="ck_waste_loads_measured",
        ),
        CheckConstraint(
            "declared_weight_kg IS NULL OR declared_weight_kg >= 0",
            name="ck_waste_loads_declared",
        ),
    )

    load_code: Mapped[Code] = mapped_column(nullable=False)
    origin_type: Mapped[LoadOriginType] = mapped_column(
        pg_enum(LoadOriginType, "load_origin_type"),
        nullable=False,
        server_default=LoadOriginType.COLLECTION.value,
    )
    origin_collection_event_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_events.id", ondelete="SET NULL"),
        nullable=True,
    )
    origin_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_tasks.id", ondelete="SET NULL"),
        nullable=True,
    )
    origin_zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
    )
    origin_facility_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("facilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    vehicle_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vehicles.id", ondelete="SET NULL"),
        nullable=True,
    )
    driver_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("drivers.id", ondelete="SET NULL"),
        nullable=True,
    )
    departed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    arrived_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    declared_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    measured_weight_kg: Mapped[WeightKg | None] = mapped_column(
        nullable=True,
        doc="From a weighbridge; authoritative when present.",
    )
    volume_m3: Mapped[VolumeCubicMetres | None] = mapped_column(nullable=True)
    weighbridge_ticket_number: Mapped[str | None] = mapped_column(Text, nullable=True)
    destination_facility_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("facilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    status: Mapped[LoadStatus] = mapped_column(
        pg_enum(LoadStatus, "load_status"),
        nullable=False,
        server_default=LoadStatus.FORMING.value,
    )
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    contamination_level: Mapped[ContaminationEnum | None] = mapped_column(
        pg_enum(ContaminationEnum, "contamination_level"),
        nullable=True,
    )
    chain_of_custody: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'[]'::jsonb"),
        doc="Append-only array of handoffs: actor, facility, timestamp, weight.",
    )

    items: Mapped[list[WasteLoadItem]] = relationship(
        "WasteLoadItem",
        back_populates="load",
        cascade="all, delete-orphan",
    )



class WasteLoadItem(Base, TenantScopedMixin, TimestampMixin):
    """One line of a load's composition."""

    __tablename__ = "waste_load_items"
    __table_args__ = (
        Index("ix_waste_load_items_load", "waste_load_id"),
        CheckConstraint("weight_kg IS NULL OR weight_kg >= 0", name="ck_waste_load_items_weight"),
        CheckConstraint(
            "percentage IS NULL OR percentage BETWEEN 0 AND 100",
            name="ck_waste_load_items_percentage",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
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
    weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    source: Mapped[CompositionSource] = mapped_column(
        pg_enum(CompositionSource, "composition_source"),
        nullable=False,
        server_default=CompositionSource.ESTIMATED_VISUAL.value,
    )
    classification_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
        doc="Set when the composition came from an image classification.",
    )

    load: Mapped[WasteLoad] = relationship(back_populates="items", foreign_keys=[waste_load_id])


class WasteTransfer(Base, TenantScopedMixin, TimestampMixin):
    """A custody handoff between facilities, with both parties recorded."""

    __tablename__ = "waste_transfers"
    __table_args__ = (
        Index("ix_waste_transfers_load", "waste_load_id"),
        CheckConstraint("weight_kg IS NULL OR weight_kg >= 0", name="ck_waste_transfers_weight"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
        nullable=False,
    )
    from_facility_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("facilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    to_facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="RESTRICT"),
        nullable=False,
    )
    transferred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    vehicle_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vehicles.id", ondelete="SET NULL"),
        nullable=True,
    )
    handover_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    receiving_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    receiving_confirmed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    document_file_id: Mapped[UUID | None] = mapped_column(nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class _OutcomeBase:
    """Columns shared by the four processing-outcome tables."""

    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    input_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    output_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    recovery_rate: Mapped[Percentage | None] = mapped_column(nullable=True)
    process_method: Mapped[str | None] = mapped_column(Text, nullable=True)
    batch_reference: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    provenance: Mapped[ProvenanceKind] = mapped_column(
        pg_enum(ProvenanceKind, "provenance_kind"),
        nullable=False,
        server_default=ProvenanceKind.MEASURED.value,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class RecoveryEvent(Base, TenantScopedMixin, TimestampMixin, _OutcomeBase):
    """Material or energy recovered from a load."""

    __tablename__ = "recovery_events"
    __table_args__ = (
        Index("ix_recovery_events_load", "waste_load_id"),
        CheckConstraint(
            "revenue IS NULL OR revenue >= 0",
            name="ck_recovery_events_revenue",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
        nullable=False,
    )
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="RESTRICT"),
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
    recovery_type: Mapped[RecoveryType] = mapped_column(
        pg_enum(RecoveryType, "recovery_type"),
        nullable=False,
    )
    material_grade: Mapped[str | None] = mapped_column(Text, nullable=True)
    revenue: Mapped[Decimal | None] = mapped_column(Numeric(14, 2), nullable=True)
    buyer_name: Mapped[str | None] = mapped_column(Text, nullable=True)


class CompostingEvent(Base, TenantScopedMixin, TimestampMixin, _OutcomeBase):
    """Organic waste turned into compost."""

    __tablename__ = "composting_events"
    __table_args__ = (Index("ix_composting_events_load", "waste_load_id"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
        nullable=False,
    )
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="RESTRICT"),
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
    compost_grade: Mapped[str | None] = mapped_column(Text, nullable=True)
    curing_days: Mapped[int | None] = mapped_column(Integer, nullable=True)
    moisture_pct: Mapped[Percentage | None] = mapped_column(nullable=True)


class TreatmentEvent(Base, TenantScopedMixin, TimestampMixin, _OutcomeBase):
    """Waste treated before disposal, possibly with energy recovery."""

    __tablename__ = "treatment_events"
    __table_args__ = (Index("ix_treatment_events_load", "waste_load_id"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
        nullable=False,
    )
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="RESTRICT"),
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
    treatment_type: Mapped[TreatmentType] = mapped_column(
        pg_enum(TreatmentType, "treatment_type"),
        nullable=False,
    )
    energy_recovered_kwh: Mapped[Decimal | None] = mapped_column(Numeric(14, 3), nullable=True)
    residue_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)


class DisposalEvent(Base, TenantScopedMixin, TimestampMixin, _OutcomeBase):
    """Waste disposed of without recovery — the last resort, recorded honestly."""

    __tablename__ = "disposal_events"
    __table_args__ = (Index("ix_disposal_events_load", "waste_load_id"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_load_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="CASCADE"),
        nullable=False,
    )
    facility_id: Mapped[UUID] = mapped_column(
        ForeignKey("facilities.id", ondelete="RESTRICT"),
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
    disposal_type: Mapped[DisposalType] = mapped_column(
        pg_enum(DisposalType, "disposal_type"),
        nullable=False,
    )
    landfill_cell: Mapped[str | None] = mapped_column(Text, nullable=True)
    residue_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)

