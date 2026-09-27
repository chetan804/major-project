"""
Collection operations: requests, schedules, tasks and events (``erd.md`` §6.1-6.4).

The task lifecycle is the operational spine of the product:

    PLANNED → ASSIGNED → DISPATCHED → IN_PROGRESS → COMPLETED

with PARTIALLY_COMPLETED, FAILED, SKIPPED, CANCELLED and OVERDUE as the
exception states. Illegal transitions are rejected in the service layer with
``409 INVALID_STATE_TRANSITION``; the database encodes the one rule that must
hold unconditionally (BR-07): a task may not be FAILED without a reason.

``collection_events`` is the fact table — what actually happened at the stop,
including the quantity and its certification source. ``client_uuid`` is what
makes offline driver synchronisation idempotent: the same event submitted twice
is stored once.
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    VersionMixin,
)
from app.db.types import (
    Code,
    Latitude,
    Longitude,
    Percentage,
    ShortText,
    VolumeLiters,
    WeightKg,
)
from app.models._enums import (
    CertificationSource,
    CollectionEventType,
    CollectionRequestSource,
    CollectionRequestStatus,
    CollectionTaskStatus,
    ContaminationLevel,
    PriorityLevel,
    SyncState,
    TaskFailureReason,
    pg_enum,
)

__all__ = [
    "CollectionEvent",
    "CollectionRequest",
    "CollectionSchedule",
    "CollectionTask",
]


class CollectionRequest(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A demand for collection, raised by a human, a sensor, a schedule or the AI."""

    __tablename__ = "collection_requests"
    __table_args__ = (
        UniqueConstraint("tenant_id", "request_code", name="uq_collection_requests_code"),
        Index("ix_collection_requests_tenant_status", "tenant_id", "status"),
        CheckConstraint(
            "bin_id IS NOT NULL OR address_id IS NOT NULL OR zone_id IS NOT NULL",
            name="ck_collection_requests_target",
        ),
    )

    request_code: Mapped[Code] = mapped_column(nullable=False)
    bin_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bins.id", ondelete="SET NULL"),
        nullable=True,
    )
    zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
    )
    address_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("addresses.id", ondelete="SET NULL"),
        nullable=True,
    )
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    requested_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    source: Mapped[CollectionRequestSource] = mapped_column(
        pg_enum(CollectionRequestSource, "collection_request_source"),
        nullable=False,
        server_default=CollectionRequestSource.MANUAL.value,
    )
    priority: Mapped[PriorityLevel] = mapped_column(
        pg_enum(PriorityLevel, "priority_level"),
        nullable=False,
        server_default=PriorityLevel.NORMAL.value,
    )
    requested_for_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    status: Mapped[CollectionRequestStatus] = mapped_column(
        pg_enum(CollectionRequestStatus, "collection_request_status"),
        nullable=False,
        server_default=CollectionRequestStatus.PENDING.value,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    estimated_quantity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    # ``use_alter`` breaks the creation cycle with ``collection_tasks``: the
    # constraint is added by an ALTER TABLE after both tables exist, which is
    # what lets a single migration create both.
    fulfilled_by_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_tasks.id", ondelete="SET NULL", use_alter=True),
        nullable=True,
    )


class CollectionSchedule(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """
    A recurring service commitment.

    ``recurrence_rule`` is an RFC-5545 RRULE parsed by ``dateutil``; the
    scheduler materialises tasks forward and is idempotent on
    ``(schedule_id, scheduled_date)``.
    """

    __tablename__ = "collection_schedules"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_collection_schedules_code"),
        Index("ix_collection_schedules_area", "service_area_id"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    service_area_id: Mapped[UUID] = mapped_column(
        ForeignKey("service_areas.id", ondelete="RESTRICT"),
        nullable=False,
    )
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    recurrence_rule: Mapped[str] = mapped_column(Text, nullable=False)
    start_date: Mapped[date] = mapped_column(Date, nullable=False)
    end_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    service_window_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    service_window_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    is_active: Mapped[bool] = mapped_column(nullable=False, server_default=text("true"))
    last_generated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class CollectionTask(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, VersionMixin):
    """One unit of work: collect this bin, on this date, by this crew."""

    __tablename__ = "collection_tasks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "task_code", name="uq_collection_tasks_code"),
        Index("ix_collection_tasks_tenant_date_status", "tenant_id", "planned_date", "status"),
        Index("ix_collection_tasks_route", "route_id"),
        Index("ix_collection_tasks_driver_date", "assigned_driver_id", "planned_date"),
        Index("ix_collection_tasks_bin_date", "bin_id", "planned_date"),
        Index(
            "ix_collection_tasks_open",
            "tenant_id",
            "planned_date",
            postgresql_where=text(
                "status NOT IN ('COMPLETED', 'PARTIALLY_COMPLETED', 'CANCELLED', 'SKIPPED')"
            ),
        ),
        CheckConstraint(
            "status <> 'FAILED' OR failure_reason IS NOT NULL",
            name="ck_collection_tasks_failure_reason",
        ),
        CheckConstraint(
            "estimated_quantity_kg IS NULL OR estimated_quantity_kg >= 0",
            name="ck_collection_tasks_quantity",
        ),
    )

    task_code: Mapped[Code] = mapped_column(nullable=False)
    collection_request_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_requests.id", ondelete="SET NULL"),
        nullable=True,
    )
    schedule_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_schedules.id", ondelete="SET NULL"),
        nullable=True,
    )
    bin_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bins.id", ondelete="SET NULL"),
        nullable=True,
    )
    address_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("addresses.id", ondelete="SET NULL"),
        nullable=True,
    )
    zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
    )
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    route_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"),
        nullable=True,
    )
    # ``use_alter`` for the same reason: ``route_stops.collection_task_id``
    # points back here, so the pair cannot be created inline in one statement.
    route_stop_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("route_stops.id", ondelete="SET NULL", use_alter=True),
        nullable=True,
        doc="Set once the task has been sequenced onto a route.",
    )
    assigned_vehicle_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vehicles.id", ondelete="SET NULL"),
        nullable=True,
    )
    assigned_driver_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("drivers.id", ondelete="SET NULL"),
        nullable=True,
    )
    planned_date: Mapped[date] = mapped_column(Date, nullable=False)
    planned_window_start: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    planned_window_end: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    estimated_quantity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    status: Mapped[CollectionTaskStatus] = mapped_column(
        pg_enum(CollectionTaskStatus, "collection_task_status"),
        nullable=False,
        server_default=CollectionTaskStatus.PLANNED.value,
    )
    priority: Mapped[PriorityLevel] = mapped_column(
        pg_enum(PriorityLevel, "priority_level"),
        nullable=False,
        server_default=PriorityLevel.NORMAL.value,
    )
    dispatched_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    arrived_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    priority_score: Mapped[Decimal | None] = mapped_column(
        Numeric(8, 4),
        nullable=True,
        doc="From the explainable bin-intelligence scorer.",
    )
    priority_factors: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="The factor breakdown — the explanation behind ``priority_score``.",
    )
    failure_reason: Mapped[TaskFailureReason | None] = mapped_column(
        pg_enum(TaskFailureReason, "task_failure_reason"),
        nullable=True,
    )
    failure_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    rescheduled_from_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_tasks.id", ondelete="SET NULL"),
        nullable=True,
    )
    scheduled_date: Mapped[date | None] = mapped_column(
        Date,
        nullable=True,
        doc="Denormalised schedule occurrence date; the idempotency key of generation.",
    )


class CollectionEvent(Base, TenantScopedMixin, TimestampMixin):
    """What actually happened at a stop. A fact, never mutated."""

    __tablename__ = "collection_events"
    __table_args__ = (
        UniqueConstraint("tenant_id", "client_uuid", name="uq_collection_events_client_uuid"),
        Index("ix_collection_events_task", "task_id"),
        Index("ix_collection_events_tenant_occurred", "tenant_id", text("occurred_at DESC")),
        CheckConstraint(
            "quantity_kg IS NULL OR quantity_kg >= 0",
            name="ck_collection_events_quantity",
        ),
        CheckConstraint(
            "fill_level_at_collection IS NULL OR fill_level_at_collection BETWEEN 0 AND 100",
            name="ck_collection_events_fill",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    task_id: Mapped[UUID] = mapped_column(
        ForeignKey("collection_tasks.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_type: Mapped[CollectionEventType] = mapped_column(
        pg_enum(CollectionEventType, "collection_event_type"),
        nullable=False,
    )
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    quantity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    volume_liters: Mapped[VolumeLiters | None] = mapped_column(nullable=True)
    fill_level_at_collection: Mapped[Percentage | None] = mapped_column(nullable=True)
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
        doc="May differ from the planned category: contamination changes what the waste is.",
    )
    contamination_level: Mapped[ContaminationLevel] = mapped_column(
        pg_enum(ContaminationLevel, "contamination_level"),
        nullable=False,
        server_default=ContaminationLevel.NONE.value,
    )
    recorded_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    certification_source: Mapped[CertificationSource] = mapped_column(
        pg_enum(CertificationSource, "certification_source"),
        nullable=False,
        server_default=CertificationSource.MANUAL_ENTRY.value,
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    evidence_file_ids: Mapped[list[UUID] | None] = mapped_column(
        ARRAY(PGUUID(as_uuid=True)), nullable=True
    )
    sync_state: Mapped[SyncState] = mapped_column(
        pg_enum(SyncState, "sync_state"),
        nullable=False,
        server_default=SyncState.PENDING.value,
    )
    client_uuid: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        nullable=False,
        doc="Generated by the driver's device before it goes offline; the dedup key.",
    )
    device_synced_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
