"""
Bins, bin sensors, telemetry and alerts (``erd.md`` §5).

``bin_types`` is tenant-scoped rather than carrying a nullable ``tenant_id``:
the platform baseline is a template applied when a tenant is provisioned, and
each tenant may add its own types. That keeps one rule true everywhere —
tenant-owned ⇒ row-level security — and avoids the "shared rows under RLS"
problem described in ``app/models/taxonomy.py``.

Telemetry is append-only. ``bin_telemetry`` carries the deduplication key
``(bin_id, sensor_id, recorded_at)`` that makes ingestion idempotent under
replay (BR-03), and ``bin_telemetry_latest`` is the read model that keeps the
operations dashboard O(bins) instead of O(telemetry rows).
"""

from __future__ import annotations

from datetime import date, datetime
from decimal import Decimal
from typing import Any
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    BigInteger,
    Boolean,
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    AuditActorMixin,
    Base,
    SoftDeleteMixin,
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
    AlertStatus,
    BinAlertType,
    BinStatus,
    SensorStatus,
    SensorType,
    Severity,
    TelemetrySource,
    pg_enum,
)

__all__ = [
    "Bin",
    "BinAlert",
    "BinMaintenance",
    "BinSensor",
    "BinTelemetry",
    "BinTelemetryLatest",
    "BinType",
    "IngestionBatch",
]


class BinType(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A physical bin design. Seeded per tenant from the platform baseline."""

    __tablename__ = "bin_types"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_bin_types_tenant_code"),
        CheckConstraint("capacity_liters > 0", name="ck_bin_types_capacity"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    capacity_liters: Mapped[VolumeLiters] = mapped_column(nullable=False)
    tare_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    material: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="PLASTIC",
        doc="PLASTIC, STEEL, CONCRETE or COMPOSITE.",
    )
    has_sensor_mount: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    has_compactor: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    has_weighing: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    dimensions_mm: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")


class Bin(
    Base,
    UUIDPrimaryKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    SoftDeleteMixin,
    VersionMixin,
    AuditActorMixin,
):
    """
    A physical bin.

    ``capacity_liters`` is denormalised from the type on purpose: if the type's
    capacity is later corrected, historical bins must keep the capacity they
    actually had, or every past fill-level reading becomes meaningless.
    """

    __tablename__ = "bins"
    __table_args__ = (
        UniqueConstraint("tenant_id", "bin_code", name="uq_bins_tenant_code"),
        Index("ix_bins_tenant_status", "tenant_id", "status"),
        Index("ix_bins_tenant_zone", "tenant_id", "zone_id"),
        Index("ix_bins_tenant_location", "tenant_id", "latitude", "longitude"),
        Index("ix_bins_last_telemetry", "last_telemetry_at"),
        CheckConstraint("capacity_liters > 0", name="ck_bins_capacity"),
        CheckConstraint("latitude BETWEEN -90 AND 90", name="ck_bins_latitude"),
        CheckConstraint("longitude BETWEEN -180 AND 180", name="ck_bins_longitude"),
    )

    bin_code: Mapped[Code] = mapped_column(nullable=False)
    bin_type_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bin_types.id", ondelete="SET NULL"),
        nullable=True,
    )
    zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
    )
    service_area_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("service_areas.id", ondelete="SET NULL"),
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
    capacity_liters: Mapped[VolumeLiters] = mapped_column(nullable=False)
    status: Mapped[BinStatus] = mapped_column(
        pg_enum(BinStatus, "bin_status"),
        nullable=False,
        server_default=BinStatus.ACTIVE.value,
    )
    latitude: Mapped[Latitude] = mapped_column(nullable=False)
    longitude: Mapped[Longitude] = mapped_column(nullable=False)
    installation_date: Mapped[date | None] = mapped_column(Date, nullable=True)
    last_collection_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_telemetry_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_sensorized: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_public_facing: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    access_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    qr_code: Mapped[str | None] = mapped_column(String(64), nullable=True)
    photo_file_id: Mapped[UUID | None] = mapped_column(nullable=True)

    sensors: Mapped[list[BinSensor]] = relationship(back_populates="bin")


class BinSensor(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """
    A sensor mounted on a bin.

    The partial unique index enforces one *active* sensor per bin per type: a
    bin cannot carry two live fill-level sensors, which would make every
    subsequent reading ambiguous.
    """

    __tablename__ = "bin_sensors"
    __table_args__ = (
        UniqueConstraint("tenant_id", "device_id", name="uq_bin_sensors_tenant_device"),
        # A plain composite index: an expression element here would render as
        # bare SQL in the migration, and ``removed_at NULL`` is not a valid index
        # expression.
        Index("ix_bin_sensors_bin", "bin_id", "sensor_type"),
        Index(
            "uq_bin_sensors_active_per_type",
            "bin_id",
            "sensor_type",
            unique=True,
            postgresql_where=text("removed_at IS NULL"),
        ),
    )

    bin_id: Mapped[UUID] = mapped_column(
        ForeignKey("bins.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[str] = mapped_column(Text, nullable=False)
    sensor_type: Mapped[SensorType] = mapped_column(
        pg_enum(SensorType, "sensor_type"),
        nullable=False,
        server_default=SensorType.FILL_LEVEL.value,
    )
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    model: Mapped[str | None] = mapped_column(Text, nullable=True)
    firmware_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    installed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    removed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    connectivity_status: Mapped[SensorStatus] = mapped_column(
        pg_enum(SensorStatus, "sensor_status"),
        nullable=False,
        server_default=SensorStatus.ONLINE.value,
    )
    calibration_offset: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    calibration_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    battery_reported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")

    bin: Mapped[Bin] = relationship(back_populates="sensors")


class IngestionBatch(Base, TenantScopedMixin, TimestampMixin):
    """
    One submission from a device gateway.

    This is what makes "why did my device's data not appear?" answerable: the
    batch records how many readings were accepted, rejected and recognised as
    duplicates, plus a bounded error summary.
    """

    __tablename__ = "ingestion_batches"
    __table_args__ = (
        Index("ix_ingestion_batches_tenant_received", "tenant_id", text("received_at DESC")),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    device_gateway_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    reading_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    accepted_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    rejected_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    duplicate_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    error_summary: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    source: Mapped[TelemetrySource] = mapped_column(
        pg_enum(TelemetrySource, "telemetry_source"),
        nullable=False,
        server_default=TelemetrySource.SENSOR.value,
    )


class BinTelemetry(Base, TenantScopedMixin):
    """
    One reading. Append-only: no ``updated_at``, no soft delete.

    The unique constraint is the deduplication key, so a replayed batch resolves
    to ``ON CONFLICT DO NOTHING`` rather than to a duplicate row (BR-03).
    """

    __tablename__ = "bin_telemetry"
    __table_args__ = (
        UniqueConstraint("bin_id", "sensor_id", "recorded_at", name="uq_bin_telemetry_dedup"),
        Index("ix_bin_telemetry_latest", "tenant_id", "bin_id", text("recorded_at DESC")),
        Index("ix_bin_telemetry_time", "recorded_at"),
        Index("ix_bin_telemetry_batch", "ingestion_batch_id"),
        CheckConstraint(
            "fill_percentage IS NULL OR fill_percentage BETWEEN 0 AND 100",
            name="ck_bin_telemetry_fill",
        ),
        CheckConstraint(
            "weight_kg IS NULL OR weight_kg >= 0",
            name="ck_bin_telemetry_weight",
        ),
        CheckConstraint(
            "battery_percentage IS NULL OR battery_percentage BETWEEN 0 AND 100",
            name="ck_bin_telemetry_battery",
        ),
        CheckConstraint(
            "temperature_c IS NULL OR temperature_c BETWEEN -60 AND 200",
            name="ck_bin_telemetry_temperature",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger,
        primary_key=True,
        autoincrement=True,
        doc="High volume and never updated; a 64-bit sequence is the right key.",
    )
    bin_id: Mapped[UUID] = mapped_column(
        ForeignKey("bins.id", ondelete="CASCADE"),
        nullable=False,
    )
    sensor_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bin_sensors.id", ondelete="SET NULL"),
        nullable=True,
    )
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    received_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    fill_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    volume_liters: Mapped[VolumeLiters | None] = mapped_column(nullable=True)
    temperature_c: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    humidity_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    battery_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    signal_strength_dbm: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    sensor_status: Mapped[SensorStatus | None] = mapped_column(
        pg_enum(SensorStatus, "sensor_status"),
        nullable=True,
    )
    gateway_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    source: Mapped[TelemetrySource] = mapped_column(
        pg_enum(TelemetrySource, "telemetry_source"),
        nullable=False,
        server_default=TelemetrySource.SENSOR.value,
    )
    quality_flags: Mapped[list[str] | None] = mapped_column(
        ARRAY(Text),
        nullable=True,
        doc="e.g. {frozen_value}, {out_of_range_rejected_partial}.",
    )
    ingestion_batch_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ingestion_batches.id", ondelete="SET NULL"),
        nullable=True,
    )
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Bounded at ingestion; retained for fault diagnosis only.",
    )


class BinTelemetryLatest(Base, TenantScopedMixin):
    """
    The current state of each bin, upserted on ingestion.

    Rebuildable from ``bin_telemetry``, so a corruption is recoverable rather
    than permanent.
    """

    __tablename__ = "bin_telemetry_latest"
    __table_args__ = (
        Index("ix_bin_telemetry_latest_overflow", "tenant_id", "is_overflow_risk"),
    )

    bin_id: Mapped[UUID] = mapped_column(
        ForeignKey("bins.id", ondelete="CASCADE"),
        primary_key=True,
    )
    fill_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    temperature_c: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    battery_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    signal_strength_dbm: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    sensor_status: Mapped[SensorStatus | None] = mapped_column(
        pg_enum(SensorStatus, "sensor_status"),
        nullable=True,
    )
    recorded_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_overflow_risk: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class BinAlert(Base, TenantScopedMixin, TimestampMixin):
    """
    A threshold or rule breach raised against a bin.

    ``dedup_key`` plus the partial unique index on open alerts is what prevents
    an alert storm: a sensor oscillating around a threshold raises one alert,
    not one per reading.
    """

    __tablename__ = "bin_alerts"
    __table_args__ = (
        Index(
            "uq_bin_alerts_open_dedup",
            "tenant_id",
            "dedup_key",
            unique=True,
            postgresql_where=text("status = 'OPEN'"),
        ),
        Index("ix_bin_alerts_tenant_status", "tenant_id", "status"),
        Index("ix_bin_alerts_bin", "bin_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    bin_id: Mapped[UUID] = mapped_column(
        ForeignKey("bins.id", ondelete="CASCADE"),
        nullable=False,
    )
    alert_type: Mapped[BinAlertType] = mapped_column(
        pg_enum(BinAlertType, "bin_alert_type"),
        nullable=False,
    )
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        server_default=Severity.MEDIUM.value,
    )
    status: Mapped[AlertStatus] = mapped_column(
        pg_enum(AlertStatus, "alert_status"),
        nullable=False,
        server_default=AlertStatus.OPEN.value,
    )
    triggered_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    trigger_value: Mapped[Decimal | None] = mapped_column(Numeric(12, 4), nullable=True)
    threshold_value: Mapped[Decimal | None] = mapped_column(Numeric(12, 4), nullable=True)
    rule_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    acknowledged_by: Mapped[UUID | None] = mapped_column(nullable=True)
    acknowledged_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    dedup_key: Mapped[str] = mapped_column(Text, nullable=False)


class BinMaintenance(Base, TenantScopedMixin, TimestampMixin):
    """A maintenance record for a bin (cleaning, repair, calibration, inspection)."""

    __tablename__ = "bin_maintenance"
    __table_args__ = (
        Index("ix_bin_maintenance_bin", "bin_id"),
        Index("ix_bin_maintenance_tenant_status", "tenant_id", "status"),
        CheckConstraint("cost IS NULL OR cost >= 0", name="ck_bin_maintenance_cost"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    bin_id: Mapped[UUID] = mapped_column(
        ForeignKey("bins.id", ondelete="CASCADE"),
        nullable=False,
    )
    maintenance_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="CLEANING, REPAIR, CALIBRATION, SENSOR_REPLACEMENT or INSPECTION.",
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="SCHEDULED")
    reported_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    scheduled_for: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    performed_by: Mapped[UUID | None] = mapped_column(nullable=True)
    cost: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    parts_replaced: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)

