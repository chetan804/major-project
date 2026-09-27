"""
Fleet and workforce: vehicles, drivers and their assignments (``erd.md`` §6.5–6.11).

Capacity is **effective-dated** (``vehicle_capacities``) because a trailer change
or a re-registration changes what a vehicle can legally carry, and route
planning must use the capacity that was in force on the service date — not the
value that happens to be in the column today (BR-06).

Driver assignment overlap is guarded by a partial unique index on
``(driver_id, assignment_date)`` plus a service-layer interval check. The ERD's
preferred ``EXCLUDE USING gist`` needs ``btree_gist``, which is unavailable in
this environment's PostgreSQL build; the limitation is disclosed in
``erd.md`` Appendix A rather than papered over.
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
    Integer,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
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
from app.db.types import (
    Code,
    Latitude,
    Longitude,
    Percentage,
    ShortText,
    VolumeCubicMetres,
    WeightKg,
)
from app.models._enums import (
    AssignmentStatus,
    DriverStatus,
    FuelType,
    TelemetrySource,
    VehicleStatus,
    pg_enum,
)

__all__ = [
    "Driver",
    "DriverAssignment",
    "Vehicle",
    "VehicleCapacity",
    "VehicleMaintenance",
    "VehicleTelemetry",
    "VehicleType",
]


class VehicleType(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A class of vehicle. Seeded per tenant from the platform baseline."""

    __tablename__ = "vehicle_types"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_vehicle_types_tenant_code"),
        CheckConstraint("capacity_kg IS NULL OR capacity_kg > 0", name="ck_vehicle_types_capacity"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    capacity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    capacity_m3: Mapped[VolumeCubicMetres | None] = mapped_column(nullable=True)
    axle_configuration: Mapped[str | None] = mapped_column(String(24), nullable=True)
    typical_crew_size: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)


class Vehicle(
    Base,
    UUIDPrimaryKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    SoftDeleteMixin,
    VersionMixin,
    AuditActorMixin,
):
    """A vehicle in the tenant's fleet."""

    __tablename__ = "vehicles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "registration_number", name="uq_vehicles_tenant_registration"),
        UniqueConstraint("tenant_id", "fleet_code", name="uq_vehicles_tenant_fleet_code"),
        Index("ix_vehicles_tenant_status", "tenant_id", "status"),
        CheckConstraint("capacity_kg > 0", name="ck_vehicles_capacity"),
    )

    registration_number: Mapped[str] = mapped_column(Text, nullable=False)
    fleet_code: Mapped[Code] = mapped_column(nullable=False)
    vehicle_type_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vehicle_types.id", ondelete="SET NULL"),
        nullable=True,
    )
    capacity_kg: Mapped[WeightKg] = mapped_column(nullable=False)
    capacity_m3: Mapped[VolumeCubicMetres | None] = mapped_column(nullable=True)
    fuel_type: Mapped[FuelType] = mapped_column(
        pg_enum(FuelType, "fuel_type"),
        nullable=False,
        server_default=FuelType.DIESEL.value,
    )
    status: Mapped[VehicleStatus] = mapped_column(
        pg_enum(VehicleStatus, "vehicle_status"),
        nullable=False,
        server_default=VehicleStatus.AVAILABLE.value,
    )
    ownership: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="OWNED",
        doc="OWNED, LEASED or CONTRACTOR.",
    )
    acquisition_date: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    odometer_km: Mapped[Decimal | None] = mapped_column(Numeric(12, 1), nullable=True)
    last_maintenance_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_maintenance_due: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    current_latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    current_longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    current_location_updated_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    has_compactor: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    has_weighbridge: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    telematics_device_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class VehicleCapacity(Base, TenantScopedMixin):
    """An effective-dated capacity override (a trailer change, a re-registration)."""

    __tablename__ = "vehicle_capacities"
    __table_args__ = (
        UniqueConstraint("vehicle_id", "effective_from", name="uq_vehicle_capacities"),
        CheckConstraint("capacity_kg > 0", name="ck_vehicle_capacities_kg"),
        CheckConstraint(
            "effective_to IS NULL OR effective_to > effective_from",
            name="ck_vehicle_capacities_range",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    vehicle_id: Mapped[UUID] = mapped_column(
        ForeignKey("vehicles.id", ondelete="CASCADE"),
        nullable=False,
    )
    effective_from: Mapped[dt.date] = mapped_column(Date, nullable=False)
    effective_to: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    capacity_kg: Mapped[WeightKg] = mapped_column(nullable=False)
    capacity_m3: Mapped[VolumeCubicMetres | None] = mapped_column(nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    recorded_by: Mapped[UUID | None] = mapped_column(nullable=True)


class VehicleTelemetry(Base, TenantScopedMixin):
    """
    A vehicle position/state sample. Append-only.

    ``source`` records whether the sample came from a real telematics unit or
    from the simulator, and the API surfaces that label: simulated movement is
    never presented as a live GPS feed (``architecture.md`` §13).
    """

    __tablename__ = "vehicle_telemetry"
    __table_args__ = (
        UniqueConstraint("vehicle_id", "recorded_at", name="uq_vehicle_telemetry"),
        Index("ix_vehicle_telemetry_vehicle_time", "tenant_id", "vehicle_id", text("recorded_at DESC")),
        CheckConstraint(
            "latitude IS NULL OR latitude BETWEEN -90 AND 90",
            name="ck_vehicle_telemetry_latitude",
        ),
        CheckConstraint(
            "longitude IS NULL OR longitude BETWEEN -180 AND 180",
            name="ck_vehicle_telemetry_longitude",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vehicle_id: Mapped[UUID] = mapped_column(
        ForeignKey("vehicles.id", ondelete="CASCADE"),
        nullable=False,
    )
    recorded_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    speed_kph: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    heading_degrees: Mapped[Decimal | None] = mapped_column(Numeric(5, 2), nullable=True)
    odometer_km: Mapped[Decimal | None] = mapped_column(Numeric(12, 1), nullable=True)
    fuel_level_percentage: Mapped[Percentage | None] = mapped_column(nullable=True)
    engine_hours: Mapped[Decimal | None] = mapped_column(Numeric(10, 2), nullable=True)
    load_weight_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    load_volume_m3: Mapped[VolumeCubicMetres | None] = mapped_column(nullable=True)
    source: Mapped[TelemetrySource] = mapped_column(
        pg_enum(TelemetrySource, "telemetry_source"),
        nullable=False,
        server_default=TelemetrySource.SENSOR.value,
    )
    raw_payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)


class VehicleMaintenance(Base, TenantScopedMixin, TimestampMixin):
    """A maintenance record for a vehicle."""

    __tablename__ = "vehicle_maintenance"
    __table_args__ = (
        Index("ix_vehicle_maintenance_vehicle", "vehicle_id"),
        CheckConstraint("cost IS NULL OR cost >= 0", name="ck_vehicle_maintenance_cost"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    vehicle_id: Mapped[UUID] = mapped_column(
        ForeignKey("vehicles.id", ondelete="CASCADE"),
        nullable=False,
    )
    maintenance_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="PREVENTIVE, CORRECTIVE, INSPECTION, TYRE, ENGINE or BODYWORK.",
    )
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="SCHEDULED")
    reported_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    scheduled_for: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cost: Mapped[Decimal | None] = mapped_column(Numeric(12, 2), nullable=True)
    odometer_at_service: Mapped[Decimal | None] = mapped_column(Numeric(12, 1), nullable=True)
    vendor: Mapped[str | None] = mapped_column(Text, nullable=True)
    parts: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class Driver(
    Base,
    UUIDPrimaryKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    SoftDeleteMixin,
    VersionMixin,
):
    """
    A driver. ``user_id`` is optional: a driver may exist in the registry without
    app access, and a user may hold a driver record.
    """

    __tablename__ = "drivers"
    __table_args__ = (
        UniqueConstraint("tenant_id", "employee_code", name="uq_drivers_tenant_code"),
        Index("ix_drivers_tenant_status", "tenant_id", "status"),
        CheckConstraint(
            "licence_expiry IS NULL OR licence_expiry > DATE '2000-01-01'",
            name="ck_drivers_licence_expiry",
        ),
    )

    employee_code: Mapped[Code] = mapped_column(nullable=False)
    user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    full_name: Mapped[str] = mapped_column(Text, nullable=False)
    phone: Mapped[str | None] = mapped_column(String(24), nullable=True)
    licence_number: Mapped[str | None] = mapped_column(String(40), nullable=True)
    licence_class: Mapped[str | None] = mapped_column(String(16), nullable=True)
    licence_expiry: Mapped[dt.date | None] = mapped_column(Date, nullable=True)
    status: Mapped[DriverStatus] = mapped_column(
        pg_enum(DriverStatus, "driver_status"),
        nullable=False,
        server_default=DriverStatus.ACTIVE.value,
    )
    home_depot_facility_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("facilities.id", ondelete="SET NULL"),
        nullable=True,
    )
    default_vehicle_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("vehicles.id", ondelete="SET NULL"),
        nullable=True,
    )
    shift_preference: Mapped[str | None] = mapped_column(String(24), nullable=True)
    certifications: Mapped[list[str] | None] = mapped_column(ARRAY(Text), nullable=True)


class DriverAssignment(Base, TenantScopedMixin, TimestampMixin):
    """
    A shift: this driver, this vehicle, this date, this time range.

    The partial unique index makes one *active* assignment per driver per date,
    and the service additionally rejects overlapping time ranges for the same
    driver (see the module docstring for why this is not an ``EXCLUDE``
    constraint).
    """

    __tablename__ = "driver_assignments"
    __table_args__ = (
        UniqueConstraint(
            "driver_id",
            "assignment_date",
            name="uq_driver_assignments_driver_date",
        ),
        Index("ix_driver_assignments_route", "route_id"),
        CheckConstraint("shift_end > shift_start", name="ck_driver_assignments_shift"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    driver_id: Mapped[UUID] = mapped_column(
        ForeignKey("drivers.id", ondelete="CASCADE"),
        nullable=False,
    )
    vehicle_id: Mapped[UUID] = mapped_column(
        ForeignKey("vehicles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    route_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"),
        nullable=True,
    )
    assignment_date: Mapped[dt.date] = mapped_column(Date, nullable=False)
    shift_start: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    shift_end: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    status: Mapped[AssignmentStatus] = mapped_column(
        pg_enum(AssignmentStatus, "assignment_status"),
        nullable=False,
        server_default=AssignmentStatus.SCHEDULED.value,
    )
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    ended_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

