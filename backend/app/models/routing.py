"""
Routing: routes, stops, optimization runs, assignments and comparisons.

``route_optimization_runs`` is **append-only** (ADR-0010). A run stores the exact
input snapshot, the constraints, the solver identity and status, the objective
and the runtime, so a plan can be reproduced and audited years later. That is
what makes route comparison possible: without the frozen inputs there is nothing
to compare against, only a number nobody can explain.

The solver is OR-Tools. An LLM is never used for optimization — see
``docs/architecture/architecture.md`` §8.
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
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import JSONB
from app.db.base import (
    AuditActorMixin,
    Base,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
    VersionMixin,
)
from app.db.types import Code, DistanceKm, Latitude, Longitude, WeightKg
from app.models._enums import (
    BaselineType,
    OptimizationStatus,
    RouteStatus,
    StopStatus,
    pg_enum,
)

__all__ = [
    "Route",
    "RouteAssignment",
    "RouteComparison",
    "RouteOptimizationRun",
    "RouteStop",
]


class Route(
    Base,
    UUIDPrimaryKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    SoftDeleteMixin,
    VersionMixin,
    AuditActorMixin,
):
    """A planned or executed collection route for one date."""

    __tablename__ = "routes"
    __table_args__ = (
        UniqueConstraint("tenant_id", "route_code", name="uq_routes_tenant_code"),
        Index("ix_routes_tenant_date", "tenant_id", "route_date"),
        Index("ix_routes_tenant_status", "tenant_id", "status"),
        Index("ix_routes_vehicle", "vehicle_id"),
        Index("ix_routes_driver", "driver_id"),
        CheckConstraint(
            "planned_distance_km IS NULL OR planned_distance_km >= 0",
            name="ck_routes_distance",
        ),
    )

    route_code: Mapped[Code] = mapped_column(nullable=False)
    route_date: Mapped[dt.date] = mapped_column(Date, nullable=False)
    zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
    )
    service_area_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("service_areas.id", ondelete="SET NULL"),
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
    depot_latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    depot_longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    status: Mapped[RouteStatus] = mapped_column(
        pg_enum(RouteStatus, "route_status"),
        nullable=False,
        server_default=RouteStatus.DRAFT.value,
    )
    planned_start_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    planned_end_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actual_start_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actual_end_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    planned_distance_km: Mapped[DistanceKm | None] = mapped_column(nullable=True)
    actual_distance_km: Mapped[DistanceKm | None] = mapped_column(nullable=True)
    planned_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    actual_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    planned_load_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    actual_load_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    stop_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    completed_stop_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    optimization_run_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("route_optimization_runs.id", ondelete="SET NULL"),
        nullable=True,
    )
    baseline_route_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"),
        nullable=True,
        doc="The route this one is compared against, when it is a comparison.",
    )
    is_optimized: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    stops: Mapped[list[RouteStop]] = relationship(
        "RouteStop",
        back_populates="route",
        cascade="all, delete-orphan",
    )



class RouteStop(Base, TenantScopedMixin, TimestampMixin):
    """
    One stop on a route.

    Latitude/longitude are **snapshots** taken at planning time: the plan must
    remain reproducible and explainable even if the bin is later moved.
    """

    __tablename__ = "route_stops"
    __table_args__ = (
        UniqueConstraint("route_id", "stop_sequence", name="uq_route_stops_sequence"),
        UniqueConstraint("route_id", "bin_id", name="uq_route_stops_bin"),
        Index("ix_route_stops_task", "collection_task_id"),
        CheckConstraint("stop_sequence > 0", name="ck_route_stops_sequence"),
        CheckConstraint(
            "service_duration_minutes IS NULL OR service_duration_minutes >= 0",
            name="ck_route_stops_service",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    route_id: Mapped[UUID] = mapped_column(
        ForeignKey("routes.id", ondelete="CASCADE"),
        nullable=False,
    )
    stop_sequence: Mapped[int] = mapped_column(Integer, nullable=False)
    bin_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bins.id", ondelete="SET NULL"),
        nullable=True,
    )
    address_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("addresses.id", ondelete="SET NULL"),
        nullable=True,
    )
    collection_task_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("collection_tasks.id", ondelete="SET NULL"),
        nullable=True,
    )
    latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    planned_arrival_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    planned_departure_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    service_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    estimated_quantity_kg: Mapped[WeightKg | None] = mapped_column(nullable=True)
    actual_arrival_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    actual_departure_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    status: Mapped[StopStatus] = mapped_column(
        pg_enum(StopStatus, "stop_status"),
        nullable=False,
        server_default=StopStatus.PLANNED.value,
    )
    distance_from_previous_km: Mapped[DistanceKm | None] = mapped_column(nullable=True)
    travel_time_from_previous_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)

    route: Mapped[Route] = relationship(back_populates="stops", foreign_keys=[route_id])


class RouteOptimizationRun(Base, TenantScopedMixin, TimestampMixin):
    """An immutable record of one solver invocation (ADR-0010)."""

    __tablename__ = "route_optimization_runs"
    __table_args__ = (
        UniqueConstraint("tenant_id", "run_code", name="uq_route_optimization_runs_code"),
        Index("ix_route_optimization_runs_tenant_status", "tenant_id", "status"),
        Index("ix_route_optimization_runs_created", text("created_at DESC")),
        CheckConstraint(
            "objective_value IS NULL OR objective_value >= 0",
            name="ck_route_optimization_runs_objective",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    run_code: Mapped[Code] = mapped_column(nullable=False)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    status: Mapped[OptimizationStatus] = mapped_column(
        pg_enum(OptimizationStatus, "optimization_status"),
        nullable=False,
        server_default=OptimizationStatus.QUEUED.value,
    )
    algorithm: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="ortools_cvrptw",
        doc="Solver identity. An LLM is never an optimizer (architecture §8).",
    )
    algorithm_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    objective_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    objective_weights: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    input_snapshot: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        doc="Stops, capacities, windows, priorities and depot — the exact input.",
    )
    constraints: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Capacity, time windows, max vehicles, max duration, priority penalties.",
    )
    solver_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_optimal: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    objective_value: Mapped[Decimal | None] = mapped_column(Numeric(14, 3), nullable=True)
    total_distance_km: Mapped[Decimal | None] = mapped_column(Numeric(12, 3), nullable=True)
    total_duration_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    vehicles_used: Mapped[int | None] = mapped_column(Integer, nullable=True)
    unassigned_stop_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    unassigned_reasons: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Why each unassigned stop could not be served.",
    )
    execution_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    baseline_run_id: Mapped[UUID | None] = mapped_column(nullable=True)
    comparison: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Computed metrics against the baseline, each labelled estimated or measured.",
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class RouteAssignment(Base, TenantScopedMixin, TimestampMixin):
    """A vehicle/driver assignment to a route, with its effective period."""

    __tablename__ = "route_assignments"
    __table_args__ = (
        Index(
            "uq_route_assignments_current",
            "route_id",
            unique=True,
            postgresql_where=text("is_current"),
        ),
        Index("ix_route_assignments_vehicle", "vehicle_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    route_id: Mapped[UUID] = mapped_column(
        ForeignKey("routes.id", ondelete="CASCADE"),
        nullable=False,
    )
    vehicle_id: Mapped[UUID] = mapped_column(
        ForeignKey("vehicles.id", ondelete="RESTRICT"),
        nullable=False,
    )
    driver_id: Mapped[UUID] = mapped_column(
        ForeignKey("drivers.id", ondelete="RESTRICT"),
        nullable=False,
    )
    assigned_by: Mapped[UUID | None] = mapped_column(nullable=True)
    assigned_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    unassigned_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_current: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")


class RouteComparison(Base, TenantScopedMixin, TimestampMixin):
    """
    A materialised comparison of an optimized route against a baseline.

    ``metric_provenance`` labels each metric as estimated or measured, so a
    reader can never mistake a haversine estimate for a measured distance.
    """

    __tablename__ = "route_comparisons"
    __table_args__ = (
        Index("ix_route_comparisons_optimized", "optimized_route_id"),
        Index("ix_route_comparisons_baseline", "baseline_route_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    optimized_route_id: Mapped[UUID] = mapped_column(
        ForeignKey("routes.id", ondelete="CASCADE"),
        nullable=False,
    )
    baseline_type: Mapped[BaselineType] = mapped_column(
        pg_enum(BaselineType, "baseline_type"),
        nullable=False,
    )
    baseline_route_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("routes.id", ondelete="SET NULL"),
        nullable=True,
    )
    distance_delta_km: Mapped[DistanceKm | None] = mapped_column(nullable=True)
    duration_delta_minutes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stops_delta: Mapped[int | None] = mapped_column(Integer, nullable=True)
    utilization_delta_pct: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    fuel_delta_liters: Mapped[Decimal | None] = mapped_column(Numeric(12, 3), nullable=True)
    emissions_delta_kgco2e: Mapped[Decimal | None] = mapped_column(Numeric(14, 4), nullable=True)
    priority_coverage_pct: Mapped[Decimal | None] = mapped_column(Numeric(6, 2), nullable=True)
    metric_provenance: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )

