"""
Geography: zones, service areas, addresses and ad-hoc points (``erd.md`` §3).

No PostGIS column is declared anywhere in this schema (ADR-0005). Coordinates are
``NUMERIC`` with database-enforced bounds, proximity is computed with the
haversine formula, and the bounding-box pre-filter is an ordinary composite
index. That keeps the schema runnable on a stock PostgreSQL build while leaving
a documented upgrade path.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.db.types import Code, Latitude, Longitude, ShortText
from app.models._enums import ServiceFrequency, ZoneType, pg_enum

__all__ = ["Address", "GeoPoint", "ServiceArea", "Zone"]


class Zone(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A geographic grouping (ward, district, campus sector) that scopes operations."""

    __tablename__ = "zones"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_zones_tenant_code"),
        Index("ix_zones_tenant_status", "tenant_id", "status"),
        CheckConstraint(
            "centroid_latitude IS NULL OR centroid_latitude BETWEEN -90 AND 90",
            name="ck_zones_latitude",
        ),
        CheckConstraint(
            "centroid_longitude IS NULL OR centroid_longitude BETWEEN -180 AND 180",
            name="ck_zones_longitude",
        ),
        CheckConstraint("priority IS NULL OR priority BETWEEN 1 AND 10", name="ck_zones_priority"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    zone_type: Mapped[ZoneType] = mapped_column(
        pg_enum(ZoneType, "zone_type"),
        nullable=False,
        server_default=ZoneType.WARD.value,
    )
    parent_zone_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("zones.id", ondelete="SET NULL"),
        nullable=True,
        doc="Self-reference for hierarchies; recursion is depth-limited in the service.",
    )
    boundary_geojson: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Optional polygon as a closed GeoJSON ring; validated to have >= 4 points.",
    )
    centroid_latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    centroid_longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    priority: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
        doc="Feeds the zone weight of the collection-priority scorer.",
    )
    population: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")

    service_areas: Mapped[list[ServiceArea]] = relationship(back_populates="zone")


class ServiceArea(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """A zone sub-region with a service frequency and a time window."""

    __tablename__ = "service_areas"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_service_areas_tenant_code"),
        Index("ix_service_areas_zone", "zone_id"),
        CheckConstraint(
            "service_window_end IS NULL OR service_window_start IS NULL "
            "OR service_window_end > service_window_start",
            name="ck_service_areas_window",
        ),
        CheckConstraint("sla_hours IS NULL OR sla_hours > 0", name="ck_service_areas_sla"),
    )

    zone_id: Mapped[UUID] = mapped_column(ForeignKey("zones.id", ondelete="RESTRICT"), nullable=False)
    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    service_frequency: Mapped[ServiceFrequency] = mapped_column(
        pg_enum(ServiceFrequency, "service_frequency"),
        nullable=False,
        server_default=ServiceFrequency.WEEKLY.value,
    )
    days_of_week: Mapped[list[int] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="ISO day numbers 1-7 (Mon-Sun); validated in the service layer.",
    )
    service_window_start: Mapped[str | None] = mapped_column(
        String(5),
        nullable=True,
        doc="Local wall-clock HH:MM.",
    )
    service_window_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    sla_hours: Mapped[int | None] = mapped_column(Integer, nullable=True)
    default_vehicle_type_id: Mapped[UUID | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")

    zone: Mapped[Zone] = relationship(back_populates="service_areas")


class Address(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """A postal address with optional coordinates, used by bins and facilities."""

    __tablename__ = "addresses"
    __table_args__ = (
        Index("ix_addresses_tenant", "tenant_id"),
        CheckConstraint(
            "latitude IS NULL OR latitude BETWEEN -90 AND 90",
            name="ck_addresses_latitude",
        ),
        CheckConstraint(
            "longitude IS NULL OR longitude BETWEEN -180 AND 180",
            name="ck_addresses_longitude",
        ),
    )

    line1: Mapped[str] = mapped_column(Text, nullable=False)
    line2: Mapped[str | None] = mapped_column(Text, nullable=True)
    landmark: Mapped[str | None] = mapped_column(Text, nullable=True)
    city: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    postal_code: Mapped[str | None] = mapped_column(String(16), nullable=True)
    country: Mapped[str | None] = mapped_column(String(2), nullable=True)
    latitude: Mapped[Latitude | None] = mapped_column(nullable=True)
    longitude: Mapped[Longitude | None] = mapped_column(nullable=True)
    geohash: Mapped[str | None] = mapped_column(
        String(12),
        nullable=True,
        doc="Coarse proximity key; computed by the service on write.",
    )
    access_notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class GeoPoint(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """Ad-hoc points that are neither bins nor facilities: depots, landmarks."""

    __tablename__ = "geo_points"
    __table_args__ = (
        Index("ix_geo_points_tenant_type", "tenant_id", "point_type"),
        CheckConstraint("latitude BETWEEN -90 AND 90", name="ck_geo_points_latitude"),
        CheckConstraint("longitude BETWEEN -180 AND 180", name="ck_geo_points_longitude"),
    )

    label: Mapped[ShortText] = mapped_column(nullable=False)
    point_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="DEPOT",
        doc="DEPOT, COLLECTION_POINT, LANDMARK or TRANSFER_POINT.",
    )
    latitude: Mapped[Latitude] = mapped_column(nullable=False)
    longitude: Mapped[Longitude] = mapped_column(nullable=False)
    address_id: Mapped[UUID | None] = mapped_column(nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")
