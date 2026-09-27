"""
Waste taxonomy (``erd.md`` §4).

``waste_categories`` and ``waste_materials`` are **platform-global** reference
data with no ``tenant_id`` column at all — deliberately, and this is a deviation
from the ERD's single-table-with-nullable-tenant design that is recorded in
``erd.md`` Appendix A. The reason is mechanical rather than stylistic: a table
with a nullable ``tenant_id`` cannot be placed under row-level security without
either hiding the platform baseline from every tenant or allowing tenants to
write into the shared baseline. Splitting shared and tenant-owned rows into
separate tables keeps one rule (tenant-owned ⇒ RLS) true everywhere, and keeps
baseline seeding possible under ``FORCE ROW LEVEL SECURITY``.

Tenant-level taxonomy customisation therefore lives in the tenant-scoped tables
below: ``tenant_waste_categories`` for categories a tenant adds, and
``waste_category_mappings`` for translating external labels into canonical ones.
"""

from __future__ import annotations

from decimal import Decimal
from uuid import UUID

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Numeric,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.db.types import Code, Confidence, ShortText
from app.models._enums import WasteDisposalRoute, pg_enum

__all__ = [
    "TenantWasteCategory",
    "WasteCategory",
    "WasteCategoryMapping",
    "WasteMaterial",
]


class WasteCategory(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """
    A canonical waste category. Global reference data (see the module docstring).

    The eleven baseline categories are seeded with ``is_system=true``; they are
    shared by every tenant so that diversion and carbon analytics remain
    comparable between municipalities.
    """

    __tablename__ = "waste_categories"
    __table_args__ = (
        UniqueConstraint("code", name="uq_waste_categories_code"),
        Index("ix_waste_categories_parent", "parent_id"),
        CheckConstraint(
            "sensitivity_weight IS NULL OR sensitivity_weight BETWEEN 0 AND 1",
            name="ck_waste_categories_weight",
        ),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    parent_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="SET NULL"),
        nullable=True,
        doc="Self-reference for subcategories.",
    )
    is_recyclable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_hazardous: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_organic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_compostable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    disposal_route: Mapped[WasteDisposalRoute] = mapped_column(
        pg_enum(WasteDisposalRoute, "waste_disposal_route"),
        nullable=False,
        server_default=WasteDisposalRoute.LANDFILL.value,
    )
    default_emission_factor_id: Mapped[UUID | None] = mapped_column(nullable=True)
    sensitivity_weight: Mapped[Decimal | None] = mapped_column(
        Numeric(4, 3),
        nullable=True,
        doc="Feeds the category weight of the collection-priority scorer.",
    )
    icon: Mapped[str | None] = mapped_column(String(40), nullable=True)
    colour: Mapped[str | None] = mapped_column(
        String(16),
        nullable=True,
        doc="UI token, e.g. a design-system colour name.",
    )
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")

    materials: Mapped[list[WasteMaterial]] = relationship(back_populates="category")


class WasteMaterial(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A finer-grained material under a category (PET, HDPE, aluminium, …)."""

    __tablename__ = "waste_materials"
    __table_args__ = (
        UniqueConstraint("code", name="uq_waste_materials_code"),
        Index("ix_waste_materials_category", "category_id"),
        CheckConstraint(
            "recyclability_grade IS NULL OR recyclability_grade BETWEEN 1 AND 5",
            name="ck_waste_materials_grade",
        ),
    )

    category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    recyclability_grade: Mapped[int | None] = mapped_column(SmallInteger, nullable=True)
    unit: Mapped[str | None] = mapped_column(String(16), nullable=True)
    density_kg_per_l: Mapped[Decimal | None] = mapped_column(Numeric(8, 4), nullable=True)
    market_value_per_kg: Mapped[Decimal | None] = mapped_column(Numeric(12, 4), nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")

    category: Mapped[WasteCategory] = relationship(back_populates="materials")


class TenantWasteCategory(
    Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin
):
    """
    A category a tenant adds on top of the platform baseline.

    ``extends_category_id`` points at the global baseline row it specialises, so
    analytics can still roll a tenant-specific category up into the shared one.
    """

    __tablename__ = "tenant_waste_categories"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_tenant_waste_categories_code"),
        Index("ix_tenant_waste_categories_extends", "extends_category_id"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    extends_category_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="SET NULL"),
        nullable=True,
    )
    is_recyclable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_hazardous: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_organic: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    is_compostable: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    disposal_route: Mapped[WasteDisposalRoute] = mapped_column(
        pg_enum(WasteDisposalRoute, "waste_disposal_route"),
        nullable=False,
        server_default=WasteDisposalRoute.LANDFILL.value,
    )
    sensitivity_weight: Mapped[Decimal | None] = mapped_column(Numeric(4, 3), nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")


class WasteCategoryMapping(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """
    External label → canonical category, so imports stay deterministic.

    A CSV import or a partner system sends its own strings; resolving them
    through this table (rather than by fuzzy matching at import time) makes an
    import reproducible and reviewable.
    """

    __tablename__ = "waste_category_mappings"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "source_system",
            "external_label",
            name="uq_waste_category_mappings",
        ),
        Index("ix_waste_category_mappings_category", "waste_category_id"),
    )

    source_system: Mapped[str] = mapped_column(Text, nullable=False)
    external_label: Mapped[str] = mapped_column(Text, nullable=False)
    waste_category_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="RESTRICT"),
        nullable=False,
    )
    waste_material_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_materials.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence: Mapped[Confidence | None] = mapped_column(
        nullable=True,
        doc="How much the mapping is trusted; low-confidence mappings are flagged in import reports.",
    )
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
