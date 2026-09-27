"""
Identity, tenancy and access-control entities (``erd.md`` §2).

This module is the schema half of multi-tenancy. Three rules are encoded here and
are not negotiable (ADR-0003):

1. every tenant-owned table carries ``tenant_id`` — via
   :class:`~app.db.base.TenantScopedMixin` when a foreign key is meaningful, or
   :class:`~app.db.base.TenantKeyMixin` when a *platform* actor must also be able
   to write the row (sessions, audit logs, outbox events, job runs);
2. ``password_hash`` and ``refresh_token_hash`` exist only as hashes — no model
   or schema in this package can return a credential;
3. ``audit_logs`` is append-only: no ``updated_at``, no soft delete, and no code
   path updates or deletes a row.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from sqlalchemy import (
    ARRAY,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import INET, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TenantKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.db.types import Code, ShortText
from app.models._enums import (
    ActorType,
    EventOutcome,
    PermissionScope,
    SettingValueType,
    TenantStatus,
    TenantType,
    UserStatus,
    pg_enum,
)

__all__ = [
    "ApiKey",
    "AuditLog",
    "OrganizationProfile",
    "Permission",
    "Role",
    "RolePermission",
    "Session",
    "Tenant",
    "TenantSetting",
    "User",
    "UserRole",
]


class Tenant(Base, UUIDPrimaryKeyMixin, TimestampMixin, SoftDeleteMixin):
    """A customer organisation. The root of every tenant-scoped row."""

    __tablename__ = "tenants"
    __table_args__ = (
        Index("uq_tenants_slug", "slug", unique=True),
        Index("ix_tenants_status", "status"),
    )

    name: Mapped[str] = mapped_column(Text, nullable=False)
    slug: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="URL-safe identifier, unique across the platform.",
    )
    type: Mapped[TenantType] = mapped_column(
        pg_enum(TenantType, "tenant_type"),
        nullable=False,
    )
    status: Mapped[TenantStatus] = mapped_column(
        pg_enum(TenantStatus, "tenant_status"),
        nullable=False,
        server_default=TenantStatus.TRIAL.value,
    )
    timezone: Mapped[str] = mapped_column(Text, nullable=False, server_default="Asia/Kolkata")
    locale: Mapped[str] = mapped_column(Text, nullable=False, server_default="en-IN")
    plan: Mapped[str] = mapped_column(Text, nullable=False, server_default="standard")
    trial_ends_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    profile: Mapped[OrganizationProfile | None] = relationship(
        back_populates="tenant",
        cascade="all, delete-orphan",
        uselist=False,
    )


class OrganizationProfile(Base, TimestampMixin):
    """The 1:1 legal/branding profile of a tenant (``erd.md`` §2.2)."""

    __tablename__ = "organization_profiles"

    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        primary_key=True,
        doc="Primary key *and* foreign key: the profile has no independent identity.",
    )
    legal_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    registration_number: Mapped[str | None] = mapped_column(Text, nullable=True)
    tax_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_contact_name: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_contact_email: Mapped[str | None] = mapped_column(Text, nullable=True)
    primary_contact_phone: Mapped[str | None] = mapped_column(Text, nullable=True)
    address_line1: Mapped[str | None] = mapped_column(Text, nullable=True)
    address_line2: Mapped[str | None] = mapped_column(Text, nullable=True)
    city: Mapped[str | None] = mapped_column(Text, nullable=True)
    state: Mapped[str | None] = mapped_column(Text, nullable=True)
    postal_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    country: Mapped[str | None] = mapped_column(
        String(2),
        nullable=True,
        doc="ISO-3166 alpha-2.",
    )
    logo_file_id: Mapped[UUID | None] = mapped_column(
        nullable=True,
        doc="FK to file_assets.id, resolved lazily so the two modules stay independent.",
    )
    service_territory_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    onboarded_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    tenant: Mapped[Tenant] = relationship(back_populates="profile")


class User(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """
    An authenticated principal.

    Every user belongs to exactly one tenant scope, including platform operators,
    whose scope is the **platform tenant** seeded by the migration. That is
    deliberate: it keeps the foreign key to ``tenants`` intact, keeps the
    ``(tenant_id, lower(email))`` uniqueness rule uniform, and — most
    importantly — keeps row-level security able to *see* a platform operator's
    row when the platform context is bound. A ``NULL`` tenant id would be
    invisible to every policy, so a platform user could never authenticate.

    Email is therefore unique per tenant rather than per platform: two
    municipalities may legitimately employ the same person's address.
    """

    __tablename__ = "users"
    __table_args__ = (
        Index("uq_users_tenant_email", "tenant_id", text("lower(email)"), unique=True),
        Index("ix_users_tenant_status", "tenant_id", "status"),
    )

    email: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Argon2id encoded hash. Never selected into an API response.",
    )
    full_name: Mapped[str] = mapped_column(Text, nullable=False)
    phone: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[UserStatus] = mapped_column(
        pg_enum(UserStatus, "user_status"),
        nullable=False,
        server_default=UserStatus.INVITED.value,
    )
    email_verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_login_ip: Mapped[str | None] = mapped_column(INET, nullable=True)
    failed_login_attempts: Mapped[int] = mapped_column(
        SmallInteger,
        nullable=False,
        server_default=text("0"),
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_secret_encrypted: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Architecture only: the column exists so MFA can be added without a migration.",
    )
    preferred_timezone: Mapped[str | None] = mapped_column(Text, nullable=True)
    preferred_locale: Mapped[str | None] = mapped_column(Text, nullable=True)

    roles: Mapped[list[UserRole]] = relationship(
        back_populates="user",
        cascade="all, delete-orphan",
        foreign_keys="UserRole.user_id",
    )


class Role(Base, UUIDPrimaryKeyMixin, TenantScopedMixin, TimestampMixin):
    """
    A named bundle of permissions.

    System roles are seeded into the **platform tenant** with
    ``is_system=true``; provisioning a tenant clones them into that tenant with
    ``is_system=false``, which is how a tenant customises without touching code.
    Authorization therefore never compares a role name — it compares permission
    codes (``rbac.md`` §1).
    """

    __tablename__ = "roles"
    __table_args__ = (
        UniqueConstraint("tenant_id", "code", name="uq_roles_tenant_code"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))
    is_default: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        server_default=text("false"),
        doc="Granted automatically to a new member of the tenant.",
    )
    level: Mapped[int] = mapped_column(SmallInteger, nullable=False, server_default=text("0"))

    permissions: Mapped[list[RolePermission]] = relationship(
        back_populates="role",
        cascade="all, delete-orphan",
    )


class Permission(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A single ``resource.action`` capability.

    The catalogue is seeded by migration and is the *only* thing authorization
    checks. ``is_dangerous`` drives the extra confirmation the UI shows; it has
    no effect on enforcement, which is unconditional.
    """

    __tablename__ = "permissions"

    code: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
        doc="Permission code, e.g. ``bins.write`` or ``bins.read.own``.",
    )
    resource: Mapped[str] = mapped_column(Text, nullable=False)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    scope: Mapped[PermissionScope] = mapped_column(
        pg_enum(PermissionScope, "permission_scope"),
        nullable=False,
        server_default=PermissionScope.TENANT.value,
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_dangerous: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("false"))


class RolePermission(Base, TenantScopedMixin):
    """
    Which permissions a role grants (``rbac.md`` §4 is the seeded matrix).

    Tenant-scoped even though ``permissions`` is global: the *grant* is tenant
    data, and a tenant's custom role must not be readable by another tenant.
    """

    __tablename__ = "role_permissions"
    __table_args__ = (
        Index("ix_role_permissions_permission", "permission_id"),
        Index("ix_role_permissions_tenant", "tenant_id"),
    )

    tenant_id: Mapped[UUID] = mapped_column(
        nullable=False,
        doc="The tenant owning the role this grant belongs to.",
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True
    )
    permission_id: Mapped[UUID] = mapped_column(
        ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True
    )
    granted_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    granted_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
        doc="Who granted it. Kept as a nullable FK so a departed user's grants survive.",
    )

    role: Mapped[Role] = relationship(back_populates="permissions")


class UserRole(Base, TimestampMixin):
    """
    Membership: which user holds which role in which tenant.

    A user may hold roles in several tenants; only one is active per session
    (``X-Tenant-Id`` selects among the user's own memberships). ``expires_at``
    supports time-boxed grants such as contractor access.
    """

    __tablename__ = "user_roles"
    __table_args__ = (
        UniqueConstraint("user_id", "role_id", "tenant_id", name="uq_user_roles"),
        Index("ix_user_roles_tenant", "tenant_id"),
        Index("ix_user_roles_user", "user_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    role_id: Mapped[UUID] = mapped_column(
        ForeignKey("roles.id", ondelete="CASCADE"), nullable=False
    )
    tenant_id: Mapped[UUID] = mapped_column(
        ForeignKey("tenants.id", ondelete="CASCADE"),
        nullable=False,
        doc="The tenant this grant applies in (platform sentinel for platform roles).",
    )
    assigned_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    assigned_by: Mapped[UUID | None] = mapped_column(nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped[User] = relationship(
        back_populates="roles",
        foreign_keys=[user_id],
    )
    role: Mapped[Role] = relationship(foreign_keys=[role_id])


class Session(Base, TenantKeyMixin):
    """
    A refresh-token session.

    The ``id`` is embedded in the access token, so a token is only usable while
    its session row is live — revocation is therefore immediate rather than
    waiting for expiry. ``refresh_token_hash`` stores SHA-256 of the token; the
    token itself is returned to the client once and never persisted.

    Rotation reuse detection: presenting a token whose hash belongs to a
    superseded row in the same ``family_id`` revokes the whole family, because
    the only honest explanation is that a token was stolen.
    """

    __tablename__ = "sessions"
    __table_args__ = (
        Index("ix_sessions_user_active", "user_id", "revoked_at"),
        Index("ix_sessions_family", "family_id"),
        Index("ix_sessions_expires", "expires_at"),
    )

    id: Mapped[UUID] = mapped_column(
        primary_key=True,
        doc="Generated by the application; the token embeds it as its session id.",
    )
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        unique=True,
        doc="SHA-256 of the refresh token. The token is never stored.",
    )
    family_id: Mapped[UUID] = mapped_column(
        nullable=False,
        doc="Rotation family. Reuse of any member revokes the family.",
    )
    previous_session_id: Mapped[UUID | None] = mapped_column(nullable=True)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ApiKey(Base, TenantScopedMixin, TimestampMixin):
    """
    A long-lived credential for a device gateway or a partner integration.

    Only a prefix and a hash are stored, so a database disclosure does not yield
    a usable key. ``scopes`` restricts what the key may do; the telemetry
    ingestion endpoint is reachable only through this path (``rbac.md`` §4.1).
    """

    __tablename__ = "api_keys"
    __table_args__ = (
        Index("uq_api_keys_prefix", "key_prefix", unique=True),
        Index("ix_api_keys_tenant", "tenant_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    name: Mapped[ShortText] = mapped_column(nullable=False)
    key_prefix: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
        doc="Visible identifier shown in the UI; not a secret.",
    )
    key_hash: Mapped[str] = mapped_column(Text, nullable=False)
    scopes: Mapped[list[str]] = mapped_column(
        ARRAY(Text),
        nullable=False,
        server_default=text("'{}'::text[]"),
    )
    created_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rotation_of_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("api_keys.id", ondelete="SET NULL"),
        nullable=True,
        doc="The key this one replaces, so rotation is traceable rather than opaque.",
    )


class AuditLog(Base, TenantKeyMixin):
    """
    The append-only compliance trail (``erd.md`` §2.10).

    Immutability is structural rather than promised: there is no ``updated_at``,
    no soft-delete column and no code path that updates or deletes a row.
    Retention is a separate archival job that archives before it deletes.
    """

    __tablename__ = "audit_logs"
    __table_args__ = (
        Index("ix_audit_logs_tenant_created", "tenant_id", text("created_at DESC")),
        Index("ix_audit_logs_resource", "resource_type", "resource_id"),
        Index("ix_audit_logs_actor", "actor_user_id", text("created_at DESC")),
    )

    id: Mapped[int] = mapped_column(
        Integer,
        primary_key=True,
        autoincrement=True,
        doc="BIGSERIAL-equivalent: high volume and never updated, so a UUID adds nothing.",
    )
    actor_user_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    actor_type: Mapped[ActorType] = mapped_column(
        pg_enum(ActorType, "actor_type"),
        nullable=False,
        server_default=ActorType.USER.value,
    )
    actor_label: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Snapshot of the actor's identity at the time of the action.",
    )
    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    outcome: Mapped[EventOutcome] = mapped_column(
        pg_enum(EventOutcome, "event_outcome"),
        nullable=False,
        server_default=EventOutcome.SUCCESS.value,
    )
    request_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(INET, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: The column is named ``metadata`` in the database (``erd.md`` §2.10); the
    #: Python attribute is ``event_metadata`` because ``metadata`` is reserved by
    #: the declarative API and cannot be used as an attribute name.
    event_metadata: Mapped[dict] = mapped_column(
        "metadata",
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
        doc="Redacted by the audit service before the row is written.",
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class TenantSetting(Base, TenantScopedMixin, TimestampMixin):
    """Typed per-tenant configuration (``erd.md`` §2.11)."""

    __tablename__ = "tenant_settings"
    __table_args__ = (UniqueConstraint("tenant_id", "key", name="uq_tenant_settings"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    key: Mapped[str] = mapped_column(Text, nullable=False)
    value: Mapped[dict | list | str | int | float | bool | None] = mapped_column(JSONB, nullable=True)
    value_type: Mapped[SettingValueType] = mapped_column(
        pg_enum(SettingValueType, "setting_value_type"),
        nullable=False,
        server_default=SettingValueType.STRING.value,
    )
    updated_by: Mapped[UUID | None] = mapped_column(nullable=True)
