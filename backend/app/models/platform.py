"""
Platform services: notifications, reporting, files, integrations, jobs, assistant.

Two patterns here deserve stating:

**The transactional outbox** (``domain_events``). A state change and the event
that announces it are written in the *same* transaction, so a failed email or
webhook can never roll back or corrupt business state, and a committed state
change can never lose its notification. The dispatcher is a separate sweep.

**``job_runs`` as the idempotency record.** A job's natural key
(``job_name`` + ``job_key``) is unique, so a retried or double-scheduled job
resolves to ``SKIPPED_DUPLICATE`` rather than running twice. That is what makes
jobs safe to rerun without a distributed lock.
"""

from __future__ import annotations

import datetime as dt
from typing import Any
from uuid import UUID

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
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
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    SoftDeleteMixin,
    TenantKeyMixin,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.db.types import Code, LongText, ShortText
from app.models._enums import (
    DigestFrequency,
    ExportFormat,
    FileOwnerType,
    IntegrationType,
    JobStatus,
    NotificationChannel,
    NotificationStatus,
    NotificationType,
    ReportStatus,
    ReportType,
    ScanStatus,
    Severity,
    WebhookDeliveryStatus,
    pg_enum,
)

__all__ = [
    "AssistantConversation",
    "AssistantMessage",
    "DataRetentionPolicy",
    "DomainEvent",
    "FileAsset",
    "Integration",
    "JobRun",
    "Notification",
    "NotificationPreference",
    "NotificationTemplate",
    "ReportDefinition",
    "ReportRun",
    "ScoringConfiguration",
    "Webhook",
    "WebhookDelivery",
]


class Notification(Base, TenantScopedMixin, TimestampMixin):
    """
    One message to one recipient.

    ``dedup_key`` plus the partial unique index is the deduplication
    requirement: the same condition for the same user raises one notification,
    not one per sweep.
    """

    __tablename__ = "notifications"
    __table_args__ = (
        Index(
            "uq_notifications_dedup",
            "tenant_id",
            "recipient_user_id",
            "dedup_key",
            unique=True,
            postgresql_where=text("dedup_key IS NOT NULL"),
        ),
        Index("ix_notifications_recipient_status", "recipient_user_id", "status"),
        Index("ix_notifications_tenant_created", "tenant_id", text("created_at DESC")),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    recipient_user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    notification_type: Mapped[NotificationType] = mapped_column(
        pg_enum(NotificationType, "notification_type"),
        nullable=False,
    )
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        server_default=Severity.MEDIUM.value,
    )
    title: Mapped[ShortText] = mapped_column(nullable=False)
    body: Mapped[LongText | None] = mapped_column(nullable=True)
    action_url: Mapped[str | None] = mapped_column(Text, nullable=True)
    action_label: Mapped[ShortText | None] = mapped_column(nullable=True)
    resource_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    resource_id: Mapped[UUID | None] = mapped_column(nullable=True)
    channel: Mapped[NotificationChannel] = mapped_column(
        pg_enum(NotificationChannel, "notification_channel"),
        nullable=False,
        server_default=NotificationChannel.IN_APP.value,
    )
    status: Mapped[NotificationStatus] = mapped_column(
        pg_enum(NotificationStatus, "notification_status"),
        nullable=False,
        server_default=NotificationStatus.PENDING.value,
    )
    dedup_key: Mapped[str | None] = mapped_column(Text, nullable=True)
    read_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    sent_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivery_attempts: Mapped[int] = mapped_column(
        SmallInteger, nullable=False, server_default=text("0")
    )
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NotificationPreference(Base, TenantScopedMixin, TimestampMixin):
    """Per-user, per-type delivery preferences, including quiet hours."""

    __tablename__ = "notification_preferences"
    __table_args__ = (
        UniqueConstraint("user_id", "notification_type", name="uq_notification_preferences"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    notification_type: Mapped[NotificationType] = mapped_column(
        pg_enum(NotificationType, "notification_type"),
        nullable=False,
    )
    in_app_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    email_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    push_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    webhook_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    min_severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        server_default=Severity.MEDIUM.value,
    )
    quiet_hours_start: Mapped[str | None] = mapped_column(String(5), nullable=True)
    quiet_hours_end: Mapped[str | None] = mapped_column(String(5), nullable=True)
    digest_frequency: Mapped[DigestFrequency] = mapped_column(
        pg_enum(DigestFrequency, "digest_frequency"),
        nullable=False,
        server_default=DigestFrequency.INSTANT.value,
    )


class NotificationTemplate(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """User-facing copy per type, channel and locale. Global reference data."""

    __tablename__ = "notification_templates"
    __table_args__ = (
        UniqueConstraint(
            "notification_type",
            "channel",
            "locale",
            name="uq_notification_templates",
        ),
    )

    notification_type: Mapped[NotificationType] = mapped_column(
        pg_enum(NotificationType, "notification_type"),
        nullable=False,
    )
    channel: Mapped[NotificationChannel] = mapped_column(
        pg_enum(NotificationChannel, "notification_channel"),
        nullable=False,
    )
    locale: Mapped[str] = mapped_column(String(8), nullable=False, server_default="en-IN")
    subject_template: Mapped[str | None] = mapped_column(Text, nullable=True)
    body_template: Mapped[str] = mapped_column(Text, nullable=False)
    variables: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="The variable names the template expects.",
    )
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")


class ReportDefinition(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A parameterised report. Global reference data; ``data_provider`` names the
    service function that builds the payload, which keeps data generation and
    rendering separate (``erd.md`` §9.4).
    """

    __tablename__ = "report_definitions"
    __table_args__ = (UniqueConstraint("code", name="uq_report_definitions_code"),)

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    report_type: Mapped[ReportType] = mapped_column(
        pg_enum(ReportType, "report_type"),
        nullable=False,
    )
    parameter_schema: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        doc="JSON Schema; validated at request time.",
    )
    data_provider: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="The service function that builds the structured payload.",
    )
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")


class ReportRun(Base, TenantScopedMixin, TimestampMixin):
    """One execution of a report definition. Append-only."""

    __tablename__ = "report_runs"
    __table_args__ = (
        Index("ix_report_runs_tenant_status", "tenant_id", "status"),
        Index("ix_report_runs_definition", "report_definition_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    report_definition_id: Mapped[UUID] = mapped_column(
        ForeignKey("report_definitions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    parameters: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    requested_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    status: Mapped[ReportStatus] = mapped_column(
        pg_enum(ReportStatus, "report_status"),
        nullable=False,
        server_default=ReportStatus.QUEUED.value,
    )
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    payload: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="The structured result. Rendering is a separate step.",
    )
    export_file_id: Mapped[UUID | None] = mapped_column(nullable=True)
    export_format: Mapped[ExportFormat | None] = mapped_column(
        pg_enum(ExportFormat, "export_format"),
        nullable=True,
    )
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class FileAsset(Base, TenantScopedMixin, TimestampMixin, SoftDeleteMixin):
    """
    An uploaded file.

    ``content_type`` is detected by **content sniffing**, never taken from the
    client's declared MIME type, and ``stored_filename`` is server-generated: a
    user-supplied filename can never reach the filesystem. The CHECK constraint
    is the last line of that defence.
    """

    __tablename__ = "file_assets"
    __table_args__ = (
        Index("ix_file_assets_owner", "owner_type", "owner_id"),
        Index("ix_file_assets_tenant_created", "tenant_id", text("created_at DESC")),
        CheckConstraint("size_bytes > 0", name="ck_file_assets_size"),
        CheckConstraint("stored_filename !~ '[/\\\\]'", name="ck_file_assets_filename"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    owner_type: Mapped[FileOwnerType | None] = mapped_column(
        pg_enum(FileOwnerType, "file_owner_type"),
        nullable=True,
    )
    owner_id: Mapped[UUID | None] = mapped_column(nullable=True)
    original_filename: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Stored for display only; never used to build a path.",
    )
    stored_filename: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Server-generated UUID-based name.",
    )
    storage_provider: Mapped[str] = mapped_column(Text, nullable=False, server_default="local")
    storage_path: Mapped[str] = mapped_column(Text, nullable=False)
    content_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="Detected by sniffing the content, not from the client header.",
    )
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    checksum_sha256: Mapped[str | None] = mapped_column(Text, nullable=True)
    width_px: Mapped[int | None] = mapped_column(Integer, nullable=True)
    height_px: Mapped[int | None] = mapped_column(Integer, nullable=True)
    uploaded_by: Mapped[UUID | None] = mapped_column(nullable=True)
    scan_status: Mapped[ScanStatus] = mapped_column(
        pg_enum(ScanStatus, "scan_status"),
        nullable=False,
        server_default=ScanStatus.PENDING.value,
    )
    scan_detail: Mapped[str | None] = mapped_column(Text, nullable=True)


class Integration(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    A configured external adapter. Global reference data.

    ``configuration`` holds **references** to secrets by name, never the secrets
    themselves: a database disclosure must not yield usable credentials.
    """

    __tablename__ = "integrations"
    __table_args__ = (UniqueConstraint("code", name="uq_integrations_code"),)

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    integration_type: Mapped[IntegrationType] = mapped_column(
        pg_enum(IntegrationType, "integration_type"),
        nullable=False,
    )
    adapter_class: Mapped[str] = mapped_column(Text, nullable=False)
    configuration: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    is_enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    last_health_check_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_health_status: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")


class Webhook(Base, TenantScopedMixin, TimestampMixin):
    """An outbound subscription. The signing secret is stored only as a hash."""

    __tablename__ = "webhooks"
    __table_args__ = (
        UniqueConstraint("tenant_id", "event_type", "target_url", name="uq_webhooks"),
        Index("ix_webhooks_tenant_active", "tenant_id", "is_active"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    target_url: Mapped[str] = mapped_column(Text, nullable=False)
    secret_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="HMAC signing secret, stored hashed. The secret is shown once.",
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    failure_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_success_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    last_failure_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by: Mapped[UUID | None] = mapped_column(nullable=True)


class WebhookDelivery(Base, TenantScopedMixin, TimestampMixin):
    """
    One delivery attempt record.

    The unique constraint on ``(webhook_id, event_id)`` is what makes delivery
    idempotent under retries: the same event to the same webhook is delivered
    once, however many times the dispatcher runs.
    """

    __tablename__ = "webhook_deliveries"
    __table_args__ = (
        UniqueConstraint("webhook_id", "event_id", name="uq_webhook_deliveries"),
        Index("ix_webhook_deliveries_status", "tenant_id", "status", "next_retry_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    webhook_id: Mapped[UUID] = mapped_column(
        ForeignKey("webhooks.id", ondelete="CASCADE"),
        nullable=False,
    )
    event_id: Mapped[UUID] = mapped_column(nullable=False)
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    status: Mapped[WebhookDeliveryStatus] = mapped_column(
        pg_enum(WebhookDeliveryStatus, "webhook_delivery_status"),
        nullable=False,
        server_default=WebhookDeliveryStatus.PENDING.value,
    )
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body_excerpt: Mapped[str | None] = mapped_column(Text, nullable=True)
    next_retry_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    delivered_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class DomainEvent(Base, TenantKeyMixin):
    """The transactional outbox: written with the state change, dispatched after."""

    __tablename__ = "domain_events"
    __table_args__ = (
        Index("ix_domain_events_pending", text("published_at NULLS FIRST"), "occurred_at"),
        Index("ix_domain_events_type", "event_type"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    event_type: Mapped[str] = mapped_column(Text, nullable=False)
    aggregate_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    aggregate_id: Mapped[UUID | None] = mapped_column(nullable=True)
    payload: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    occurred_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    attempt_count: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)


class JobRun(Base, TenantKeyMixin, TimestampMixin):
    """
    One execution of a background job, and its idempotency record.

    ``UNIQUE (job_name, job_key)`` is the mechanism: a retried or
    double-scheduled job inserts nothing and reports ``SKIPPED_DUPLICATE``.
    """

    __tablename__ = "job_runs"
    __table_args__ = (
        UniqueConstraint("job_name", "job_key", name="uq_job_runs"),
        Index("ix_job_runs_tenant_status", "tenant_id", "status"),
        Index("ix_job_runs_scheduled", "status", "scheduled_at"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    job_name: Mapped[str] = mapped_column(Text, nullable=False)
    job_key: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Natural idempotency key; NULL for jobs that are always allowed to rerun.",
    )
    payload: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    status: Mapped[JobStatus] = mapped_column(
        pg_enum(JobStatus, "job_status"),
        nullable=False,
        server_default=JobStatus.QUEUED.value,
    )
    attempt: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("0"))
    max_attempts: Mapped[int] = mapped_column(Integer, nullable=False, server_default=text("3"))
    scheduled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    result: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)


class ScoringConfiguration(Base, TenantScopedMixin, TimestampMixin):
    """
    The active weights and thresholds of a scorer.

    Because the weights are data and the scorer reads them, a reader can inspect
    exactly why a bin scored as it did — the explainability requirement.
    """

    __tablename__ = "scoring_configurations"
    __table_args__ = (
        Index(
            "uq_scoring_configurations_active",
            "tenant_id",
            "score_type",
            unique=True,
            postgresql_where=text("is_active"),
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    score_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="COLLECTION_PRIORITY or OVERFLOW_RISK.",
    )
    weights: Mapped[dict[str, Any]] = mapped_column(JSONB, nullable=False)
    thresholds: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        server_default=text("'{}'::jsonb"),
    )
    version: Mapped[str] = mapped_column(Text, nullable=False, server_default="v1")
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    updated_by: Mapped[UUID | None] = mapped_column(nullable=True)


class DataRetentionPolicy(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """How long a class of data is kept, and whether it is archived first."""

    __tablename__ = "data_retention_policies"
    __table_args__ = (
        UniqueConstraint("data_class", name="uq_data_retention_policies"),
        CheckConstraint("retention_days > 0", name="ck_data_retention_policies_days"),
    )

    data_class: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="BIN_TELEMETRY, VEHICLE_TELEMETRY, AUDIT_LOG, NOTIFICATION, JOB_RUN, …",
    )
    retention_days: Mapped[int] = mapped_column(Integer, nullable=False)
    archive_before_delete: Mapped[bool] = mapped_column(
        Boolean, nullable=False, server_default="true"
    )
    last_enforced_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)


class AssistantConversation(Base, TenantScopedMixin, TimestampMixin):
    """A conversation with the tool-bound assistant."""

    __tablename__ = "assistant_conversations"
    __table_args__ = (Index("ix_assistant_conversations_user", "user_id", text("created_at DESC")),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )
    title: Mapped[ShortText | None] = mapped_column(nullable=True)
    last_message_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AssistantMessage(Base, TenantScopedMixin, TimestampMixin):
    """
    One turn of a conversation.

    ``statements`` carries the grounded answer with per-statement evidence and a
    type label (``DATABASE_FACT``, ``MODEL_PREDICTION``, ``ESTIMATE``,
    ``RECOMMENDATION`` or ``UNKNOWN``); ``tools_used`` records which tools ran
    and what they returned, so an answer is always auditable.
    """

    __tablename__ = "assistant_messages"
    __table_args__ = (Index("ix_assistant_messages_conversation", "conversation_id", "created_at"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    conversation_id: Mapped[UUID] = mapped_column(
        ForeignKey("assistant_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(Text, nullable=False, doc="user, assistant or system.")
    content: Mapped[LongText] = mapped_column(nullable=False)
    statements: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Grounded statements, each with evidence and a type label.",
    )
    tools_used: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Which tools ran, with their arguments and results.",
    )
    limitations: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="What the assistant could not determine, and why.",
    )
    provider: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_version_id: Mapped[UUID | None] = mapped_column(nullable=True)
    token_usage: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
