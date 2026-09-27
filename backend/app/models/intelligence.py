"""
Intelligence: model registry, forecasts, anomalies, classification, recommendations.

Three rules shape this module:

1. **No metric without an evaluation run.** ``model_metrics`` rows are produced
   by an evaluation pipeline against a named dataset; nothing here can store a
   hand-written accuracy figure (ADR-0008).
2. **Datasets are never ambiguous about being synthetic.** ``ml_datasets.is_synthetic``
   is NOT NULL, so a synthetic-corpus evaluation can never be presented as field
   validation.
3. **Every prediction carries provenance.** Forecasts, anomalies and
   classifications store the model version, the input window and, where
   available, an uncertainty interval. When there is not enough data the honest
   answer is ``INSUFFICIENT_DATA``, not a zero.

``recommendations`` requires non-empty evidence at the database level: a
recommendation nobody can trace back to the rows that produced it is not a
recommendation, it is a guess (BR-16).
"""

from __future__ import annotations

import datetime as dt
from decimal import Decimal
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
    Numeric,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.db.base import (
    Base,
    TenantScopedMixin,
    TimestampMixin,
    UUIDPrimaryKeyMixin,
)
from app.db.types import Code, Confidence, LongText, Score, ShortText
from app.models._enums import (
    AnomalyDetectionMethod,
    AnomalyStatus,
    ClassificationMethod,
    EvaluationType,
    ForecastGranularity,
    ForecastTargetMetric,
    ModelType,
    ModelVersionStatus,
    PriorityLevel,
    ProvenanceKind,
    RecommendationGenerator,
    RecommendationStatus,
    RecommendationType,
    ReviewStatus,
    RunStatus,
    ScopeType,
    Severity,
    pg_enum,
)

__all__ = [
    "AIModel",
    "AIModelVersion",
    "Anomaly",
    "AnomalyEvent",
    "ClassificationFeedback",
    "Forecast",
    "ForecastRun",
    "MLDataset",
    "ModelMetric",
    "Recommendation",
    "RecommendationFeedback",
    "WasteClassification",
]


class AIModel(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    The registry root for a model.

    Global: promotion is a platform action (``platform.models.manage``), because
    a tenant activating an unevaluated model would violate the
    scientific-integrity rules (``rbac.md`` §4.1).
    """

    __tablename__ = "ai_models"
    __table_args__ = (
        UniqueConstraint("code", name="uq_ai_models_code"),
        Index("ix_ai_models_type", "model_type"),
    )

    code: Mapped[Code] = mapped_column(nullable=False)
    name: Mapped[ShortText] = mapped_column(nullable=False)
    model_type: Mapped[ModelType] = mapped_column(
        pg_enum(ModelType, "model_type"),
        nullable=False,
    )
    task_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_system: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="true")
    status: Mapped[str] = mapped_column(Text, nullable=False, server_default="ACTIVE")
    created_by: Mapped[UUID | None] = mapped_column(nullable=True)


class AIModelVersion(Base, UUIDPrimaryKeyMixin, TimestampMixin):
    """
    One immutable version of a model.

    The partial unique index — one ACTIVE version per model — is BR-14 enforced
    by the database rather than by convention. ``feature_definition`` is the
    feature contract: without it, a version cannot be reproduced or compared.
    """

    __tablename__ = "ai_model_versions"
    __table_args__ = (
        UniqueConstraint("model_id", "version", name="uq_ai_model_versions"),
        Index(
            "uq_ai_model_versions_active",
            "model_id",
            unique=True,
            postgresql_where=text("status = 'ACTIVE'"),
        ),
        Index("ix_ai_model_versions_status", "status"),
    )

    model_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai_models.id", ondelete="CASCADE"),
        nullable=False,
    )
    version: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[ModelVersionStatus] = mapped_column(
        pg_enum(ModelVersionStatus, "model_version_status"),
        nullable=False,
        server_default=ModelVersionStatus.CANDIDATE.value,
    )
    algorithm_family: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="CLASSICAL_CV, GBT_REGRESSOR, SEASONAL_NAIVE, EXPONENTIAL_SMOOTHING, …",
    )
    framework: Mapped[str | None] = mapped_column(Text, nullable=True)
    framework_version: Mapped[str | None] = mapped_column(Text, nullable=True)
    hyperparameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    feature_definition: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        doc="The feature contract: what goes in, in what order.",
    )
    artifact_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    artifact_checksum: Mapped[str | None] = mapped_column(Text, nullable=True)
    training_dataset_id: Mapped[UUID | None] = mapped_column(nullable=True)
    training_started_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    training_completed_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    training_duration_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    trained_by_user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    promoted_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    promoted_by: Mapped[UUID | None] = mapped_column(nullable=True)
    retired_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)


class MLDataset(Base, TenantScopedMixin, TimestampMixin):
    """A dataset a model was trained or evaluated on. ``is_synthetic`` is mandatory."""

    __tablename__ = "ml_datasets"
    __table_args__ = (
        UniqueConstraint("tenant_id", "name", "version", name="uq_ml_datasets"),
        CheckConstraint("row_count IS NULL OR row_count >= 0", name="ck_ml_datasets_rows"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    name: Mapped[ShortText] = mapped_column(nullable=False)
    version: Mapped[str] = mapped_column(Text, nullable=False)
    dataset_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="LABELLED_IMAGES, TELEMETRY_HISTORY, COLLECTION_HISTORY or SYNTHETIC.",
    )
    row_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    date_range_start: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    date_range_end: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    checksum: Mapped[str | None] = mapped_column(Text, nullable=True)
    storage_path: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_synthetic: Mapped[bool] = mapped_column(
        Boolean,
        nullable=False,
        doc="Never optional: a synthetic corpus must not masquerade as field data.",
    )
    generation_parameters: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Required when is_synthetic: the seed and the distribution used.",
    )
    created_by: Mapped[UUID | None] = mapped_column(nullable=True)


class ModelMetric(Base, TenantScopedMixin, TimestampMixin):
    """One metric from one evaluation run against one dataset."""

    __tablename__ = "model_metrics"
    __table_args__ = (
        UniqueConstraint(
            "model_version_id",
            "dataset_id",
            "evaluation_type",
            "metric_name",
            name="uq_model_metrics",
        ),
        Index("ix_model_metrics_version", "model_version_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    model_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai_model_versions.id", ondelete="CASCADE"),
        nullable=False,
    )
    dataset_id: Mapped[UUID] = mapped_column(
        ForeignKey("ml_datasets.id", ondelete="RESTRICT"),
        nullable=False,
    )
    evaluation_type: Mapped[EvaluationType] = mapped_column(
        pg_enum(EvaluationType, "evaluation_type"),
        nullable=False,
        doc="TRAINING results are stored but never presented as validation performance.",
    )
    metric_name: Mapped[str] = mapped_column(Text, nullable=False)
    metric_value: Mapped[Decimal] = mapped_column(Numeric(10, 6), nullable=False)
    per_class: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    confusion_matrix: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    sample_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    computed_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )


class ForecastRun(Base, TenantScopedMixin, TimestampMixin):
    """One invocation of a forecasting model. Append-only."""

    __tablename__ = "forecast_runs"
    __table_args__ = (
        Index("ix_forecast_runs_tenant_subject", "tenant_id", "subject_type", "subject_id"),
        Index("ix_forecast_runs_status", "status"),
        CheckConstraint("horizon_periods > 0", name="ck_forecast_runs_horizon"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    model_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai_model_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    status: Mapped[RunStatus] = mapped_column(
        pg_enum(RunStatus, "run_status"),
        nullable=False,
        server_default=RunStatus.QUEUED.value,
    )
    subject_type: Mapped[ScopeType] = mapped_column(
        pg_enum(ScopeType, "scope_type"),
        nullable=False,
    )
    subject_id: Mapped[UUID | None] = mapped_column(nullable=True)
    target_metric: Mapped[ForecastTargetMetric] = mapped_column(
        pg_enum(ForecastTargetMetric, "forecast_target_metric"),
        nullable=False,
    )
    granularity: Mapped[ForecastGranularity] = mapped_column(
        pg_enum(ForecastGranularity, "forecast_granularity"),
        nullable=False,
        server_default=ForecastGranularity.DAY.value,
    )
    horizon_periods: Mapped[int] = mapped_column(Integer, nullable=False)
    horizon_start: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    horizon_end: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    input_window_start: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    input_window_end: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    input_record_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    feature_definition_snapshot: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    random_seed: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    execution_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    is_backtest: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")


class Forecast(Base, TenantScopedMixin, TimestampMixin):
    """One predicted value, with its uncertainty interval and provenance."""

    __tablename__ = "forecasts"
    __table_args__ = (
        UniqueConstraint("forecast_run_id", "forecast_for", name="uq_forecasts"),
        Index("ix_forecasts_tenant_for", "tenant_id", "forecast_for"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    forecast_run_id: Mapped[UUID] = mapped_column(
        ForeignKey("forecast_runs.id", ondelete="CASCADE"),
        nullable=False,
    )
    forecast_for: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    horizon_step: Mapped[int] = mapped_column(Integer, nullable=False)
    predicted_value: Mapped[Decimal] = mapped_column(Numeric(16, 4), nullable=False)
    lower_bound: Mapped[Decimal | None] = mapped_column(
        Numeric(16, 4),
        nullable=True,
        doc="Lower bound of the uncertainty interval; NULL when it cannot be derived.",
    )
    upper_bound: Mapped[Decimal | None] = mapped_column(Numeric(16, 4), nullable=True)
    confidence_level: Mapped[Confidence | None] = mapped_column(nullable=True)
    baseline_value: Mapped[Decimal | None] = mapped_column(
        Numeric(16, 4),
        nullable=True,
        doc="A seasonal-naive baseline for the same step, for honest comparison.",
    )
    provenance: Mapped[ProvenanceKind] = mapped_column(
        pg_enum(ProvenanceKind, "provenance_kind"),
        nullable=False,
        server_default=ProvenanceKind.PREDICTED.value,
    )


class Anomaly(Base, TenantScopedMixin, TimestampMixin):
    """
    A detected deviation, with the method, baseline and threshold that found it.

    ``method_parameters`` and the baseline window are what make the finding
    explainable: a reader can see which rule fired, over what window, with what
    threshold.
    """

    __tablename__ = "anomalies"
    __table_args__ = (
        UniqueConstraint(
            "tenant_id",
            "subject_type",
            "subject_id",
            "metric_name",
            "occurred_at",
            "detection_method",
            name="uq_anomalies",
        ),
        Index("ix_anomalies_tenant_status", "tenant_id", "status"),
        Index("ix_anomalies_subject", "subject_type", "subject_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    detected_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    occurred_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    subject_type: Mapped[ScopeType] = mapped_column(
        pg_enum(ScopeType, "scope_type"),
        nullable=False,
    )
    subject_id: Mapped[UUID | None] = mapped_column(nullable=True)
    metric_name: Mapped[str] = mapped_column(Text, nullable=False)
    observed_value: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    expected_value: Mapped[Decimal | None] = mapped_column(Numeric(18, 6), nullable=True)
    deviation: Mapped[Decimal] = mapped_column(Numeric(18, 6), nullable=False)
    deviation_unit: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        server_default="SIGMA",
        doc="SIGMA, PERCENT or ABSOLUTE.",
    )
    detection_method: Mapped[AnomalyDetectionMethod] = mapped_column(
        pg_enum(AnomalyDetectionMethod, "anomaly_detection_method"),
        nullable=False,
    )
    method_parameters: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    baseline_window_start: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    baseline_window_end: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    score: Mapped[Score | None] = mapped_column(nullable=True)
    threshold: Mapped[Score | None] = mapped_column(nullable=True)
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        server_default=Severity.MEDIUM.value,
    )
    status: Mapped[AnomalyStatus] = mapped_column(
        pg_enum(AnomalyStatus, "anomaly_status"),
        nullable=False,
        server_default=AnomalyStatus.OPEN.value,
    )
    reviewed_by: Mapped[UUID | None] = mapped_column(nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    model_version_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ai_model_versions.id", ondelete="SET NULL"),
        nullable=True,
    )


class AnomalyEvent(Base, TenantScopedMixin, TimestampMixin):
    """A grouping of related anomalies into one triageable incident."""

    __tablename__ = "anomaly_events"
    __table_args__ = (Index("ix_anomaly_events_tenant_status", "tenant_id", "status"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    title: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[Severity] = mapped_column(
        pg_enum(Severity, "severity"),
        nullable=False,
        server_default=Severity.MEDIUM.value,
    )
    status: Mapped[AnomalyStatus] = mapped_column(
        pg_enum(AnomalyStatus, "anomaly_status"),
        nullable=False,
        server_default=AnomalyStatus.OPEN.value,
    )
    first_detected_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    anomaly_ids: Mapped[list[UUID] | None] = mapped_column(JSONB, nullable=True)
    affected_zones: Mapped[list[UUID] | None] = mapped_column(JSONB, nullable=True)
    root_cause_hypothesis: Mapped[str | None] = mapped_column(Text, nullable=True)
    assigned_to: Mapped[UUID | None] = mapped_column(nullable=True)
    resolution_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class WasteClassification(Base, TenantScopedMixin, TimestampMixin):
    """
    One image classification result.

    ``needs_review`` is set when confidence falls below the configured review
    threshold, which is how low-confidence predictions reach a human instead of
    being silently trusted.
    """

    __tablename__ = "waste_classifications"
    __table_args__ = (
        Index("ix_waste_classifications_tenant_status", "tenant_id", "review_status"),
        Index("ix_waste_classifications_bin", "bin_id"),
        CheckConstraint("confidence BETWEEN 0 AND 1", name="ck_waste_classifications_confidence"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    file_asset_id: Mapped[UUID] = mapped_column(nullable=False)
    bin_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("bins.id", ondelete="SET NULL"),
        nullable=True,
    )
    collection_event_id: Mapped[UUID | None] = mapped_column(nullable=True)
    waste_load_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_loads.id", ondelete="SET NULL"),
        nullable=True,
    )
    model_version_id: Mapped[UUID] = mapped_column(
        ForeignKey("ai_model_versions.id", ondelete="RESTRICT"),
        nullable=False,
    )
    predicted_category_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="SET NULL"),
        nullable=True,
    )
    predicted_material_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_materials.id", ondelete="SET NULL"),
        nullable=True,
    )
    confidence: Mapped[Confidence] = mapped_column(nullable=False)
    top_k: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Ranked alternatives with their scores.",
    )
    classification_method: Mapped[ClassificationMethod] = mapped_column(
        pg_enum(ClassificationMethod, "classification_method"),
        nullable=False,
        server_default=ClassificationMethod.CLASSICAL_CV.value,
    )
    inference_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    image_hash: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        doc="Deduplication and caching key for identical images.",
    )
    needs_review: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default="false")
    review_status: Mapped[ReviewStatus] = mapped_column(
        pg_enum(ReviewStatus, "review_status"),
        nullable=False,
        server_default=ReviewStatus.NOT_REQUIRED.value,
    )
    reviewed_by: Mapped[UUID | None] = mapped_column(nullable=True)
    reviewed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    corrected_category_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_categories.id", ondelete="SET NULL"),
        nullable=True,
    )
    corrected_material_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("waste_materials.id", ondelete="SET NULL"),
        nullable=True,
    )
    review_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    provenance: Mapped[ProvenanceKind] = mapped_column(
        pg_enum(ProvenanceKind, "provenance_kind"),
        nullable=False,
        server_default=ProvenanceKind.PREDICTED.value,
    )
    human_corrected_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class ClassificationFeedback(Base, TenantScopedMixin, TimestampMixin):
    """The closed loop: human judgement on a prediction, kept for retraining."""

    __tablename__ = "classification_feedback"
    __table_args__ = (
        Index("ix_classification_feedback_classification", "waste_classification_id"),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    waste_classification_id: Mapped[UUID] = mapped_column(
        ForeignKey("waste_classifications.id", ondelete="CASCADE"),
        nullable=False,
    )
    feedback_type: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="CORRECT, INCORRECT, RELABELLED or LOW_QUALITY_IMAGE.",
    )
    corrected_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    provided_by: Mapped[UUID | None] = mapped_column(nullable=True)
    provided_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
    used_in_training_dataset_id: Mapped[UUID | None] = mapped_column(
        ForeignKey("ml_datasets.id", ondelete="SET NULL"),
        nullable=True,
    )


class Recommendation(Base, TenantScopedMixin, TimestampMixin):
    """
    A decision-support artefact with mandatory evidence (BR-16).

    The CHECK constraint is the point: an evidence-free recommendation cannot be
    inserted, so the engine cannot produce advice nobody can audit.
    """

    __tablename__ = "recommendations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "recommendation_code", name="uq_recommendations_code"),
        Index("ix_recommendations_tenant_status", "tenant_id", "status"),
        CheckConstraint(
            "jsonb_array_length(evidence -> 'items') > 0",
            name="ck_recommendations_evidence",
        ),
    )

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    recommendation_code: Mapped[Code] = mapped_column(nullable=False)
    type: Mapped[RecommendationType] = mapped_column(
        pg_enum(RecommendationType, "recommendation_type"),
        nullable=False,
    )
    title: Mapped[ShortText] = mapped_column(nullable=False)
    description: Mapped[LongText | None] = mapped_column(nullable=True)
    priority: Mapped[PriorityLevel] = mapped_column(
        pg_enum(PriorityLevel, "priority_level"),
        nullable=False,
        server_default=PriorityLevel.NORMAL.value,
    )
    status: Mapped[RecommendationStatus] = mapped_column(
        pg_enum(RecommendationStatus, "recommendation_status"),
        nullable=False,
        server_default=RecommendationStatus.GENERATED.value,
    )
    confidence: Mapped[Confidence | None] = mapped_column(nullable=True)
    evidence: Mapped[dict[str, Any]] = mapped_column(
        JSONB,
        nullable=False,
        doc="Metric names, values, source windows and the ids of the rows consulted.",
    )
    source_metrics: Mapped[dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    generated_by: Mapped[UUID | None] = mapped_column(
        ForeignKey("ai_model_versions.id", ondelete="SET NULL"),
        nullable=True,
    )
    generator: Mapped[RecommendationGenerator] = mapped_column(
        pg_enum(RecommendationGenerator, "recommendation_generator"),
        nullable=False,
        server_default=RecommendationGenerator.RULE_ENGINE.value,
    )
    valid_until: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    estimated_impact: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc="Impact estimate, each value carrying a provenance label.",
    )
    actions: Mapped[dict[str, Any] | None] = mapped_column(
        JSONB,
        nullable=True,
        doc='Deep-link targets, e.g. "open the optimizer with these stops".',
    )
    executed_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    executed_reference_type: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_reference_id: Mapped[UUID | None] = mapped_column(nullable=True)
    expires_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class RecommendationFeedback(Base, TenantScopedMixin, TimestampMixin):
    """What a human decided about a recommendation, and why."""

    __tablename__ = "recommendation_feedback"
    __table_args__ = (Index("ix_recommendation_feedback_recommendation", "recommendation_id"),)

    id: Mapped[UUID] = mapped_column(primary_key=True, server_default=text("gen_random_uuid()"))
    recommendation_id: Mapped[UUID] = mapped_column(
        ForeignKey("recommendations.id", ondelete="CASCADE"),
        nullable=False,
    )
    user_id: Mapped[UUID | None] = mapped_column(nullable=True)
    feedback: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        doc="ACCEPTED, REJECTED, NOT_USEFUL or ALREADY_DONE.",
    )
    reason_code: Mapped[str | None] = mapped_column(Text, nullable=True)
    comment: Mapped[str | None] = mapped_column(Text, nullable=True)
    provided_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=text("now()"),
    )
