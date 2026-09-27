"""
Closed enumerations shared by the ORM models.

Every enumeration here is a **closed set that a business rule depends on**
(``docs/database/erd.md`` §1: "Native PostgreSQL ``ENUM`` types for closed sets
that must honour BR-xx rules"). Storing the value rather than the member name
keeps the database readable by a DBA and keeps the wire representation stable if
a member is renamed in Python.

``pg_enum`` is the single place that decision is made, so no model can
accidentally persist member names.
"""

from __future__ import annotations

from enum import StrEnum

from sqlalchemy import Enum
from sqlalchemy.types import TypeEngine

__all__ = [
    "pg_enum",
    "TenantType",
    "TenantStatus",
    "UserStatus",
    "PermissionScope",
    "ActorType",
    "EventOutcome",
    "SettingValueType",
    "ZoneType",
    "ServiceFrequency",
    "WasteDisposalRoute",
    "BinStatus",
    "SensorType",
    "SensorStatus",
    "TelemetrySource",
    "Severity",
    "AlertStatus",
    "BinAlertType",
    "CollectionRequestSource",
    "CollectionRequestStatus",
    "CollectionTaskStatus",
    "TaskFailureReason",
    "CollectionEventType",
    "ContaminationLevel",
    "CertificationSource",
    "SyncState",
    "FuelType",
    "VehicleStatus",
    "DriverStatus",
    "AssignmentStatus",
    "RouteStatus",
    "StopStatus",
    "OptimizationStatus",
    "BaselineType",
    "FacilityCategory",
    "FacilityStatus",
    "OperatingEntity",
    "LoadOriginType",
    "LoadStatus",
    "CompositionSource",
    "RecoveryType",
    "TreatmentType",
    "DisposalType",
    "EmissionActivityType",
    "CarbonEstimateType",
    "ScopeType",
    "PeriodType",
    "ProvenanceKind",
    "ModelType",
    "ModelVersionStatus",
    "EvaluationType",
    "ForecastTargetMetric",
    "ForecastGranularity",
    "RunStatus",
    "AnomalyDetectionMethod",
    "AnomalyStatus",
    "ClassificationMethod",
    "ReviewStatus",
    "RecommendationType",
    "RecommendationStatus",
    "RecommendationGenerator",
    "RecommendationFeedback",
    "PriorityLevel",
    "NotificationType",
    "NotificationChannel",
    "NotificationStatus",
    "DigestFrequency",
    "ReportType",
    "ReportStatus",
    "ExportFormat",
    "FileOwnerType",
    "ScanStatus",
    "IntegrationType",
    "WebhookDeliveryStatus",
    "JobStatus",
]


def pg_enum(enum_cls: type[StrEnum], name: str) -> TypeEngine:
    """
    A native PostgreSQL ``ENUM`` column type bound to ``enum_cls``.

    ``values_callable`` makes the persisted value the *member value* rather than
    the member name. Without it, renaming a Python member would silently change
    the stored representation and orphan every existing row.
    """
    return Enum(
        enum_cls,
        name=name,
        values_callable=lambda members: [member.value for member in members],
        native_enum=True,
        create_type=True,
    )


# ---------------------------------------------------------------------------
# Identity and tenancy
# ---------------------------------------------------------------------------
class TenantType(StrEnum):
    MUNICIPALITY = "MUNICIPALITY"
    PRIVATE_HAULER = "PRIVATE_HAULER"
    RESIDENTIAL_CAMPUS = "RESIDENTIAL_CAMPUS"
    COMMERCIAL = "COMMERCIAL"
    INDUSTRIAL = "INDUSTRIAL"
    GOVERNMENT_AGENCY = "GOVERNMENT_AGENCY"


class TenantStatus(StrEnum):
    TRIAL = "TRIAL"
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    CANCELLED = "CANCELLED"


class UserStatus(StrEnum):
    ACTIVE = "ACTIVE"
    INVITED = "INVITED"
    SUSPENDED = "SUSPENDED"
    LOCKED = "LOCKED"
    DISABLED = "DISABLED"


class PermissionScope(StrEnum):
    """A permission is either tenant-scoped or platform-scoped; never both."""

    TENANT = "TENANT"
    PLATFORM = "PLATFORM"


class ActorType(StrEnum):
    USER = "USER"
    SYSTEM = "SYSTEM"
    DEVICE = "DEVICE"
    API_KEY = "API_KEY"
    AI = "AI"


class EventOutcome(StrEnum):
    SUCCESS = "SUCCESS"
    FAILURE = "FAILURE"
    DENIED = "DENIED"


class SettingValueType(StrEnum):
    STRING = "STRING"
    NUMBER = "NUMBER"
    BOOLEAN = "BOOLEAN"
    JSON = "JSON"
    DURATION = "DURATION"


# ---------------------------------------------------------------------------
# Geography
# ---------------------------------------------------------------------------
class ZoneType(StrEnum):
    WARD = "WARD"
    DISTRICT = "DISTRICT"
    CAMPUS_SECTOR = "CAMPUS_SECTOR"
    BUILDING = "BUILDING"
    INDUSTRIAL_BLOCK = "INDUSTRIAL_BLOCK"


class ServiceFrequency(StrEnum):
    DAILY = "DAILY"
    ALTERNATE_DAY = "ALTERNATE_DAY"
    TWICE_WEEKLY = "TWICE_WEEKLY"
    WEEKLY = "WEEKLY"
    ON_DEMAND = "ON_DEMAND"


# ---------------------------------------------------------------------------
# Waste taxonomy
# ---------------------------------------------------------------------------
class WasteDisposalRoute(StrEnum):
    RECYCLE = "RECYCLE"
    COMPOST = "COMPOST"
    RECOVER_ENERGY = "RECOVER_ENERGY"
    TREAT = "TREAT"
    LANDFILL = "LANDFILL"
    SPECIAL_HANDLING = "SPECIAL_HANDLING"


# ---------------------------------------------------------------------------
# Bins, sensors, telemetry
# ---------------------------------------------------------------------------
class BinStatus(StrEnum):
    ACTIVE = "ACTIVE"
    FULL = "FULL"
    MAINTENANCE = "MAINTENANCE"
    DAMAGED = "DAMAGED"
    DECOMMISSIONED = "DECOMMISSIONED"


class SensorType(StrEnum):
    FILL_LEVEL = "FILL_LEVEL"
    WEIGHT = "WEIGHT"
    TEMPERATURE = "TEMPERATURE"
    COMBINED = "COMBINED"
    GAS = "GAS"
    LID_STATE = "LID_STATE"


class SensorStatus(StrEnum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    FAULTY = "FAULTY"
    MAINTENANCE = "MAINTENANCE"


class TelemetrySource(StrEnum):
    SENSOR = "SENSOR"
    SIMULATOR = "SIMULATOR"
    MANUAL = "MANUAL"
    IMPORT = "IMPORT"


class Severity(StrEnum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    SUPPRESSED = "SUPPRESSED"


class BinAlertType(StrEnum):
    OVERFLOW = "OVERFLOW"
    OVERFLOW_RISK = "OVERFLOW_RISK"
    SENSOR_OFFLINE = "SENSOR_OFFLINE"
    LOW_BATTERY = "LOW_BATTERY"
    TEMPERATURE_HIGH = "TEMPERATURE_HIGH"
    FIRE_RISK = "FIRE_RISK"
    ABNORMAL_FILL = "ABNORMAL_FILL"
    SENSOR_FAULT = "SENSOR_FAULT"


# ---------------------------------------------------------------------------
# Collections
# ---------------------------------------------------------------------------
class CollectionRequestSource(StrEnum):
    MANUAL = "MANUAL"
    CITIZEN = "CITIZEN"
    SENSOR_ALERT = "SENSOR_ALERT"
    SCHEDULED = "SCHEDULED"
    COMPLAINT = "COMPLAINT"
    AI_RECOMMENDATION = "AI_RECOMMENDATION"


class CollectionRequestStatus(StrEnum):
    PENDING = "PENDING"
    SCHEDULED = "SCHEDULED"
    IN_PROGRESS = "IN_PROGRESS"
    FULFILLED = "FULFILLED"
    REJECTED = "REJECTED"
    CANCELLED = "CANCELLED"


class CollectionTaskStatus(StrEnum):
    """The collection task lifecycle (``domain-model.md`` §4.2)."""

    PLANNED = "PLANNED"
    ASSIGNED = "ASSIGNED"
    DISPATCHED = "DISPATCHED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    PARTIALLY_COMPLETED = "PARTIALLY_COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"
    CANCELLED = "CANCELLED"
    OVERDUE = "OVERDUE"


class TaskFailureReason(StrEnum):
    BIN_MISSING = "BIN_MISSING"
    ACCESS_DENIED = "ACCESS_DENIED"
    VEHICLE_BREAKDOWN = "VEHICLE_BREAKDOWN"
    BIN_DAMAGED = "BIN_DAMAGED"
    CONTAMINATED = "CONTAMINATED"
    TRAFFIC = "TRAFFIC"
    WEATHER = "WEATHER"
    OTHER = "OTHER"


class CollectionEventType(StrEnum):
    COLLECTED = "COLLECTED"
    PARTIAL = "PARTIAL"
    SKIPPED = "SKIPPED"
    CONTAMINATED = "CONTAMINATED"
    OVERFLOW_FOUND = "OVERFLOW_FOUND"
    BIN_MISSING = "BIN_MISSING"
    ACCESS_DENIED = "ACCESS_DENIED"


class ContaminationLevel(StrEnum):
    NONE = "NONE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


class CertificationSource(StrEnum):
    MEASURED_ONBOARD = "MEASURED_ONBOARD"
    MANUAL_ENTRY = "MANUAL_ENTRY"
    WEIGHBRIDGE = "WEIGHBRIDGE"
    ESTIMATED = "ESTIMATED"


class SyncState(StrEnum):
    PENDING = "PENDING"
    SYNCED = "SYNCED"
    CONFLICT = "CONFLICT"


# ---------------------------------------------------------------------------
# Fleet, workforce, routing
# ---------------------------------------------------------------------------
class FuelType(StrEnum):
    DIESEL = "DIESEL"
    PETROL = "PETROL"
    CNG = "CNG"
    ELECTRIC = "ELECTRIC"
    HYBRID = "HYBRID"
    HUMAN_POWERED = "HUMAN_POWERED"


class VehicleStatus(StrEnum):
    AVAILABLE = "AVAILABLE"
    ASSIGNED = "ASSIGNED"
    IN_SERVICE = "IN_SERVICE"
    MAINTENANCE = "MAINTENANCE"
    OUT_OF_SERVICE = "OUT_OF_SERVICE"
    RETIRED = "RETIRED"
    DECOMMISSIONED = "DECOMMISSIONED"


class DriverStatus(StrEnum):
    ACTIVE = "ACTIVE"
    ON_LEAVE = "ON_LEAVE"
    SUSPENDED = "SUSPENDED"
    INACTIVE = "INACTIVE"


class AssignmentStatus(StrEnum):
    SCHEDULED = "SCHEDULED"
    ACTIVE = "ACTIVE"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    NO_SHOW = "NO_SHOW"


class RouteStatus(StrEnum):
    DRAFT = "DRAFT"
    PLANNED = "PLANNED"
    DISPATCHED = "DISPATCHED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    CANCELLED = "CANCELLED"
    ARCHIVED = "ARCHIVED"


class StopStatus(StrEnum):
    PLANNED = "PLANNED"
    ARRIVED = "ARRIVED"
    COMPLETED = "COMPLETED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"


class OptimizationStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    INFEASIBLE = "INFEASIBLE"
    TIMEOUT = "TIMEOUT"


class BaselineType(StrEnum):
    PREVIOUS_ROUTE = "PREVIOUS_ROUTE"
    MANUAL_PLAN = "MANUAL_PLAN"
    NAIVE_PLAN = "NAIVE_PLAN"
    ALTERNATE_OPTIMIZATION = "ALTERNATE_OPTIMIZATION"


# ---------------------------------------------------------------------------
# Facilities, loads, recovery
# ---------------------------------------------------------------------------
class FacilityCategory(StrEnum):
    TRANSFER_STATION = "TRANSFER_STATION"
    MATERIAL_RECOVERY = "MATERIAL_RECOVERY"
    RECYCLING_CENTER = "RECYCLING_CENTER"
    COMPOSTING = "COMPOSTING"
    TREATMENT_PLANT = "TREATMENT_PLANT"
    WASTE_TO_ENERGY = "WASTE_TO_ENERGY"
    LANDFILL = "LANDFILL"
    SPECIALIZED = "SPECIALIZED"


class FacilityStatus(StrEnum):
    OPERATIONAL = "OPERATIONAL"
    LIMITED = "LIMITED"
    MAINTENANCE = "MAINTENANCE"
    CLOSED = "CLOSED"
    DECOMMISSIONED = "DECOMMISSIONED"


class OperatingEntity(StrEnum):
    TENANT = "TENANT"
    THIRD_PARTY = "THIRD_PARTY"


class LoadOriginType(StrEnum):
    COLLECTION = "COLLECTION"
    TRANSFER = "TRANSFER"
    DIRECT_DELIVERY = "DIRECT_DELIVERY"
    FACILITY_INTAKE = "FACILITY_INTAKE"


class LoadStatus(StrEnum):
    FORMING = "FORMING"
    IN_TRANSIT = "IN_TRANSIT"
    RECEIVED = "RECEIVED"
    PROCESSING = "PROCESSING"
    CLOSED = "CLOSED"
    REJECTED = "REJECTED"


class CompositionSource(StrEnum):
    MEASURED = "MEASURED"
    ESTIMATED_VISUAL = "ESTIMATED_VISUAL"
    SORTING_ANALYSIS = "SORTING_ANALYSIS"
    DEFAULT_MIX = "DEFAULT_MIX"


class RecoveryType(StrEnum):
    RECYCLED = "RECYCLED"
    REUSED = "REUSED"
    ENERGY_RECOVERY = "ENERGY_RECOVERY"
    MATERIAL_RECOVERY = "MATERIAL_RECOVERY"
    OTHER_RECOVERY = "OTHER_RECOVERY"


class TreatmentType(StrEnum):
    INCINERATION_WITH_RECOVERY = "INCINERATION_WITH_RECOVERY"
    ANAEROBIC_DIGESTION = "ANAEROBIC_DIGESTION"
    CHEMICAL = "CHEMICAL"
    STERILIZATION = "STERILIZATION"
    AUTOCLAVE = "AUTOCLAVE"


class DisposalType(StrEnum):
    LANDFILL = "LANDFILL"
    INCINERATION_NO_RECOVERY = "INCINERATION_NO_RECOVERY"
    OPEN_DUMP = "OPEN_DUMP"
    SPECIAL_HANDLING = "SPECIAL_HANDLING"


# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
class EmissionActivityType(StrEnum):
    FUEL_COMBUSTION = "FUEL_COMBUSTION"
    ELECTRICITY = "ELECTRICITY"
    TRANSPORT = "TRANSPORT"
    WASTE_TREATMENT = "WASTE_TREATMENT"
    LANDFILL_AVOIDED = "LANDFILL_AVOIDED"
    MATERIAL_RECOVERY = "MATERIAL_RECOVERY"
    COMPOSTING = "COMPOSTING"


class CarbonEstimateType(StrEnum):
    COLLECTION_TRANSPORT = "COLLECTION_TRANSPORT"
    FACILITY_PROCESSING = "FACILITY_PROCESSING"
    AVOIDED_DISPOSAL = "AVOIDED_DISPOSAL"
    RECYCLING_OFFSET = "RECYCLING_OFFSET"
    TOTAL_OPERATION = "TOTAL_OPERATION"


class ScopeType(StrEnum):
    TENANT = "TENANT"
    ZONE = "ZONE"
    FACILITY = "FACILITY"
    CATEGORY = "CATEGORY"
    BIN = "BIN"
    ROUTE = "ROUTE"
    VEHICLE = "VEHICLE"


class PeriodType(StrEnum):
    DAY = "DAY"
    WEEK = "WEEK"
    MONTH = "MONTH"
    QUARTER = "QUARTER"
    YEAR = "YEAR"


class ProvenanceKind(StrEnum):
    """Every non-measured value carries one of these (ADR-0013)."""

    MEASURED = "MEASURED"
    ESTIMATED = "ESTIMATED"
    PREDICTED = "PREDICTED"
    SIMULATED = "SIMULATED"
    USER_ENTERED = "USER_ENTERED"
    DERIVED = "DERIVED"


# ---------------------------------------------------------------------------
# Intelligence
# ---------------------------------------------------------------------------
class ModelType(StrEnum):
    WASTE_CLASSIFICATION = "WASTE_CLASSIFICATION"
    FILL_FORECAST = "FILL_FORECAST"
    VOLUME_FORECAST = "VOLUME_FORECAST"
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    OVERFLOW_RISK = "OVERFLOW_RISK"


class ModelVersionStatus(StrEnum):
    CANDIDATE = "CANDIDATE"
    ACTIVE = "ACTIVE"
    RETIRED = "RETIRED"
    FAILED = "FAILED"


class EvaluationType(StrEnum):
    TRAINING = "TRAINING"
    VALIDATION = "VALIDATION"
    TEST = "TEST"
    HOLDOUT = "HOLDOUT"
    SYNTHETIC_BENCH = "SYNTHETIC_BENCH"


class ForecastTargetMetric(StrEnum):
    WASTE_VOLUME_L = "WASTE_VOLUME_L"
    WASTE_WEIGHT_KG = "WASTE_WEIGHT_KG"
    BIN_FILL_PCT = "BIN_FILL_PCT"
    COLLECTION_COUNT = "COLLECTION_COUNT"


class ForecastGranularity(StrEnum):
    HOUR = "HOUR"
    DAY = "DAY"
    WEEK = "WEEK"
    MONTH = "MONTH"


class RunStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class AnomalyDetectionMethod(StrEnum):
    ZSCORE = "ZSCORE"
    IQR = "IQR"
    MOVING_BASELINE = "MOVING_BASELINE"
    ISOLATION_FOREST = "ISOLATION_FOREST"


class AnomalyStatus(StrEnum):
    OPEN = "OPEN"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class ClassificationMethod(StrEnum):
    CLASSICAL_CV = "CLASSICAL_CV"
    DEEP_LEARNING = "DEEP_LEARNING"
    MANUAL = "MANUAL"


class ReviewStatus(StrEnum):
    NOT_REQUIRED = "NOT_REQUIRED"
    PENDING = "PENDING"
    CONFIRMED = "CONFIRMED"
    CORRECTED = "CORRECTED"


class RecommendationType(StrEnum):
    COLLECTION_PRIORITY = "COLLECTION_PRIORITY"
    ROUTE_OPTIMIZATION = "ROUTE_OPTIMIZATION"
    OVERFLOW_PREVENTION = "OVERFLOW_PREVENTION"
    MAINTENANCE = "MAINTENANCE"
    FACILITY_REBALANCE = "FACILITY_REBALANCE"
    CAPACITY_PLANNING = "CAPACITY_PLANNING"
    ANOMALY_INVESTIGATION = "ANOMALY_INVESTIGATION"
    FUEL_REDUCTION = "FUEL_REDUCTION"


class RecommendationStatus(StrEnum):
    GENERATED = "GENERATED"
    PRESENTED = "PRESENTED"
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    EXECUTED = "EXECUTED"
    EXPIRED = "EXPIRED"


class RecommendationGenerator(StrEnum):
    RULE_ENGINE = "RULE_ENGINE"
    STATISTICAL_MODEL = "STATISTICAL_MODEL"
    ASSISTANT = "ASSISTANT"


class RecommendationFeedback(StrEnum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"
    NOT_USEFUL = "NOT_USEFUL"
    ALREADY_DONE = "ALREADY_DONE"


class PriorityLevel(StrEnum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    URGENT = "URGENT"


# ---------------------------------------------------------------------------
# Notifications, reporting, integrations
# ---------------------------------------------------------------------------
class NotificationType(StrEnum):
    BIN_OVERFLOW = "BIN_OVERFLOW"
    OVERFLOW_RISK = "OVERFLOW_RISK"
    SENSOR_OFFLINE = "SENSOR_OFFLINE"
    LOW_BATTERY = "LOW_BATTERY"
    COLLECTION_OVERDUE = "COLLECTION_OVERDUE"
    COLLECTION_MISSED = "COLLECTION_MISSED"
    ROUTE_DELAY = "ROUTE_DELAY"
    ANOMALY_DETECTED = "ANOMALY_DETECTED"
    REPORT_READY = "REPORT_READY"
    SYSTEM = "SYSTEM"


class NotificationChannel(StrEnum):
    IN_APP = "IN_APP"
    EMAIL = "EMAIL"
    PUSH = "PUSH"
    WEBHOOK = "WEBHOOK"


class NotificationStatus(StrEnum):
    PENDING = "PENDING"
    SENT = "SENT"
    FAILED = "FAILED"
    READ = "READ"
    DISMISSED = "DISMISSED"


class DigestFrequency(StrEnum):
    INSTANT = "INSTANT"
    HOURLY = "HOURLY"
    DAILY = "DAILY"
    WEEKLY = "WEEKLY"


class ReportType(StrEnum):
    OPERATIONAL = "OPERATIONAL"
    WASTE_GENERATION = "WASTE_GENERATION"
    COLLECTION_PERFORMANCE = "COLLECTION_PERFORMANCE"
    RECYCLING = "RECYCLING"
    ENVIRONMENTAL = "ENVIRONMENTAL"
    VEHICLE = "VEHICLE"
    FACILITY = "FACILITY"
    EXECUTIVE_SUMMARY = "EXECUTIVE_SUMMARY"


class ReportStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ExportFormat(StrEnum):
    CSV = "CSV"
    JSON = "JSON"


class FileOwnerType(StrEnum):
    BIN = "BIN"
    COLLECTION_EVENT = "COLLECTION_EVENT"
    WASTE_LOAD = "WASTE_LOAD"
    CLASSIFICATION = "CLASSIFICATION"
    REPORT_RUN = "REPORT_RUN"
    ORGANIZATION = "ORGANIZATION"
    MAINTENANCE = "MAINTENANCE"
    USER_AVATAR = "USER_AVATAR"


class ScanStatus(StrEnum):
    PENDING = "PENDING"
    CLEAN = "CLEAN"
    REJECTED = "REJECTED"
    SKIPPED = "SKIPPED"


class IntegrationType(StrEnum):
    ROUTING = "ROUTING"
    WEATHER = "WEATHER"
    EMAIL = "EMAIL"
    SMS = "SMS"
    IOT_GATEWAY = "IOT_GATEWAY"
    FLEET_TRACKING = "FLEET_TRACKING"
    MUNICIPAL_SYSTEM = "MUNICIPAL_SYSTEM"
    STORAGE = "STORAGE"
    LLM = "LLM"


class WebhookDeliveryStatus(StrEnum):
    PENDING = "PENDING"
    DELIVERED = "DELIVERED"
    FAILED = "FAILED"
    DEAD_LETTER = "DEAD_LETTER"


class JobStatus(StrEnum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    SKIPPED_DUPLICATE = "SKIPPED_DUPLICATE"
