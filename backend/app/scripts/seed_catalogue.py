"""
Idempotent seeding of the platform-wide reference data.

This module is called by the migration that creates the schema, and again by
``python -m app.scripts.seed`` during bootstrap. Being idempotent is what makes
both safe: every insert resolves to ``ON CONFLICT DO NOTHING``, so re-running a
migration or a seed converges on the same state instead of failing.

Identifiers are derived with ``uuid5`` from a fixed namespace and the row's
natural key. That is not decoration: the role-permission join table needs the
ids of rows that may already exist, and a random id would create a duplicate
role on every run.

What is *not* here: tenant data, bins, telemetry, KPI values. Those come from
``app.scripts.seed`` (a development profile, explicitly labelled) or from the
running system.
"""

from __future__ import annotations

import json
import uuid
from typing import Any, cast

from sqlalchemy import column, table, text
from sqlalchemy.dialects.postgresql import insert as pg_insert

from app.authorization.permissions import PERMISSIONS
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.scripts.baseline_data import (
    AI_MODELS,
    EMISSION_FACTORS,
    INTEGRATIONS,
    NOTIFICATION_TEMPLATES,
    REPORT_DEFINITIONS,
    RETENTION_POLICIES,
    WASTE_CATEGORIES,
    WASTE_MATERIALS,
)

__all__ = ["PLATFORM_NAMESPACE", "PLATFORM_TENANT_ID", "deterministic_id", "seed_reference_data"]

#: The namespace every seeded identifier is derived from. Fixed so that the same
#: logical row always receives the same UUID, in every environment.
PLATFORM_NAMESPACE = uuid.UUID("6f0b4a1e-2f6d-4f6a-9b7e-1c2d3e4f5a6b")

#: The identifier of the platform tenant that owns the shared baseline (system
#: roles, platform users, platform audit records). It matches
#: ``app.db.base.PLATFORM_SCOPE_ID`` so a platform-scoped row and a
#: platform-tenant row are the same thing.
PLATFORM_TENANT_ID = uuid.UUID("00000000-0000-0000-0000-000000000000")


def deterministic_id(*parts: object) -> uuid.UUID:
    """A stable UUID derived from ``parts`` — the same input always yields it."""
    key = "|".join(str(part) for part in parts)
    return uuid.uuid5(PLATFORM_NAMESPACE, key)


def _json(value: Any) -> Any:
    """
    Serialise a JSON column value.

    The lightweight table objects used for seeding are untyped, so psycopg2
    receives the Python object directly and cannot adapt a ``dict``. Encoding it
    explicitly keeps the seed independent of the ORM type registry.
    """
    if isinstance(value, (dict, list)):
        return json.dumps(value)
    return value


def _upsert(connection: Any, target: Any, rows: list[dict[str, Any]]) -> int:
    """Insert ``rows`` ignoring conflicts, in one statement per batch."""
    if not rows:
        return 0
    statement = pg_insert(target).on_conflict_do_nothing()
    connection.execute(statement, rows)
    return len(rows)


def seed_reference_data(connection: Any) -> dict[str, int]:
    """
    Seed every global reference table plus the platform tenant and its roles.

    Safe to call repeatedly. Returns the number of rows *considered*, which the
    migration logs so an operator can see that seeding actually ran.
    """
    counts: dict[str, int] = {}

    # -- Platform tenant ----------------------------------------------------
    tenants = table(
        "tenants",
        column("id"),
        column("name"),
        column("slug"),
        column("type"),
        column("status"),
        column("timezone"),
        column("locale"),
        column("plan"),
    )
    counts["tenants"] = _upsert(
        connection,
        tenants,
        [
            {
                "id": str(PLATFORM_TENANT_ID),
                "name": "EcoMind Platform",
                "slug": "ecomind-platform",
                "type": "GOVERNMENT_AGENCY",
                "status": "ACTIVE",
                "timezone": "UTC",
                "locale": "en-IN",
                "plan": "platform",
            }
        ],
    )

    # -- Permission catalogue ----------------------------------------------
    permissions = table(
        "permissions",
        column("id"),
        column("code"),
        column("resource"),
        column("action"),
        column("scope"),
        column("description"),
        column("is_dangerous"),
    )
    counts["permissions"] = _upsert(
        connection,
        permissions,
        [
            {
                "id": str(deterministic_id("permission", code)),
                "code": code,
                "resource": definition.resource,
                "action": definition.action,
                "scope": definition.scope.value,
                "description": definition.description,
                "is_dangerous": definition.is_dangerous,
            }
            for code, definition in PERMISSIONS.items()
        ],
    )

    # -- System roles, in the platform tenant -------------------------------
    roles = table(
        "roles",
        column("id"),
        column("tenant_id"),
        column("code"),
        column("name"),
        column("description"),
        column("is_system"),
        column("is_default"),
        column("level"),
    )
    role_rows = [
        {
            "id": str(deterministic_id("role", role.code)),
            "tenant_id": str(PLATFORM_TENANT_ID),
            "code": role.code,
            "name": role.name,
            "description": role.description,
            "is_system": True,
            "is_default": False,
            "level": role.level,
        }
        for role in ROLE_DEFINITIONS.values()
    ]
    counts["roles"] = _upsert(connection, roles, role_rows)

    # -- Role → permission grants -------------------------------------------
    role_permissions = table(
        "role_permissions",
        column("tenant_id"),
        column("role_id"),
        column("permission_id"),
        column("granted_at"),
    )
    grant_rows = [
        {
            "tenant_id": str(PLATFORM_TENANT_ID),
            "role_id": str(deterministic_id("role", role.code)),
            "permission_id": str(deterministic_id("permission", code)),
            "granted_at": "now()",
        }
        for role in ROLE_DEFINITIONS.values()
        for code in sorted(role.permissions)
    ]
    counts["role_permissions"] = _upsert(connection, role_permissions, grant_rows)

    # -- Waste taxonomy -----------------------------------------------------
    categories = table(
        "waste_categories",
        column("id"),
        column("code"),
        column("name"),
        column("description"),
        column("is_recyclable"),
        column("is_hazardous"),
        column("is_organic"),
        column("is_compostable"),
        column("disposal_route"),
        column("sensitivity_weight"),
        column("icon"),
        column("colour"),
        column("is_system"),
    )
    counts["waste_categories"] = _upsert(
        connection,
        categories,
        [
            {
                "id": str(deterministic_id("waste_category", str(row["code"]))),
                "is_system": True,
                **{key: value for key, value in row.items() if key != "is_system"},
            }
            for row in WASTE_CATEGORIES
        ],
    )

    materials = table(
        "waste_materials",
        column("id"),
        column("category_id"),
        column("code"),
        column("name"),
        column("recyclability_grade"),
        column("unit"),
        column("density_kg_per_l"),
    )
    counts["waste_materials"] = _upsert(
        connection,
        materials,
        [
            {
                "id": str(deterministic_id("waste_material", str(row["code"]))),
                "category_id": str(deterministic_id("waste_category", str(row["category"]))),
                "code": row["code"],
                "name": row["name"],
                "recyclability_grade": row["recyclability_grade"],
                "unit": row["unit"],
                "density_kg_per_l": row["density_kg_per_l"],
            }
            for row in WASTE_MATERIALS
        ],
    )

    # -- Emission factors ---------------------------------------------------
    factors = table(
        "emission_factors",
        column("id"),
        column("factor_code"),
        column("name"),
        column("activity_type"),
        column("activity_unit"),
        column("factor_value"),
        column("result_unit"),
        column("source"),
        column("source_url"),
        column("geography"),
        column("methodology"),
        column("effective_from"),
        column("is_active"),
    )
    counts["emission_factors"] = _upsert(
        connection,
        factors,
        [
            {
                "id": str(deterministic_id("emission_factor", str(row["factor_code"]))),
                "is_active": True,
                **{key: value for key, value in row.items() if key != "is_active"},
            }
            for row in EMISSION_FACTORS
        ],
    )

    # -- Model registry -----------------------------------------------------
    models = table(
        "ai_models",
        column("id"),
        column("code"),
        column("name"),
        column("model_type"),
        column("task_description"),
        column("is_system"),
        column("status"),
    )
    model_rows = [
        {
            "id": str(deterministic_id("ai_model", str(model["code"]))),
            "code": model["code"],
            "name": model["name"],
            "model_type": model["model_type"],
            "task_description": model["task_description"],
            "is_system": True,
            "status": "ACTIVE",
        }
        for model in AI_MODELS
    ]
    counts["ai_models"] = _upsert(connection, models, model_rows)

    versions = table(
        "ai_model_versions",
        column("id"),
        column("model_id"),
        column("version"),
        column("status"),
        column("algorithm_family"),
        column("framework"),
        column("framework_version"),
        column("hyperparameters"),
        column("feature_definition"),
        column("notes"),
    )
    version_rows = [
        {
            "id": str(
                deterministic_id("ai_model_version", str(model["code"]), str(version["version"]))
            ),
            "model_id": str(deterministic_id("ai_model", str(model["code"]))),
            # Seeded as CANDIDATE: a version becomes ACTIVE only through an
            # evaluation run that records real metrics against a named dataset.
            "status": "CANDIDATE",
            "version": version["version"],
            "algorithm_family": version["algorithm_family"],
            "framework": version.get("framework"),
            "framework_version": None,
            "hyperparameters": _json(version.get("hyperparameters")),
            "feature_definition": _json(version["feature_definition"]),
            "notes": version.get("notes"),
        }
        for model in AI_MODELS
        for version in cast("tuple[dict[str, object], ...]", model["versions"])
    ]
    counts["ai_model_versions"] = _upsert(connection, versions, version_rows)

    # -- Reporting, notifications, integrations, retention -------------------
    report_definitions = table(
        "report_definitions",
        column("id"),
        column("code"),
        column("name"),
        column("description"),
        column("report_type"),
        column("parameter_schema"),
        column("data_provider"),
        column("is_system"),
        column("status"),
    )
    counts["report_definitions"] = _upsert(
        connection,
        report_definitions,
        [
            {
                "id": str(deterministic_id("report_definition", str(row["code"]))),
                "code": row["code"],
                "name": row["name"],
                "description": row["description"],
                "report_type": row["report_type"],
                "parameter_schema": _json(row["parameter_schema"]),
                "data_provider": row["data_provider"],
                "is_system": True,
                "status": "ACTIVE",
            }
            for row in REPORT_DEFINITIONS
        ],
    )

    templates = table(
        "notification_templates",
        column("id"),
        column("notification_type"),
        column("channel"),
        column("locale"),
        column("subject_template"),
        column("body_template"),
        column("variables"),
        column("is_system"),
    )
    counts["notification_templates"] = _upsert(
        connection,
        templates,
        [
            {
                "id": str(
                    deterministic_id(
                        "notification_template",
                        str(row["notification_type"]),
                        str(row["channel"]),
                        "en-IN",
                    )
                ),
                "locale": "en-IN",
                "is_system": True,
                **{
                    key: _json(value)
                    for key, value in row.items()
                    if key not in {"locale", "is_system"}
                },
            }
            for row in NOTIFICATION_TEMPLATES
        ],
    )

    integrations = table(
        "integrations",
        column("id"),
        column("code"),
        column("name"),
        column("integration_type"),
        column("adapter_class"),
        column("configuration"),
        column("is_enabled"),
        column("status"),
    )
    counts["integrations"] = _upsert(
        connection,
        integrations,
        [
            {
                "id": str(deterministic_id("integration", str(row["code"]))),
                "code": row["code"],
                "name": row["name"],
                "integration_type": row["integration_type"],
                "adapter_class": row["adapter_class"],
                "configuration": _json(row["configuration"]),
                "is_enabled": row["is_enabled"],
                "status": "ACTIVE",
            }
            for row in INTEGRATIONS
        ],
    )

    retention = table(
        "data_retention_policies",
        column("id"),
        column("data_class"),
        column("retention_days"),
        column("archive_before_delete"),
        column("description"),
    )
    counts["data_retention_policies"] = _upsert(
        connection,
        retention,
        [
            {
                "id": str(deterministic_id("data_retention_policy", str(row["data_class"]))),
                "data_class": row["data_class"],
                "retention_days": row["retention_days"],
                "archive_before_delete": row["archive_before_delete"],
                "description": row["description"],
            }
            for row in RETENTION_POLICIES
        ],
    )

    return counts


#: The unified processing-outcome view (``erd.md`` §7.8). Created here rather
#: than in the model layer because it is a database object, not an entity.
PROCESSING_OUTCOMES_VIEW = """
CREATE OR REPLACE VIEW v_processing_outcomes AS
SELECT r.id, r.tenant_id, r.waste_load_id, r.facility_id, r.waste_category_id,
       r.waste_material_id, r.occurred_at, r.input_weight_kg, r.output_weight_kg,
       r.recovery_rate, r.process_method, r.batch_reference,
       r.recorded_by_user_id, r.provenance, r.notes,
       'RECOVERY'::text AS outcome_family,
       r.recovery_type::text AS outcome_type
  FROM recovery_events r
UNION ALL
SELECT c.id, c.tenant_id, c.waste_load_id, c.facility_id, c.waste_category_id,
       c.waste_material_id, c.occurred_at, c.input_weight_kg, c.output_weight_kg,
       c.recovery_rate, c.process_method, c.batch_reference,
       c.recorded_by_user_id, c.provenance, c.notes,
       'COMPOSTING'::text AS outcome_family,
       c.compost_grade::text AS outcome_type
  FROM composting_events c
UNION ALL
SELECT t.id, t.tenant_id, t.waste_load_id, t.facility_id, t.waste_category_id,
       t.waste_material_id, t.occurred_at, t.input_weight_kg, t.output_weight_kg,
       t.recovery_rate, t.process_method, t.batch_reference,
       t.recorded_by_user_id, t.provenance, t.notes,
       'TREATMENT'::text AS outcome_family,
       t.treatment_type::text AS outcome_type
  FROM treatment_events t
UNION ALL
SELECT d.id, d.tenant_id, d.waste_load_id, d.facility_id, d.waste_category_id,
       d.waste_material_id, d.occurred_at, d.input_weight_kg, d.output_weight_kg,
       d.recovery_rate, d.process_method, d.batch_reference,
       d.recorded_by_user_id, d.provenance, d.notes,
       'DISPOSAL'::text AS outcome_family,
       d.disposal_type::text AS outcome_type
  FROM disposal_events d
"""


def create_processing_outcomes_view(connection: Any) -> None:
    """Create (or replace) the unified processing-outcome view."""
    connection.execute(text(PROCESSING_OUTCOMES_VIEW))
