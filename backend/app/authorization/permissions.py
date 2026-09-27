"""
The permission catalogue — the single source of truth for authorization.

**Authorization checks a permission code, never a role name.** Roles are data: a
tenant may clone, rename or customise them without touching code, which is what
makes "do not assume every tenant needs every role" (``rbac.md`` §6) true rather
than aspirational. The consequence is that this module, not the role matrix, is
the authoritative list of capabilities.

Codes follow ``resource.action`` with an optional ``.own`` suffix that restricts
the action to resources the caller is personally responsible for — a driver
reads the stops assigned to them, not every bin in the tenant.

The seeded catalogue is written to the ``permissions`` table by migration, and
``rbac.md`` §4 is asserted against it by
``tests/test_authorization_matrix.py`` so this document cannot drift from the
implementation.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.models._enums import PermissionScope

__all__ = [
    "PERMISSIONS",
    "PERMISSION_CODES",
    "PermissionDefinition",
    "permissions_by_family",
]


@dataclass(frozen=True, slots=True)
class PermissionDefinition:
    """One capability: what it is called, what it gates and how risky it is."""

    code: str
    resource: str
    action: str
    family: str
    description: str
    scope: PermissionScope = PermissionScope.TENANT
    is_dangerous: bool = False

    @property
    def is_own_scoped(self) -> bool:
        """Whether the code carries the ``.own`` suffix (self-service scope)."""
        return self.code.endswith(".own") or ".own" in self.code


def _define(
    code: str,
    family: str,
    description: str,
    *,
    is_dangerous: bool = False,
    scope: PermissionScope = PermissionScope.TENANT,
) -> tuple[str, PermissionDefinition]:
    resource, _, action = code.partition(".")
    definition = PermissionDefinition(
        code=code,
        resource=resource,
        action=action,
        family=family,
        description=description,
        scope=scope,
        is_dangerous=is_dangerous,
    )
    return code, definition


_RAW: tuple[tuple[str, PermissionDefinition], ...] = (
    # -- Identity and access -------------------------------------------------
    _define("users.read", "identity", "List and view tenant users."),
    _define("users.write", "identity", "Invite, update, activate or suspend users.", is_dangerous=False),
    _define("users.delete", "identity", "Soft-delete a user.", is_dangerous=True),
    _define("roles.read", "identity", "List roles and their permissions."),
    _define("roles.write", "identity", "Create, clone or rename tenant roles."),
    _define(
        "roles.assign",
        "identity",
        "Assign or revoke roles for users.",
    ),
    _define(
        "roles.assign.elevate",
        "identity",
        "Grant a role containing permissions the actor does not hold.",
        is_dangerous=True,
    ),
    _define("sessions.read", "identity", "View active sessions."),
    _define("sessions.revoke", "identity", "Revoke a session or every session of a user."),
    _define("apikeys.read", "identity", "View integration API keys (metadata only)."),
    _define("apikeys.write", "identity", "Create, rotate or revoke API keys.", is_dangerous=True),
    # -- Tenant configuration ------------------------------------------------
    _define("settings.read", "configuration", "Read tenant settings and the organisation profile."),
    _define(
        "settings.write",
        "configuration",
        "Update tenant settings, branding, timezone and the diversion-rate definition.",
    ),
    _define(
        "scoring.configure",
        "configuration",
        "Edit collection-priority and overflow-risk weights.",
    ),
    _define("emission_factors.read", "configuration", "Read the carbon factor library."),
    _define(
        "emission_factors.write",
        "configuration",
        "Add or supersede emission factors. Requires a source and a methodology.",
        is_dangerous=True,
    ),
    _define("taxonomy.write", "configuration", "Create tenant waste categories and materials."),
    # -- Bins and telemetry --------------------------------------------------
    _define("bins.read", "bins", "List and view bins, including the map layer."),
    _define("bins.read.own", "bins", "Read bins the caller is responsible for."),
    _define("bins.write", "bins", "Create or update bins."),
    _define("bins.delete", "bins", "Decommission a bin (soft delete)."),
    _define("bins.telemetry.read", "bins", "Read raw telemetry history for a bin."),
    _define("bins.telemetry.read.own", "bins", "Read telemetry for bins the caller is responsible for."),
    _define(
        "bins.telemetry.ingest",
        "bins",
        "Submit telemetry through the device-gateway path (API-key authentication only).",
    ),
    _define("bins.maintenance.write", "bins", "Record bin maintenance."),
    _define("alerts.read", "bins", "View bin alerts."),
    _define("alerts.read.own", "bins", "View alerts for bins the caller is responsible for."),
    _define("alerts.acknowledge", "bins", "Acknowledge an alert."),
    _define("alerts.resolve", "bins", "Resolve an alert with a note."),
    _define("scoring.read", "bins", "Inspect priority and risk factor breakdowns."),
    # -- Collections ---------------------------------------------------------
    _define("collections.read", "collections", "View collection tasks and schedules."),
    _define("collections.read.own", "collections", "View the caller's own assigned tasks."),
    _define("collections.create", "collections", "Raise a collection request or create a task."),
    _define("collections.update", "collections", "Reassign, reschedule or edit a task."),
    _define(
        "collections.complete.own",
        "collections",
        "Complete the caller's own stop with quantity and evidence.",
    ),
    _define("collections.cancel", "collections", "Cancel a task. A reason is required."),
    _define("collections.schedule.write", "collections", "Manage recurring collection schedules."),
    # -- Routes, vehicles, drivers ------------------------------------------
    _define("routes.read", "routing", "View routes."),
    _define("routes.read.own", "routing", "View routes assigned to the caller."),
    _define("routes.create", "routing", "Manually create a route."),
    _define("routes.update", "routing", "Edit stops and their sequence."),
    _define("routes.optimize", "routing", "Run the optimizer (a CPU-bounded, audited job)."),
    _define("routes.assign", "routing", "Assign a vehicle and a driver to a route."),
    _define("routes.dispatch", "routing", "Move a route from DRAFT to DISPATCHED."),
    _define("routes.complete.own", "routing", "Complete the caller's own route."),
    _define("vehicles.read", "routing", "View the fleet registry."),
    _define("vehicles.read.own", "routing", "View the vehicle the caller is assigned to."),
    _define("vehicles.write", "routing", "Create or update vehicles."),
    _define("vehicles.delete", "routing", "Retire a vehicle."),
    _define("vehicles.telemetry.read", "routing", "Read vehicle position history (sensitive)."),
    _define("vehicles.telemetry.read.own", "routing", "Read the caller's own vehicle telemetry."),
    _define("vehicles.maintenance.write", "routing", "Record vehicle maintenance."),
    _define("drivers.read", "routing", "View the driver registry."),
    _define("drivers.write", "routing", "Create or update drivers."),
    _define("drivers.assignments.write", "routing", "Manage shifts and assignments."),
    # -- Facilities, loads, recovery ----------------------------------------
    _define("facilities.read", "facilities", "View facilities and their capabilities."),
    _define("facilities.write", "facilities", "Create or update facilities."),
    _define("facilities.capacity.write", "facilities", "Declare or override facility capacity."),
    _define("loads.read", "facilities", "View waste loads and their chain of custody."),
    _define("loads.read.own", "facilities", "View loads the caller is responsible for."),
    _define("loads.create", "facilities", "Open a waste load."),
    _define("loads.update", "facilities", "Update a waste load."),
    _define("loads.transfer", "facilities", "Record a custody handoff."),
    _define("loads.composition.write", "facilities", "Enter composition analysis for a load."),
    _define("recovery.record", "facilities", "Record a recovery, composting, treatment or disposal outcome."),
    _define("weighbridge.record", "facilities", "Record a measured weighbridge weight."),
    # -- Analytics, AI, reporting -------------------------------------------
    _define("analytics.read", "analytics", "Read analytics endpoints and dashboards."),
    _define(
        "analytics.export",
        "analytics",
        "Export aggregates. Rate-limited and audited.",
    ),
    _define("forecasts.read", "analytics", "Read forecast results including uncertainty."),
    _define("forecasts.execute", "analytics", "Trigger a forecast run (a job)."),
    _define("anomalies.read", "analytics", "View detected anomalies."),
    _define("anomalies.manage", "analytics", "Triage anomalies (acknowledge, resolve, mark false positive)."),
    _define("classification.execute", "ai", "Submit an image for waste classification."),
    _define("classification.review", "ai", "Verify or correct a classification."),
    _define("models.read", "ai", "View the model registry and published metrics."),
    # Tenant scope, and granted to no role: promoting a model to ACTIVE is a
    # platform action (``platform.models.manage``), because a tenant activating
    # an unevaluated model would breach the scientific-integrity rules
    # (``rbac.md`` §4.1, ADR-0008). The code exists so the capability is named
    # and can be audited if a tenant is ever granted it deliberately.
    _define(
        "models.manage",
        "ai",
        "Promote or retire a model version (tenant scope, granted to nobody).",
        is_dangerous=True,
        scope=PermissionScope.TENANT,
    ),
    _define("recommendations.read", "ai", "View recommendations."),
    _define("recommendations.act", "ai", "Accept, reject or execute a recommendation."),
    _define(
        "assistant.use",
        "ai",
        "Use the conversational assistant. Tool access is inherited from the caller.",
    ),
    _define("reports.read", "reporting", "View report definitions and runs."),
    _define("reports.generate", "reporting", "Generate a report run."),
    _define("reports.export", "reporting", "Export a rendered report."),
    # -- Governance ----------------------------------------------------------
    _define("audit.read", "governance", "Read the tenant audit log. The read is itself audited."),
    _define(
        "audit.read.platform",
        "governance",
        "Read audit records that belong to no tenant (platform scope).",
        scope=PermissionScope.PLATFORM,
    ),
    _define("integrations.read", "governance", "View integrations and webhooks."),
    _define("integrations.write", "governance", "Configure integrations and webhooks.", is_dangerous=True),
    _define("files.upload", "governance", "Upload a file."),
    _define("files.read.own", "governance", "Read a file the caller uploaded."),
    _define("data.export", "governance", "Bulk data export. Rate-limited and audited.", is_dangerous=True),
    _define("data.import", "governance", "CSV import. Validated and all-or-nothing in its reporting."),
    _define("retention.configure", "governance", "Change a data retention policy.", is_dangerous=True),
    # -- Platform (SUPER_ADMIN only) ----------------------------------------
    _define(
        "platform.tenants.read",
        "platform",
        "List tenants across the platform.",
        scope=PermissionScope.PLATFORM,
    ),
    _define(
        "platform.tenants.write",
        "platform",
        "Provision, update or suspend a tenant.",
        scope=PermissionScope.PLATFORM,
    ),
    _define(
        "platform.system_settings.write",
        "platform",
        "Change global platform settings.",
        scope=PermissionScope.PLATFORM,
    ),
    _define(
        "platform.models.manage",
        "platform",
        "Promote or retire platform-provided models.",
        scope=PermissionScope.PLATFORM,
        is_dangerous=True,
    ),
    _define(
        "platform.audit.read",
        "platform",
        "Read the cross-tenant audit log. Audited, break-glass.",
        scope=PermissionScope.PLATFORM,
    ),
    _define(
        "platform.break_glass.activate",
        "platform",
        "Activate time-boxed, fully audited access to a tenant's data.",
        scope=PermissionScope.PLATFORM,
        is_dangerous=True,
    ),
    _define(
        "platform.jobs.manage",
        "platform",
        "Administer and replay background jobs.",
        scope=PermissionScope.PLATFORM,
    ),
    _define(
        "platform.maintenance",
        "platform",
        "Read-only and feature-flag maintenance operations.",
        scope=PermissionScope.PLATFORM,
    ),
)

#: The catalogue, keyed by code. Insertion order is the seeding order.
PERMISSIONS: dict[str, PermissionDefinition] = dict(_RAW)

#: Every code, in catalogue order. Used by the seeder and by the matrix test.
PERMISSION_CODES: tuple[str, ...] = tuple(PERMISSIONS)

#: Codes a tenant role may hold. Platform-scope codes are never grantable to a
#: tenant (``rbac.md`` §1.1), which is what keeps the two families disjoint.
PLATFORM_PERMISSION_CODES: frozenset[str] = frozenset(
    code for code, definition in PERMISSIONS.items() if definition.scope is PermissionScope.PLATFORM
)


def permissions_by_family() -> dict[str, list[str]]:
    """Group the catalogue by family, for the role editor UI and the docs."""
    grouped: dict[str, list[str]] = {}
    for code, definition in PERMISSIONS.items():
        grouped.setdefault(definition.family, []).append(code)
    return grouped
