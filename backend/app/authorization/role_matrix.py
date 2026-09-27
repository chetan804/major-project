"""
The seeded role → permission matrix (``rbac.md`` §4).

The matrix is *data*, not code paths: authorization always checks a permission
string, so a tenant may clone a system role, rename it, or build an entirely new
one without any change here. What this module provides is the **starting point**
every tenant is provisioned with.

``tests/test_authorization_matrix.py`` asserts that this table and
``docs/security/rbac.md`` §4 say the same thing, so neither can drift.

Two deliberate omissions, called out because they look like mistakes:

* **``models.manage`` is granted to nobody at tenant level.** Promoting a model
  to ACTIVE is a platform action, because a tenant activating an unevaluated
  model would violate the scientific-integrity rules (ADR-0008).
* **``bins.telemetry.ingest`` is granted to no human role at all.** It is
  reachable only through API-key/device authentication, so a compromised user
  session cannot forge telemetry.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.authorization.permissions import PERMISSIONS

__all__ = [
    "ROLE_DEFINITIONS",
    "ROLE_PERMISSION_MAP",
    "RoleDefinition",
    "permissions_for_role",
]


@dataclass(frozen=True, slots=True)
class RoleDefinition:
    """A seeded role: its identity and the permission codes it grants."""

    code: str
    name: str
    description: str
    level: int
    is_default: bool = False
    permissions: frozenset[str] = field(default_factory=frozenset)


#: Permission groups referenced by more than one role. Naming them keeps the
#: matrix below readable and makes a change in one place rather than ten.
_VIEW_OPS = frozenset(
    {
        "settings.read",
        "bins.read",
        "bins.telemetry.read.own",
        "alerts.read.own",
        "scoring.read",
        "collections.read.own",
        "routes.read.own",
        "vehicles.read.own",
        "loads.read.own",
        "facilities.read",
        "analytics.read",
        "forecasts.read",
        "anomalies.read",
        "emission_factors.read",
        "recommendations.read",
        "assistant.use",
        "reports.read",
        "files.upload",
        "files.read.own",
    }
)

_ANALYST_READ = frozenset(
    {
        "settings.read",
        "roles.read",
        "users.read",
        "emission_factors.read",
        "bins.read",
        "bins.telemetry.read",
        "alerts.read",
        "scoring.read",
        "collections.read",
        "routes.read",
        "vehicles.read",
        "vehicles.telemetry.read",
        "drivers.read",
        "facilities.read",
        "loads.read",
        "analytics.read",
        "analytics.export",
        "forecasts.read",
        "forecasts.execute",
        "anomalies.read",
        "models.read",
        "recommendations.read",
        "assistant.use",
        "reports.read",
        "reports.generate",
        "reports.export",
        "data.export",
        "files.upload",
        "files.read.own",
    }
)

_SUSTAINABILITY_READ = frozenset(
    {
        "settings.read",
        "emission_factors.read",
        "emission_factors.write",
        "bins.read",
        "bins.telemetry.read",
        "alerts.read",
        "scoring.read",
        "collections.read",
        "routes.read",
        "vehicles.read",
        "drivers.read",
        "facilities.read",
        "loads.read",
        "analytics.read",
        "analytics.export",
        "forecasts.read",
        "forecasts.execute",
        "anomalies.read",
        "models.read",
        "recommendations.read",
        "recommendations.act",
        "assistant.use",
        "reports.read",
        "reports.generate",
        "reports.export",
        "data.export",
        "files.upload",
        "files.read.own",
    }
)

_OPERATIONS_WRITE = frozenset(
    {
        "settings.read",
        "scoring.configure",
        "emission_factors.read",
        "taxonomy.write",
        "users.read",
        "users.write",
        "roles.read",
        "roles.assign",
        "sessions.read",
        "sessions.revoke",
        "bins.read",
        "bins.write",
        "bins.delete",
        "bins.telemetry.read",
        "bins.maintenance.write",
        "alerts.read",
        "alerts.acknowledge",
        "alerts.resolve",
        "scoring.read",
        "collections.read",
        "collections.create",
        "collections.update",
        "collections.cancel",
        "collections.schedule.write",
        "routes.read",
        "routes.create",
        "routes.update",
        "routes.optimize",
        "routes.assign",
        "routes.dispatch",
        "vehicles.read",
        "vehicles.write",
        "vehicles.delete",
        "vehicles.telemetry.read",
        "vehicles.maintenance.write",
        "drivers.read",
        "drivers.write",
        "drivers.assignments.write",
        "facilities.read",
        "facilities.write",
        "facilities.capacity.write",
        "loads.read",
        "loads.create",
        "loads.update",
        "loads.transfer",
        "recovery.record",
        "weighbridge.record",
        "analytics.read",
        "analytics.export",
        "forecasts.read",
        "anomalies.read",
        "anomalies.manage",
        "recommendations.read",
        "recommendations.act",
        "assistant.use",
        "reports.read",
        "integrations.read",
        "data.export",
        "data.import",
        "files.upload",
        "files.read.own",
    }
)

_TENANT_ADMIN = _OPERATIONS_WRITE | frozenset(
    {
        "users.delete",
        "roles.write",
        "roles.assign.elevate",
        "settings.write",
        "apikeys.read",
        "apikeys.write",
        "integrations.write",
        "retention.configure",
        "audit.read",
        "classification.execute",
        "classification.review",
        "reports.generate",
    }
)

_SUPER_ADMIN = frozenset(
    {
        "platform.tenants.read",
        "platform.tenants.write",
        "platform.system_settings.write",
        "platform.models.manage",
        "platform.audit.read",
        "platform.break_glass.activate",
        "platform.jobs.manage",
        "platform.maintenance",
        "audit.read.platform",
    }
)

_ROLES: tuple[RoleDefinition, ...] = (
    RoleDefinition(
        code="SUPER_ADMIN",
        name="Platform administrator",
        description=(
            "EcoMind platform operator. Owns no tenant data and must activate "
            "break-glass to read any."
        ),
        level=100,
        permissions=_SUPER_ADMIN,
    ),
    RoleDefinition(
        code="TENANT_ADMIN",
        name="Tenant administrator",
        description="Full control of one tenant, including users, roles and settings.",
        level=90,
        permissions=_TENANT_ADMIN,
    ),
    RoleDefinition(
        code="OPERATIONS_MANAGER",
        name="Operations manager",
        description="Runs day-to-day collection operations; no user or role management.",
        level=70,
        permissions=_OPERATIONS_WRITE,
    ),
    RoleDefinition(
        code="DISPATCHER",
        name="Dispatcher",
        description="Builds and dispatches routes, assigns crews, works the live board.",
        level=60,
        permissions=frozenset(
            {
                "settings.read",
                "bins.read",
                "bins.telemetry.read",
                "alerts.read",
                "alerts.acknowledge",
                "alerts.resolve",
                "scoring.read",
                "collections.read",
                "collections.create",
                "collections.update",
                "collections.cancel",
                "collections.schedule.write",
                "routes.read",
                "routes.create",
                "routes.update",
                "routes.optimize",
                "routes.assign",
                "routes.dispatch",
                "vehicles.read",
                "vehicles.telemetry.read",
                "drivers.read",
                "drivers.write",
                "drivers.assignments.write",
                "facilities.read",
                "loads.read",
                "analytics.read",
                "forecasts.read",
                "anomalies.read",
                "recommendations.read",
                "assistant.use",
                "reports.read",
                "files.upload",
                "files.read.own",
            }
        ),
    ),
    RoleDefinition(
        code="DRIVER",
        name="Driver",
        description="Executes an assigned route; records quantities and exceptions.",
        level=30,
        permissions=frozenset(
            {
                "bins.read.own",
                "bins.telemetry.read.own",
                "alerts.read.own",
                "collections.read.own",
                "collections.complete.own",
                "routes.read.own",
                "routes.complete.own",
                "vehicles.read.own",
                "vehicles.telemetry.read.own",
                "loads.read.own",
                "files.upload",
                "files.read.own",
            }
        ),
    ),
    RoleDefinition(
        code="FIELD_WORKER",
        name="Field worker",
        description="Services bins, performs maintenance, captures evidence.",
        level=30,
        permissions=frozenset(
            {
                "bins.read",
                "bins.write",
                "bins.telemetry.read",
                "bins.maintenance.write",
                "alerts.read",
                "alerts.acknowledge",
                "alerts.resolve",
                "collections.read.own",
                "collections.complete.own",
                "anomalies.read",
                "classification.execute",
                "classification.review",
                "loads.read",
                "loads.composition.write",
                "files.upload",
                "files.read.own",
            }
        ),
    ),
    RoleDefinition(
        code="FACILITY_MANAGER",
        name="Facility manager",
        description="Facility intake, processing outcomes and capacity.",
        level=50,
        permissions=frozenset(
            {
                "settings.read",
                "emission_factors.read",
                "bins.read",
                "bins.maintenance.write",
                "alerts.read",
                "alerts.acknowledge",
                "alerts.resolve",
                "collections.read",
                "vehicles.read",
                "vehicles.maintenance.write",
                "facilities.read",
                "facilities.write",
                "facilities.capacity.write",
                "loads.read",
                "loads.create",
                "loads.update",
                "loads.transfer",
                "loads.composition.write",
                "recovery.record",
                "weighbridge.record",
                "analytics.read",
                "anomalies.read",
                "classification.execute",
                "classification.review",
                "recommendations.read",
                "recommendations.act",
                "reports.read",
                "reports.generate",
                "files.upload",
                "files.read.own",
            }
        ),
    ),
    RoleDefinition(
        code="ANALYST",
        name="Analyst",
        description="Read-heavy analytics, reports and exports; may trigger forecasts.",
        level=40,
        permissions=_ANALYST_READ,
    ),
    RoleDefinition(
        code="SUSTAINABILITY_MANAGER",
        name="Sustainability manager",
        description="Diversion, recovery, emissions and environmental reporting.",
        level=50,
        permissions=_SUSTAINABILITY_READ,
    ),
    RoleDefinition(
        code="VIEWER",
        name="Viewer",
        description="Read-only operational visibility. No exports, no `.own` telemetry.",
        level=10,
        permissions=frozenset(
            {
                "settings.read",
                "emission_factors.read",
                "bins.read",
                "alerts.read",
                "collections.read",
                "routes.read",
                "vehicles.read",
                "drivers.read",
                "facilities.read",
                "loads.read",
                "analytics.read",
                "forecasts.read",
                "anomalies.read",
                "recommendations.read",
                "assistant.use",
                "reports.read",
            }
        ),
    ),
)

#: Every seeded role, keyed by code.
ROLE_DEFINITIONS: dict[str, RoleDefinition] = {role.code: role for role in _ROLES}

#: The matrix itself: role code → granted permission codes.
ROLE_PERMISSION_MAP: dict[str, frozenset[str]] = {
    role.code: role.permissions for role in _ROLES
}


def permissions_for_role(role_code: str) -> frozenset[str]:
    """The permission codes a seeded role grants. Unknown roles grant nothing."""
    return ROLE_PERMISSION_MAP.get(role_code, frozenset())


def _assert_catalogue_is_complete() -> None:
    """
    Fail at import if the matrix references a code the catalogue does not define.

    A typo in the matrix would otherwise produce a role that silently grants
    nothing, and the failure would surface as a 403 nobody can explain.
    """
    unknown: set[str] = set()
    for role_code, codes in ROLE_PERMISSION_MAP.items():
        unknown.update(codes - set(PERMISSIONS))
    if unknown:  # pragma: no cover - guarded by the matrix test
        raise AssertionError(
            "the role matrix grants permission codes that are not in the catalogue: "
            + ", ".join(sorted(unknown))
        )


_assert_catalogue_is_complete()
