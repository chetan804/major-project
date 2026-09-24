# EcoMind-AI — Roles & Permissions (RBAC)

**Status:** Phase 0 baseline (seeded by migration; enforced by dependencies)
**Related:** `security-model.md`, `../architecture/architecture.md` §5, `../api/rest-api.md`
**Companion machine-readable artefacts:**
* `backend/app/authorization/permissions.py` — the single permission catalogue
* `backend/app/authorization/role_matrix.py` — the role → permission map below
* `backend/tests/test_authorization_matrix.py` — asserts the table in §4 is what
  the code does, so this document cannot drift from the implementation

---

## 1. Model

```
User ──< UserRole >── Role ──< RolePermission >── Permission
                       │
                       └── tenant_id (NULL = platform/system role, tenant-cloneable)
```

**Authorization always checks a permission string, never a role name.** Role
names are labels for humans; a tenant may create, clone or rename roles without
touching code. This is what makes "do not assume every tenant needs every role"
(section 6) true rather than aspirational: roles are data.

Permission codes follow `resource.action`, with an optional `.own` scope
suffix restricting the action to resources the caller is responsible for:

```
bins.read          bins.read.own       bins.write         bins.delete
```

`.own` is used for driver/field-worker self-service: a driver reads only the
stops assigned to them, not every bin in the tenant.

### 1.1 Enforcement points (three, all server-side)

| Point | Mechanism |
|---|---|
| Route declaration | Each endpoint declares `required_permissions=[...]` via dependency; a startup self-check fails the app if any endpoint declares none (BR-12). |
| Service guard | Service methods that must be safe even when called from another module or a job call `authorization.require(ctx, "permission")`. |
| Platform role separation | `SUPER_ADMIN` permissions are `scope=PLATFORM`; they are disjoint from tenant permissions and cannot be granted to a tenant role (`CHECK` on the seeded data + service validation). |

Frontend route guards and hidden buttons are **supplementary UX only**. Every
one of them has a corresponding backend test proving the API refuses the call
when the permission is absent.

### 1.2 Tenant context rules

* The tenant is derived from the authenticated user's active memberships
  (ADR-0004), never from a body field or a query parameter.
* A user with memberships in several tenants may act in one at a time; the
  optional `X-Tenant-Id` header selects among **their own** memberships. An
  unowned value → `403 TENANT_ACCESS_DENIED` + a security audit event.
* Platform users have no tenant context; they see no tenant data without an
  explicit, audited break-glass activation that expires.

---

## 2. Permission catalogue

Grouped by family. Each row lists the permission codes, what they gate, and
whether the action is audited (all writes are audited; read-audit is noted where
sensitive).

### Identity & access
| Code | Gates | Notes |
|---|---|---|
| `users.read` | list/view tenant users | |
| `users.write` | invite, update, activate/suspend | audit |
| `users.delete` | soft-delete user | `is_dangerous` |
| `roles.read` | list roles & permissions | |
| `roles.write` | create/clone/rename tenant roles | audit |
| `roles.assign` | assign/revoke roles for users | audit; escalating to a role the actor does not hold requires `roles.assign.elevate` |
| `roles.assign.elevate` | grant a role containing permissions the actor lacks | `is_dangerous`, TENANT_ADMIN only |
| `sessions.read` | view active sessions | |
| `sessions.revoke` | revoke a session/user's sessions | audit |
| `apikeys.read` / `apikeys.write` | integration keys | `apikeys.write` is dangerous |

### Tenant configuration
| Code | Gates |
|---|---|
| `settings.read` | read tenant settings & organisation profile |
| `settings.write` | update tenant settings, branding, timezone, diversion-rate definition (audit) |
| `scoring.configure` | edit collection-priority / overflow-risk weights (audit) |
| `emission_factors.read` / `emission_factors.write` | carbon factor library (write is dangerous; requires source + methodology) |
| `taxonomy.write` | tenant waste categories/materials |

### Bins & telemetry
| Code | Gates |
|---|---|
| `bins.read` | list/view bins, map layer |
| `bins.write` | create/update bins | 
| `bins.delete` | decommission (soft delete) |
| `bins.telemetry.read` | raw telemetry history per bin |
| `bins.telemetry.ingest` | device/gateway ingestion endpoint (API-key auth path) |
| `bins.maintenance.write` | maintenance records |
| `alerts.read` / `alerts.acknowledge` / `alerts.resolve` | alert triage |
| `scoring.read` | inspect priority/risk factor breakdowns |

### Collections
| Code | Gates |
|---|---|
| `collections.read` | tasks & schedules |
| `collections.read.own` | driver: own assigned tasks only |
| `collections.create` | raise requests / create tasks |
| `collections.update` | reassign, reschedule, edit |
| `collections.complete.own` | driver: complete own stop with quantity/evidence |
| `collections.cancel` | cancel tasks (audit, reason required) |
| `collections.schedule.write` | manage recurring schedules |

### Routes, vehicles, drivers
| Code | Gates |
|---|---|
| `routes.read` / `routes.read.own` | routes (own = assigned to the driver) |
| `routes.create` | manually create a route |
| `routes.update` | edit stops/sequence |
| `routes.optimize` | run the optimizer (audit; CPU-bounded job) |
| `routes.assign` | assign vehicle + driver (audit) |
| `routes.dispatch` | move DRAFT → DISPATCHED (audit) |
| `routes.complete.own` | driver completes own route |
| `vehicles.read` / `vehicles.write` / `vehicles.delete` | fleet registry |
| `vehicles.telemetry.read` | vehicle position history (sensitive) |
| `vehicles.maintenance.write` | maintenance records |
| `drivers.read` / `drivers.write` | driver registry |
| `drivers.assignments.write` | shifts & assignments |

### Facilities, loads, recovery
| Code | Gates |
|---|---|
| `facilities.read` / `facilities.write` | facility registry & capabilities |
| `facilities.capacity.write` | capacity declarations & overrides |
| `loads.read` / `loads.create` / `loads.update` | waste load lifecycle |
| `loads.transfer` | custody handoffs |
| `loads.composition.write` | composition analysis entry |
| `recovery.record` | record recovery/composting/treatment/disposal outcomes |
| `weighbridge.record` | record measured weights |

### Analytics, AI, reporting
| Code | Gates |
|---|---|
| `analytics.read` | analytics endpoints & dashboards |
| `analytics.export` | export aggregates (rate-limited, audited) |
| `forecasts.read` | forecast results incl. uncertainty |
| `forecasts.execute` | trigger a forecast run (job) |
| `anomalies.read` / `anomalies.manage` | view / triage anomalies |
| `classification.execute` | submit an image for classification |
| `classification.review` | human verification queue & corrections |
| `models.read` / `models.manage` | model registry, promotion, rollback (dangerous) |
| `recommendations.read` / `recommendations.act` | view / accept-reject-execute |
| `assistant.use` | conversational assistant (tool access inherited from the caller) |
| `reports.read` / `reports.generate` / `reports.export` | reporting |

### Governance
| Code | Gates |
|---|---|
| `audit.read` | tenant audit log (read is itself audited) |
| `audit.read.platform` | platform-wide audit (PLATFORM scope) |
| `integrations.read` / `integrations.write` | adapters & webhooks |
| `files.upload` / `files.read.own` | uploads and own-file access |
| `data.export` | bulk export (dangerous, rate-limited, audited) |
| `data.import` | CSV import (validated, all-or-nothing reporting) |
| `retention.configure` | data retention policy (dangerous) |

### Platform (SUPER_ADMIN only — `scope=PLATFORM`, never grantable to tenants)
| Code | Gates |
|---|---|
| `platform.tenants.read` / `platform.tenants.write` | tenant provisioning & suspension |
| `platform.system_settings.write` | global settings |
| `platform.models.manage` | platform-provided model registry |
| `platform.audit.read` | cross-tenant audit (audited, break-glass) |
| `platform.break_glass.activate` | time-boxed, fully audited tenant data access |
| `platform.jobs.manage` | job administration & replay |
| `platform.maintenance` | read-only/feature-flag maintenance operations |

---

## 3. Roles

Eleven roles: one platform role and ten tenant roles. Roles are seeded as
system roles (`is_system=true`); tenants may clone and customise them.

| Role | Intent | Typical user |
|---|---|---|
| `SUPER_ADMIN` | Platform operator. Owns no tenant data; must break glass. | EcoMind platform staff |
| `TENANT_ADMIN` | Full control of one tenant, including users, roles, settings. | Municipality IT lead |
| `OPERATIONS_MANAGER` | Runs day-to-day collection operations; no user/role management. | Municipal operations head |
| `DISPATCHER` | Builds/dispatches routes, assigns crews, handles the live board. | Control room |
| `DRIVER` | Executes an assigned route; records quantities and exceptions. | Collection vehicle driver |
| `FIELD_WORKER` | Servicing bins, maintenance, evidence capture. | Cleaner / technician |
| `FACILITY_MANAGER` | Facility intake, processing outcomes, capacity. | MRF/compositing site manager |
| `ANALYST` | Read-heavy analytics, reports, exports; may trigger forecasts. | Data/BI analyst |
| `SUSTAINABILITY_MANAGER` | Diversion, recovery, emissions, environmental reporting. | ESG / sustainability officer |
| `VIEWER` | Read-only operational visibility, no exports. | Auditor, elected official |
| `AUDITOR` *(optional custom role)* | Read-only + audit log access, no operational visibility. | External compliance reviewer |

> The last role demonstrates the customisation path: it is not a system role in
> the seed; it is created by cloning `VIEWER` and adding `audit.read`. The
> scenario is exercised in tests, proving tenants can extend the model.

---

## 4. Role → permission matrix

Legend: **✔** granted · **o** granted in `.own` scope only · **–** not granted

| Permission family | SUPER_ADMIN | TENANT_ADMIN | OPS_MGR | DISPATCHER | DRIVER | FIELD_WORKER | FACILITY_MGR | ANALYST | SUSTAINABILITY | VIEWER |
|---|---|---|---|---|---|---|---|---|---|---|
| users.read | – | ✔ | ✔ | – | – | – | – | ✔ | – | – |
| users.write | – | ✔ | ✔ | – | – | – | – | – | – | – |
| users.delete | – | ✔ | – | – | – | – | – | – | – | – |
| roles.read | – | ✔ | ✔ | – | – | – | – | ✔ | – | – |
| roles.write | – | ✔ | – | – | – | – | – | – | – | – |
| roles.assign | – | ✔ | ✔ | – | – | – | – | – | – | – |
| roles.assign.elevate | – | ✔ | – | – | – | – | – | – | – | – |
| sessions.read / revoke | – | ✔ | ✔ | – | – | – | – | – | – | – |
| apikeys.* | – | ✔ | – | – | – | – | – | – | – | – |
| settings.read | – | ✔ | ✔ | ✔ | – | – | ✔ | ✔ | ✔ | ✔ |
| settings.write | – | ✔ | – | – | – | – | – | – | – | – |
| scoring.configure | – | ✔ | ✔ | – | – | – | – | – | – | – |
| emission_factors.read | – | ✔ | ✔ | – | – | – | ✔ | ✔ | ✔ | ✔ |
| emission_factors.write | – | ✔ | – | – | – | – | – | – | ✔ | – |
| taxonomy.write | – | ✔ | ✔ | – | – | – | – | – | – | – |
| bins.read | – | ✔ | ✔ | ✔ | o | ✔ | ✔ | ✔ | ✔ | ✔ |
| bins.write | – | ✔ | ✔ | – | – | ✔ | – | – | – | – |
| bins.delete | – | ✔ | ✔ | – | – | – | – | – | – | – |
| bins.telemetry.read | – | ✔ | ✔ | ✔ | o | ✔ | – | ✔ | ✔ | o |
| bins.telemetry.ingest | – | – | – | – | – | – | – | – | – | – |
| bins.maintenance.write | – | ✔ | ✔ | – | – | ✔ | ✔ | – | – | – |
| alerts.read | – | ✔ | ✔ | ✔ | o | ✔ | ✔ | ✔ | ✔ | ✔ |
| alerts.acknowledge / resolve | – | ✔ | ✔ | ✔ | – | ✔ | ✔ | – | – | – |
| scoring.read | – | ✔ | ✔ | ✔ | – | – | – | ✔ | ✔ | – |
| collections.read | – | ✔ | ✔ | ✔ | o | o | – | ✔ | ✔ | ✔ |
| collections.create | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| collections.update | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| collections.complete.own | – | – | – | – | ✔ | ✔ | – | – | – | – |
| collections.cancel | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| collections.schedule.write | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| routes.read | – | ✔ | ✔ | ✔ | o | – | – | ✔ | – | ✔ |
| routes.create / update | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| routes.optimize | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| routes.assign / dispatch | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| routes.complete.own | – | – | – | – | ✔ | – | – | – | – | – |
| vehicles.read | – | ✔ | ✔ | ✔ | o | – | ✔ | ✔ | ✔ | ✔ |
| vehicles.write / delete | – | ✔ | ✔ | – | – | – | – | – | – | – |
| vehicles.telemetry.read | – | ✔ | ✔ | ✔ | o | – | – | ✔ | – | – |
| vehicles.maintenance.write | – | ✔ | ✔ | – | – | – | ✔ | – | – | – |
| drivers.read | – | ✔ | ✔ | ✔ | – | – | – | ✔ | – | ✔ |
| drivers.write / assignments.write | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| facilities.read | – | ✔ | ✔ | ✔ | – | – | ✔ | ✔ | ✔ | ✔ |
| facilities.write / capacity.write | – | ✔ | ✔ | – | – | – | ✔ | – | – | – |
| loads.read | – | ✔ | ✔ | ✔ | o | – | ✔ | ✔ | ✔ | ✔ |
| loads.create / update | – | ✔ | ✔ | ✔ | – | – | ✔ | – | – | – |
| loads.transfer | – | ✔ | ✔ | – | – | – | ✔ | – | – | – |
| loads.composition.write | – | ✔ | ✔ | – | – | ✔ | ✔ | – | – | – |
| recovery.record | – | ✔ | ✔ | – | – | – | ✔ | – | ✔ | – |
| weighbridge.record | – | ✔ | ✔ | – | – | – | ✔ | – | – | – |
| analytics.read | – | ✔ | ✔ | ✔ | – | – | ✔ | ✔ | ✔ | ✔ |
| analytics.export | – | ✔ | ✔ | – | – | – | – | ✔ | ✔ | – |
| forecasts.read | – | ✔ | ✔ | ✔ | – | – | – | ✔ | ✔ | ✔ |
| forecasts.execute | – | ✔ | ✔ | – | – | – | – | ✔ | ✔ | – |
| anomalies.read | – | ✔ | ✔ | ✔ | – | ✔ | ✔ | ✔ | ✔ | ✔ |
| anomalies.manage | – | ✔ | ✔ | ✔ | – | – | – | – | – | – |
| classification.execute | – | ✔ | ✔ | – | – | ✔ | ✔ | – | – | – |
| classification.review | – | ✔ | ✔ | – | – | ✔ | ✔ | – | – | – |
| models.read | – | ✔ | – | – | – | – | – | ✔ | ✔ | – |
| models.manage | – | – | – | – | – | – | – | – | – | – |
| recommendations.read | – | ✔ | ✔ | ✔ | – | – | ✔ | ✔ | ✔ | ✔ |
| recommendations.act | – | ✔ | ✔ | ✔ | – | – | ✔ | – | ✔ | – |
| assistant.use | – | ✔ | ✔ | ✔ | – | – | – | ✔ | ✔ | ✔ |
| reports.read | – | ✔ | ✔ | ✔ | – | – | ✔ | ✔ | ✔ | ✔ |
| reports.generate | – | ✔ | ✔ | – | – | – | ✔ | ✔ | ✔ | – |
| reports.export | – | ✔ | ✔ | – | – | – | – | ✔ | ✔ | – |
| audit.read | – | ✔ | – | – | – | – | – | – | – | – |
| integrations.read | – | ✔ | ✔ | – | – | – | – | – | – | – |
| integrations.write | – | ✔ | – | – | – | – | – | – | – | – |
| files.upload / files.read.own | – | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | ✔ | – |
| data.export | – | ✔ | ✔ | – | – | – | – | ✔ | ✔ | – |
| data.import | – | ✔ | ✔ | – | – | – | – | – | – | – |
| retention.configure | – | ✔ | – | – | – | – | – | – | – | – |
| platform.* | ✔ | – | – | – | – | – | – | – | – | – |

### 4.1 Deliberate omissions worth calling out

* **`models.manage` is granted to nobody at tenant level.** Promoting a model to
  ACTIVE is a platform action (`platform.models.manage`), because a tenant
  activating an unevaluated model would violate the scientific-integrity rules.
  The dashboard still *shows* model versions and metrics to `models.read` users.
* **`DRIVER` holds no `analytics.export`, `data.export` or `reports.*`** — a
  driver's app returns only their own stops (§17: minimum necessary data).
* **`VIEWER` has no `.own` telemetry and no export** — read-only means read-only.
* **`bins.telemetry.ingest` is not granted to any human role.** It is reachable
  only through API-key/device authentication, so a compromised user session
  cannot forge telemetry.

---

## 5. Authorization test matrix (executed, not asserted on paper)

For every permission family, `backend/tests/security/test_authorization_matrix.py`
parameterises over *all* roles × *all* protected endpoints and asserts the
allow/deny outcome matches §4 exactly. Adding an endpoint without updating the
matrix fails the build. The suite additionally proves:

1. Missing token → `401`. Expired token → `401`. Revoked session → `401`.
2. Insufficient permission → `403` with `PERMISSION_DENIED`.
3. Cross-tenant resource id → `404` (never `403`, so existence is not leaked).
4. A driver calling `GET /routes` receives only own-route data, and
   `GET /routes/{other_driver_route_id}` returns `404`.
5. `SUPER_ADMIN` calling a tenant endpoint without break-glass → `403`.
6. Role escalation: a `DISPATCHER` attempting `POST /users/{id}/roles` with a
   role above their own level → `403` (`roles.assign.elevate` missing).
7. Every registered route declares a permission requirement (BR-12).
