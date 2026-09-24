# EcoMind-AI — Domain Model

**Status:** Phase 0 baseline
**Related:** `architecture.md`, `../database/erd.md`, `../security/rbac.md`

This document defines **what the business domain is** — aggregates, invariants,
lifecycles and formulas — before any table is written. The physical schema in
`../database/erd.md` implements this model; it does not invent beyond it.

---

## 1. Ubiquitous language

| Term | Precise meaning in EcoMind-AI |
|---|---|
| **Tenant** | An organisation operating on the platform (municipality, private hauler, campus, commercial or industrial facility). The isolation boundary for all tenant-owned data. |
| **Zone** | A named operational sub-area of a tenant's territory (ward, block, campus sector). Bins, routes and analytics roll up to zones. |
| **Service area** | A schedulable unit within a zone with its own service frequency/SLA (e.g. "Ward 12 — daily AM"). |
| **Bin** | A physical or logical waste container with a capacity and a waste category, located at a point. |
| **Bin sensor** | The device attached to a bin; has health, connectivity and calibration state independent of the bin's own lifecycle. |
| **Bin telemetry** | An immutable time-series observation from a sensor (fill %, weight, temperature, battery, signal, status). |
| **Fill level** | Percentage of usable volume occupied, 0–100. `CHECK`-constrained at the database level. |
| **Collection task** | A unit of operational work: collect a bin (or a location group) under a route, on a date, by a crew. |
| **Collection event** | The factual record of what actually happened at a stop: timestamp, measured quantity, evidence, exception. |
| **Route** | An ordered plan of stops assigned to a vehicle and driver for a service day. |
| **Optimization run** | An immutable record of one solver execution: inputs, constraints, objective, results, status, duration. |
| **Waste load** | A traced quantity of waste moving from a collection (or transfer) to a facility, with composition. |
| **Facility** | A receiving/processing site: transfer station, MRF, recycling centre, composting site, treatment plant, WtE, landfill, specialised. |
| **Recovery event** | A processing outcome that diverts material from disposal (recycled, composted, reused, energy-recovered). |
| **Disposal event** | A processing outcome that sends material to landfill/incineration without recovery. |
| **Diversion rate** | Share of *managed* waste not sent to disposal. Formula and configuration in §6. |
| **Forecast** | A model prediction for a future quantity, with horizon, model version and uncertainty. |
| **Anomaly** | A statistically unusual observation or behaviour, with method, score and severity. |
| **Recommendation** | A machine-generated, human-actionable suggestion with evidence and lifecycle status. |
| **Provenance** | The closed label describing how a value came to exist: `MEASURED`, `ESTIMATED`, `PREDICTED`, `SIMULATED`, `USER_ENTERED`, `DERIVED`. |

---

## 2. Aggregates and ownership

An **aggregate** is a consistency boundary: it is created, modified and
validated as a unit, and referenced from outside only by id.

| Aggregate root | Owned entities | Invariants enforced at this boundary |
|---|---|---|
| `Tenant` | `OrganizationProfile`, `TenantSetting` | Slug globally unique; status ∈ {ACTIVE, SUSPENDED, TRIAL, ARCHIVED}; a suspended tenant cannot authenticate users. |
| `User` (membership-scoped) | `UserRole`, `Session`, `RefreshToken` | Email unique **per tenant**; at least one active role per membership; password meets policy; disabled users' sessions are revoked immediately. |
| `Role` | `RolePermission` | Permission strings must exist in the seeded catalogue; a role may not hold permissions from another tenant; system roles are immutable. |
| `Bin` | `BinSensor`, `BinMaintenance` | `capacity_liters > 0`; `status` transitions legal (§4.1); at most one ACTIVE sensor per bin per time window; sensor cannot be reassigned across tenants. |
| `BinTelemetryBatch` | `BinTelemetry` rows | Every reading in one batch belongs to one tenant; readings for unknown bins are rejected, never auto-created; duplicates inside the dedup window are dropped idempotently. |
| `CollectionRequest` | `CollectionTask` | Requested date not in the past at creation; converting to tasks is all-or-nothing (no orphan tasks). |
| `CollectionTask` | `CollectionEvent` | Terminal states are immutable; quantity recorded only on completion; a task cannot be completed without a collection event or a documented exception reason. |
| `Route` | `RouteStop`, `RouteAssignment` | Every stop belongs to exactly one route (`UNIQUE(route_id, sequence)` and `UNIQUE(route_id, bin_id)`); stop sequence is contiguous from 1; total planned load ≤ assigned vehicle capacity; a route's stops must be in the same tenant as the route. |
| `Vehicle` | `VehicleTelemetry`, `VehicleMaintenance`, `VehicleCapacity` | `capacity_kg > 0`; status transitions legal (§4.3); a vehicle in MAINTENANCE/RETIRED cannot be assigned. |
| `Driver` | `DriverAssignment`, `Shift` | A driver cannot hold two overlapping assignments; a driver's licence expiry blocks assignment beyond the expiry date. |
| `Facility` | `FacilityCapability`, `FacilityCapacity`, `FacilityOperatingHours` | Only accepted waste categories may be received; daily intake may not exceed declared capacity without an explicit override flag recorded in audit. |
| `WasteLoad` | `WasteLoadItem`, `WasteTransfer` | Composition percentages sum to 100 ± 0.01; total item weight ≤ declared load weight; the load's chain (`source → transfer* → facility`) must be tenant-consistent and time-monotonic. |
| `ProcessingEvent` (recovery/disposal family) | `RecoveryEvent`, `DisposalEvent`, `CompostingEvent`, `TreatmentEvent` | Quantity ≤ the received load quantity; a load cannot be processed twice beyond its declared quantity (sum of outcomes ≤ load weight). |
| `ForecastRun` | `Forecast` rows | A run has exactly one model version, one horizon and one input window; a run is immutable once `COMPLETED`. |
| `WasteClassificationModel` | `ModelVersion`, `ModelMetric` | Only one `ACTIVE` version per model at a time (partial unique index); promotion to ACTIVE requires recorded evaluation metrics. |
| `WasteClassification` | `ClassificationFeedback` | `confidence ∈ [0,1]`; below-threshold results must enter the review queue; a human correction records both the original and corrected label. |
| `AIRecommendation` | `RecommendationFeedback` | Status transitions legal (§4.5); every recommendation stores evidence referencing real metric/source ids — an unexplained recommendation is rejected at creation. |
| `ReportRun` | — | Immutable; stores the parameter set and the structured payload used to render it. |
| `AuditLog` | — | Append-only; no update or delete path exists in application code; metadata is redacted before storage. |
| `EmissionFactor` | — | Versioned with source, geography, methodology and effective dates; estimates always reference a factor id (no factor constants in code). |

---

## 3. Core relationships

```
Tenant 1─* User *─* Role *─* Permission
Tenant 1─* Zone 1─* ServiceArea
Zone 1─* Bin *─1 BinType
Bin 1─* BinSensor 1─* BinTelemetry
Bin 1─* BinMaintenance
Zone 1─* CollectionRequest 1─* CollectionTask *─1 Bin
CollectionTask *─1 Route  (via RouteStop)
Route 1─* RouteStop *─1 Bin
Route *─1 Vehicle, *─1 Driver (via RouteAssignment)
Route *─1 RouteOptimizationRun
CollectionTask 1─* CollectionEvent *─1 WasteLoad
WasteLoad *─1 Facility (destination)
WasteLoad 1─* WasteLoadItem *─1 WasteMaterial *─1 WasteCategory
WasteLoad 1─* ProcessingEvent (recovery|disposal|composting|treatment)
Facility 1─* FacilityCapability *─1 WasteCategory
ForecastRun 1─* Forecast  (subject: zone | bin | category | tenant)
Anomaly *─1 (Bin | Vehicle | Route | Facility | Zone)
AIRecommendation *─1 (metric snapshot / evidence set)
ReportRun *─1 ReportDefinition
Notification *─1 User, *─1 Tenant
FileAsset *─1 (evidence | classification image | report export)
```

Cardinality notes worth stating explicitly:

* A `CollectionTask` may exist **without** a route (ad-hoc/on-demand pickup) —
  the route assignment is added later. This is why stops are a separate entity
  rather than a column on the task.
* A `Bin` may have **zero** sensors (unsensored bin, manually serviced). The
  platform must not assume every bin is instrumented — dashboards show sensor
  coverage as a first-class metric.
* A `WasteLoad` may have **multiple** transfers (collection → transfer station →
  MRF) and multiple processing outcomes (e.g. 60 % recycled, 40 % disposed).
  The chain of custody is a list, not a single field.

---

## 4. Lifecycle state machines

Transitions are validated server-side. Illegal transitions return `409
CONFLICT` with the current state in `details`. Terminal states are immutable.

### 4.1 Bin

```
ACTIVE ──► FULL ──► ACTIVE              (fill level crosses thresholds)
ACTIVE ──► MAINTENANCE ──► ACTIVE
ACTIVE ──► DAMAGED ──► MAINTENANCE ──► ACTIVE
ACTIVE ──► DECOMMISSIONED               (terminal; soft-deleted from active maps)
*      ──► ACTIVE                       (recommission requires an audit entry)
```

`OFFLINE` is deliberately **not** a bin status: connectivity is a *sensor*
property. Conflating them was the single most common modelling error in the
reviewed prior art — a bin can be perfectly healthy while its sensor is silent.

### 4.2 Collection task

```
PLANNED ──► ASSIGNED ──► DISPATCHED ──► EN_ROUTE ──► ARRIVED ──► COLLECTING ──► COMPLETED
   │            │              │             │            │            │
   └────────────┴──────────────┴─────────────┴────────────┴────────────┴──► CANCELLED
                                                                        └──► FAILED
                                                                        └──► MISSED
   Any non-terminal ──► RESCHEDULED (creates a successor task, links via rescheduled_from_id)
```

Rules: `COMPLETED` requires a `CollectionEvent` (quantity + timestamp) or a
recorded exception; `FAILED` requires a `failure_reason` from a controlled
vocabulary; `MISSED` is set by the system when a task passes its service window
without execution; `RESCHEDULED` is not terminal — it points at its successor.

### 4.3 Vehicle

```
AVAILABLE ──► ASSIGNED ──► EN_ROUTE ──► COLLECTING ──► AVAILABLE
AVAILABLE ──► MAINTENANCE ──► AVAILABLE
AVAILABLE ──► OFFLINE ──► AVAILABLE
*         ──► RETIRED                    (terminal)
```

### 4.4 Sensor / connectivity

```
ONLINE ──► DEGRADED ──► OFFLINE ──► ONLINE
ONLINE ──► FAULTY ──► MAINTENANCE ──► ONLINE
```
`OFFLINE` is detected by absence of telemetry beyond
`TELEMETRY_OFFLINE_THRESHOLD_MINUTES`, not by a device message.

### 4.5 AI recommendation

```
NEW ──► VIEWED ──► ACCEPTED ──► EXECUTED
  │        │           └──────► REJECTED   (feedback stored with reason)
  └────────┴──────────────────► EXPIRED    (validity window passed, set by a job)
```
`EXECUTED` requires an explicit user action that references the resulting
operational artefact (e.g. the collection task created). A recommendation never
performs an action itself (section 28/29).

### 4.6 Route lifecycle

```
DRAFT ──► PLANNED ──► DISPATCHED ──► IN_PROGRESS ──► COMPLETED
   │          │            │              │
   └──────────┴────────────┴──────────────┴──► CANCELLED
```
Optimization produces `DRAFT` routes; a human (or a configurable rule) promotes
them to `PLANNED`. This is the mechanism that keeps AI advisory rather than
autonomous (section 23).

---

## 5. Business rules (explicit, numbered, testable)

| ID | Rule |
|---|---|
| BR-01 | Every tenant-owned row must carry `tenant_id`; inserts without a tenant context fail. |
| BR-02 | Fill level must satisfy `0 ≤ fill_percentage ≤ 100`; weight, battery and signal likewise bounded. Out-of-range telemetry is rejected at ingestion and recorded as a rejected reading — never stored as if valid. |
| BR-03 | Telemetry is deduplicated on `(bin_id, sensor_id, recorded_at)` inside a `DEDUP_WINDOW_SECONDS` window; replaying a batch is a no-op. |
| BR-04 | Telemetry may not be backdated beyond `TELEMETRY_MAX_BACKFILL_DAYS`; future-dated readings beyond a small clock-skew tolerance are rejected. |
| BR-05 | A bin's "current state" is derived from its latest accepted telemetry plus its bin status — it is never a separately editable field. |
| BR-06 | A route's planned load (sum of expected stop quantities) must not exceed the assigned vehicle's capacity; the optimizer treats capacity as a hard constraint. |
| BR-07 | A collection task cannot be completed without a quantity or an explicit exception reason. |
| BR-08 | Waste load composition percentages sum to 100 ± 0.01 (checked on submit), and item weights never exceed the declared load weight. |
| BR-09 | Recovery/disposal quantities for a load may not exceed the load's received weight. |
| BR-10 | A facility may only receive waste categories it declares capability for; a mismatch is a validation error unless an override is recorded with a reason and an audit entry. |
| BR-11 | Carbon estimates must reference a versioned `EmissionFactor`; if no factor matches (geography/date/material), the estimate returns `UNKNOWN` rather than a default masked as fact. |
| BR-12 | Permission checks are deny-by-default; an endpoint with no declared permission is a startup failure. |
| BR-13 | Cross-tenant access attempts return 404 and write a security audit event. |
| BR-14 | Only one model version of a given model may be `ACTIVE`; promotion requires stored evaluation metrics with a recorded dataset identifier. |
| BR-15 | Classification results below `CLASSIFICATION_REVIEW_THRESHOLD` are flagged `needs_review` and must not drive hazardous-waste handling decisions. |
| BR-16 | Every AI recommendation must persist the evidence (metric names, values, source window) that produced it; a recommendation with empty evidence is rejected. |
| BR-17 | Missing/insufficient data produces an explicit `INSUFFICIENT_DATA` result with the reason — never a zero, and never an interpolation silently passed off as measurement. |
| BR-18 | Timestamps are stored UTC; conversion to a tenant's timezone happens only at presentation. Collection "day" is computed in the tenant's timezone (`DEFAULT_TIMEZONE` per tenant setting). |
| BR-19 | Deleting a resource with operational history is a soft delete; hard deletion exists only through the documented retention/erasure workflow (GDPR-style erasure for personal data) and is always audited. |
| BR-20 | Any quantity exposed to the UI carries a provenance label; `MEASURED` is used only for values actually recorded by a sensor or a human in the field. |

---

## 6. Metric definitions (single source of truth)

To satisfy "do not silently mix incompatible definitions" (section 20), every
metric is defined once here, implemented once in `app/analytics/definitions.py`,
and referenced by analytics, reports and the assistant alike.

```
total_generated(period)   = Σ forecast/measured generation for the period
                            (MEASURED when telemetry+census data exist,
                             PREDICTED when derived from a forecast run)

total_collected(period)   = Σ collection_event.quantity_kg where
                            completed_at ∈ period

total_managed(period)     = total_collected(period) + opening_inventory_adjustment
                            (commented explicitly in code; no hidden terms)

total_recovered(period)   = Σ processing_event.quantity_kg where
                            outcome ∈ {RECYCLED, COMPOSTED, REUSED, ENERGY_RECOVERY}

total_disposed(period)    = Σ processing_event.quantity_kg where
                            outcome ∈ {LANDFILL, INCINERATION_NO_RECOVERY}

recycling_rate(period)    = Σ outcome = RECYCLED / total_managed
composting_rate(period)   = Σ outcome = COMPOSTED / total_managed
landfill_rate(period)     = Σ outcome = LANDFILL / total_managed

diversion_rate(period)    = total_recovered / total_managed          [default]
    configurable per tenant as:
      (a) RECOVERY_BASED (default)  — as above
      (b) RECYCLING_ONLY            — recycled + composted only
      (c) EXCLUDE_ENERGY_RECOVERY   — recovered minus energy recovery
    The active definition is stored on the tenant and shown in the UI next to
    the value; changing it is audited. Two tenants' diversion rates are never
    silently compared without their definitions.

collection_efficiency(period) = completed_tasks / planned_tasks
missed_collection_rate(period)= missed_tasks / planned_tasks
overflow_incidents(period)    = count(distinct bin_alert where type = OVERFLOW)
vehicle_utilization(period)   = Σ measured_load_kg / Σ capacity_kg over dispatched routes
route_efficiency(run)         = baseline_distance_km / optimized_distance_km
                                (baseline = previous plan or naive plan, stated explicitly)

estimated_co2e(period)        = Σ (activity_quantity × emission_factor[id])
    reported with: factor id, source, geography, methodology, provenance=ESTIMATED
```

Division by zero yields `null` + an `INSUFFICIENT_DATA` reason, never `0`.

---

## 7. Explainable scoring models

### 7.1 Collection priority score (deterministic, not ML)

```
priority = w_fill        × fill_pressure            (0..1, latest or predicted fill / 100)
         + w_overflow    × overflow_risk             (0..1, from the risk model)
         + w_age         × time_since_collection     (normalised to service SLA)
         + w_history     × historical_overflow_rate  (0..1, 90-day trailing)
         + w_category    × category_sensitivity      (configurable per category)
         + w_sla         × sla_breach_pressure       (0..1)
         + w_zone        × zone_priority             (0..1, tenant-configured)
         + w_access      × access_constraint         (e.g. restricted hours)
```

Every weight is a row in `scoring_configuration` (tenant-overridable, seeded
with documented defaults). The score response returns **the contribution of each
factor**, so a dispatcher can see *why* a bin ranks first. This is the
transparency requirement of section 10 — an opaque LLM is explicitly not used.

### 7.2 Overflow risk

Logistic-style blend of: current fill, fill velocity (kg or %/hour from the last
`n` readings), time-of-day/week effects, historical overflow frequency for the
bin, waste category, and days since last collection. Output is a probability in
`[0,1]` with a stated model version; the UI shows the top contributing factors.
Where a bin has insufficient telemetry history, the result is `INSUFFICIENT_DATA`
with the reason (`fewer than N readings`), never a fabricated probability.

### 7.3 Anomaly detection

Interpretable first (section 30): rolling z-score and IQR fences on fill,
weight, temperature, battery and inter-collection interval; Isolation Forest
only for multivariate cases where univariate methods demonstrably fall short.
Each anomaly stores method, parameters, score, threshold, window and severity.

---

## 8. What the domain deliberately does *not* model

Stated so that absence is a decision, not an oversight:

* **No financial/billing domain.** The specification mentions money-adjacent
  precision rules but no billing workflow; invoices are out of scope. Monetary
  columns, where they exist (e.g. disposal cost per kg), use `NUMERIC`.
* **No HR/payroll for drivers** — shifts and assignments only.
* **No citizen-facing mobile app** — the platform is operator-facing; the
  citizen complaint is modelled as a `CollectionRequest` source.
* **No LLM-authored numerical decisions** anywhere (section 24/25).
