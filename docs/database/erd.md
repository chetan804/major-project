# EcoMind-AI — Database Entity-Relationship Design

**Status:** Phase 0 baseline (physical schema implemented by Alembic migrations)
**Target engine:** PostgreSQL 16
**Related:** `../architecture/domain-model.md` (business semantics), `../architecture/decisions.md` (ADR-0002, ADR-0003, ADR-0005)

This document is the **plan**. It is written before the migrations so that the
schema is a deliberate design rather than an accumulative accident. Appendix A
tracks plan-versus-implemented status.

---

## 1. Global conventions

| Concern | Convention |
|---|---|
| Primary keys | `id UUID PRIMARY KEY DEFAULT gen_random_uuid()` (verified available on PG16.2) |
| Timestamps | `TIMESTAMPTZ`, always UTC (`now()`); `created_at NOT NULL DEFAULT now()`, `updated_at NOT NULL DEFAULT now()` maintained by trigger |
| Measured quantities | `NUMERIC(precision, scale)` — **never** `FLOAT`/`REAL`. Weights `NUMERIC(12,3)` kg, volumes `NUMERIC(12,3)` L, money `NUMERIC(14,2)`, carbon `NUMERIC(14,4)` kgCO2e, percentages `NUMERIC(5,2)` |
| Coordinates | `NUMERIC(9,6)` latitude, `NUMERIC(10,7)` longitude, with `CHECK` bounds (ADR-0005) |
| Enumeration | Native PostgreSQL `ENUM` types for closed sets that must honour BR-xx rules; `TEXT` + `CHECK` where the set is expected to grow per tenant |
| Tenant scoping | `tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE RESTRICT` + index, on every tenant-owned table |
| Soft delete | `deleted_at TIMESTAMPTZ NULL`; every read path filters `deleted_at IS NULL` via the repository base class |
| Optimistic concurrency | `version INTEGER NOT NULL DEFAULT 1` on mutable operational entities (bins, routes, tasks, vehicles) to prevent lost updates |
| External-facing identifiers | Human-readable codes (`bin_code`, `route_code`, `load_code`) are `UNIQUE(tenant_id, code)` and are the ids shown in the UI/CSV; UUIDs are internal |
| Naming | `snake_case`, plural table names, singular enum type names, `fk_`/`uq_`/`ck_`/`ix_` constraint prefixes |
| Audit columns | `created_by UUID NULL REFERENCES users(id)`, `updated_by UUID NULL` on mutable entities |

### 1.1 Index strategy

Indexes are added for **query patterns that exist**, not speculatively:

* Every FK gets an index (PostgreSQL does not create these automatically).
* Time-series: `(tenant_id, bin_id, recorded_at DESC)` and a `BRIN` index on
  `recorded_at` for range scans over large partitions.
* Operational list views: `(tenant_id, status)` and `(tenant_id, <date column>)`.
* Partial indexes for hot subsets: `WHERE deleted_at IS NULL`,
  `WHERE status = 'ACTIVE'` (bin sensors), `WHERE is_active` (model versions).
* Unique-constraint indexes double as lookup indexes.
* `GIN` on audit metadata only if a documented query needs it (deferred).

### 1.2 Row-Level Security (ADR-0003)

RLS is enabled **and forced** on every table in the tenant-scoped list below
(Appendix B), with:

```sql
USING (tenant_id = current_setting('app.tenant_id', true)::uuid)
WITH CHECK (tenant_id = current_setting('app.tenant_id', true)::uuid)
```

The application connects as a non-owner role (`ecomind_app`) for which
`FORCE ROW LEVEL SECURITY` applies; migrations run as the owner. A dedicated
test asserts that a deliberately unscoped `SELECT` still returns zero rows for a
foreign tenant.

---

## 2. Identity, tenancy and access

### 2.1 `tenants`
| Column | Type | Constraints |
|---|---|---|
| id | UUID | PK |
| name | TEXT | NOT NULL, `uq_tenants_name` |
| slug | TEXT | NOT NULL, `UNIQUE`, `CHECK (slug ~ '^[a-z0-9-]{3,60}$')` |
| type | `tenant_type` | NOT NULL (`MUNICIPALITY`, `PRIVATE_HAULER`, `RESIDENTIAL_CAMPUS`, `COMMERCIAL`, `INDUSTRIAL`, `GOVERNMENT_AGENCY`) |
| status | `tenant_status` | NOT NULL DEFAULT 'TRIAL' |
| timezone | TEXT | NOT NULL DEFAULT 'Asia/Kolkata', validated against `pg_timezone_names` |
| locale | TEXT | NOT NULL DEFAULT 'en-IN' |
| plan | TEXT | NOT NULL DEFAULT 'standard' |
| trial_ends_at | TIMESTAMPTZ | NULL |
| created_at/updated_at/deleted_at | TIMESTAMPTZ | as convention |

Indexes: `uq_tenants_slug`, `ix_tenants_status`.

### 2.2 `organization_profiles` (1:1 tenant)
`tenant_id` (PK/FK, `UNIQUE`), legal_name, registration_number, tax_id,
primary_contact_name/email/phone, address_line1/2, city, state, postal_code,
country (ISO-3166 alpha-2), latitude, longitude, logo_file_id (FK `file_assets`),
service_territory_description, `onboarded_at`.

### 2.3 `users`
`id` PK · `tenant_id` FK (nullable **only** for platform-level users, guarded by
`CHECK`) · `email CITEXT/TEXT NOT NULL` · `UNIQUE (tenant_id, lower(email))` ·
password_hash (Argon2id encoded string, never returned by any schema) ·
full_name · phone · status `user_status` (`ACTIVE`,`INVITED`,`SUSPENDED`,
`LOCKED`,`DISABLED`) · email_verified_at · last_login_at · last_login_ip INET ·
failed_login_attempts SMALLINT default 0 · locked_until · mfa_secret_encrypted
NULL (architecture only) · preferred_timezone · preferred_locale ·
`locale`/`timezone` for i18n readiness · `deleted_at`.

Constraints: `CHECK (email <> '')`; a partial unique index permits one platform
user per email: `CREATE UNIQUE INDEX ... WHERE tenant_id IS NULL`.

### 2.4 `roles`
`id` · `tenant_id` FK NULL (NULL = platform/system role) · `code TEXT NOT NULL` ·
`name` · `description` · `is_system BOOLEAN NOT NULL DEFAULT false` ·
`is_default BOOLEAN` (granted to new members) · `level SMALLINT` (for display
ordering). `UNIQUE (COALESCE(tenant_id,'00000000-0000-0000-0000-000000000000'), code)`.
The ten seeded roles are system roles; tenants may clone a system role to
customise — the clone gets `is_system=false`.

### 2.5 `permissions`
`id` · `code TEXT UNIQUE NOT NULL` (`resource.action`, e.g. `bins.write`) ·
`resource` · `action` · `scope` (`TENANT`,`PLATFORM`) · `description` ·
`is_dangerous BOOLEAN` (drives extra confirmation in UI).

### 2.6 `role_permissions`
`role_id` FK · `permission_id` FK · `granted_at` · `granted_by`. PK `(role_id, permission_id)`.

### 2.7 `user_roles` (membership assignment)
`id` · `user_id` FK · `role_id` FK · `tenant_id` FK · `assigned_at` · `assigned_by` ·
`expires_at` NULL. `UNIQUE (user_id, role_id, tenant_id)`.
Constraint trigger: the role's tenant must match the row's tenant (or the role
is a system role) — enforced in service layer **and** by a `CHECK`-able
denormalised column compared in a trigger, because BR-12 permits no ambiguity.

### 2.8 `sessions`
`id UUID PK` (the session id embedded in tokens) · `user_id` FK ·
`tenant_id` FK · `refresh_token_hash TEXT NOT NULL` (SHA-256 of the token,
never the token) · `family_id UUID NOT NULL` (rotation family) ·
`previous_session_id` NULL · `issued_at` · `expires_at` · `revoked_at` ·
`revoked_reason` · `user_agent` · `ip_address INET` · `last_used_at`.
Indexes: `ix_sessions_user_active`, `ix_sessions_family`.
Refresh-token **reuse** revokes the whole `family_id`.

### 2.9 `api_keys`
`id` · `tenant_id` · `name` · `key_prefix TEXT` (visible) · `key_hash TEXT`
(Argon2/SHA-256 of secret) · `scopes TEXT[]` · `created_by` · `last_used_at` ·
`expires_at` · `revoked_at` · `rotation_of_id` NULL. Never stores the raw key.

### 2.10 `audit_logs` (append-only)
`id BIGSERIAL` (high volume, append-only; UUID unnecessary) · `tenant_id` NULL ·
`actor_user_id` NULL · `actor_type` (`USER`,`SYSTEM`,`DEVICE`,`API_KEY`,`AI`) ·
`actor_label` (email/device id snapshot at time of action) · `action TEXT`
(`LOGIN`, `BIN_CREATED`, `ROUTE_OPTIMIZED`, …) · `resource_type` · `resource_id` ·
`outcome` (`SUCCESS`,`FAILURE`,`DENIED`) · `request_id` · `ip_address INET` ·
`user_agent` · `metadata JSONB` (redacted) · `created_at`.
Indexes: `(tenant_id, created_at DESC)`, `(resource_type, resource_id)`,
`(actor_user_id, created_at DESC)`. No `UPDATE`/`DELETE` grant for the app role.
Retention: configurable (default 24 months), enforced by a sweep job that
**archives before deleting**.

### 2.11 `tenant_settings`
`id` · `tenant_id` FK · `key TEXT` · `value JSONB` · `value_type`
(`STRING`,`NUMBER`,`BOOLEAN`,`JSON`,`DURATION`) · `updated_by`. `UNIQUE (tenant_id, key)`.
Typed accessor in code; unknown keys rejected.

### 2.12 `system_settings`
Same shape, platform scope, super-admin only.

---

## 3. Geography

### 3.1 `zones`
`id` · `tenant_id` · `code` · `name` · `description` · `zone_type`
(`WARD`,`DISTRICT`,`CAMPUS_SECTOR`,`BUILDING`,`INDUSTRIAL_BLOCK`) ·
`parent_zone_id` NULL (self-FK; recursion depth-limited in service) ·
`boundary_geojson JSONB` NULL (polygon; validated as a closed ring with ≥4 points) ·
`centroid_latitude/longitude NUMERIC` · `priority SMALLINT` (feeds `w_zone`) ·
`population INTEGER NULL` · `status` · timestamps. `UNIQUE (tenant_id, code)`.

### 3.2 `service_areas`
`id` · `tenant_id` · `zone_id` FK · `code` · `name` · `service_frequency`
(`DAILY`,`ALTERNATE_DAY`,`TWICE_WEEKLY`,`WEEKLY`,`ON_DEMAND`) ·
`days_of_week SMALLINT[]` (validated 1–7, no duplicates) ·
`service_window_start TIME` · `service_window_end TIME` (CHECK end > start) ·
`sla_hours INTEGER` · `default_vehicle_type_id` NULL · `status`.

### 3.3 `addresses`
`id` · `tenant_id` · `line1` · `line2` · `landmark` · `city` · `state` ·
`postal_code` · `country` · `latitude NUMERIC(9,6)` · `longitude NUMERIC(10,7)` ·
`geohash TEXT` (generated, for coarse proximity indexing) · `access_notes`.
CHECK bounds on coordinates; `geohash` computed in a trigger.

> **Geo note (ADR-0005).** No `geometry`/`geography` column is required.
> When `GEO_ENABLE_POSTGIS=true` the migration adds
> `geom geometry(Point,4326) GENERATED ALWAYS AS (ST_SetSRID(ST_MakePoint(longitude, latitude),4326)) STORED`
> plus a GiST index. The repository picks `ST_DWithin` or
> bbox+haversine accordingly; both return identical result sets.

### 3.4 `geo_points` (reusable lightweight point registry)
Used for ad-hoc points that are not bins/facilities (depots, temporary
collection points, landmarks). `id` · `tenant_id` · `label` · `point_type` ·
lat/lng · `address_id` NULL · `status`.

---

## 4. Waste taxonomy

### 4.1 `waste_categories`
`id` · `tenant_id` NULL (**NULL = platform-provided baseline**) · `code` ·
`name` · `description` · `parent_id` NULL (self-FK for subcategories) ·
`is_recyclable BOOLEAN` · `is_hazardous BOOLEAN` · `is_organic BOOLEAN` ·
`is_compostable BOOLEAN` · `disposal_route waste_disposal_route`
(`RECYCLE`,`COMPOST`,`RECOVER_ENERGY`,`TREAT`,`LANDFILL`,`SPECIAL_HANDLING`) ·
`default_emission_factor_id` NULL · `sensitivity_weight NUMERIC(4,3)` (feeds
`w_category`) · `icon` · `colour` (UI token) · `is_system` · `status`.
The eleven baseline categories from section 8 are seeded as `is_system=true`,
`tenant_id NULL`; tenant extensions set `tenant_id`.

### 4.2 `waste_materials`
Finer-grained material under a category (e.g. PET, HDPE, aluminium, e-waste
batteries). `id` · `tenant_id` NULL · `category_id` FK · `code` · `name` ·
`recyclability_grade SMALLINT` (1–5) · `unit` · `density_kg_per_l NUMERIC(8,4)` NULL ·
`market_value_per_kg NUMERIC(12,4)` NULL · `status`. `UNIQUE (tenant_id, code)`.

### 4.3 `waste_category_mappings` (import/config compatibility)
Maps external strings (CSV imports, partner systems, LLM-suggested labels) to a
canonical category. `id` · `tenant_id` · `source_system TEXT` · `external_label` ·
`waste_category_id` FK · `waste_material_id` NULL · `confidence NUMERIC(4,3)`.
`UNIQUE (tenant_id, source_system, external_label)`. This is how imports stay
deterministic instead of relying on fuzzy matching at runtime.

---

## 5. Bins, sensors and telemetry

### 5.1 `bin_types`
`id` · `tenant_id` NULL (NULL = shared baseline) · `code` · `name` ·
`capacity_liters NUMERIC(10,3) NOT NULL CHECK (> 0)` ·
`tare_weight_kg NUMERIC(10,3)` · `material` (`PLASTIC`,`STEEL`,`CONCRETE`,`COMPOSITE`) ·
`has_lid_ sensor_ready BOOLEAN`s → `has_sensor_mount BOOLEAN`, `has_compactor BOOLEAN`,
`has_weighing BOOLEAN` · `dimensions_mm JSONB` · `status`.

### 5.2 `bins`
`id` · `tenant_id` · `bin_code TEXT` (`UNIQUE (tenant_id, bin_code)`) ·
`bin_type_id` FK · `zone_id` FK NULL · `service_area_id` FK NULL ·
`address_id` FK NULL · `waste_category_id` FK NOT NULL ·
`capacity_liters NUMERIC(10,3) NOT NULL CHECK (> 0)` (denormalised from type so
capacity history is preserved if the type changes) ·
`status bin_status` (`ACTIVE`,`FULL`,`MAINTENANCE`,`DAMAGED`,`DECOMMISSIONED`) ·
`latitude NUMERIC(9,6) NOT NULL CHECK (-90..90)` ·
`longitude NUMERIC(10,7) NOT NULL CHECK (-180..180)` ·
`installation_date` · `last_collection_at` · `last_telemetry_at` ·
`is_sensorized BOOLEAN NOT NULL DEFAULT false` · `is_public_facing BOOLEAN` ·
`access_notes` · `qr_code` · `photo_file_id` NULL · `version` · audit columns ·
`deleted_at`.

Indexes: `uq_bins_tenant_code`, `ix_bins_tenant_status`,
`ix_bins_tenant_zone`, `ix_bins_tenant_location (tenant_id, latitude, longitude)`
(for bbox pre-filter), `ix_bins_last_telemetry` (offline sweeps).

Constraints: `CHECK (is_sensorized OR bin_type_id IS NOT NULL)` is intentionally
absent; instead a service rule mirrors BR-05. A genuine `CHECK` enforces
`capacity_liters > 0`.

### 5.3 `bin_sensors`
`id` · `tenant_id` · `bin_id` FK · `device_id TEXT NOT NULL`
(`UNIQUE (tenant_id, device_id)`) · `sensor_type` (`FILL_LEVEL`,`WEIGHT`,
`TEMPERATURE`,`COMBINED`,`GAS`,`LID_STATE`) · `vendor` · `model` · `firmware_version` ·
`installed_at` · `removed_at` NULL · `connectivity_status sensor_status`
(`ONLINE`,`DEGRADED`,`OFFLINE`,`FAULTY`,`MAINTENANCE`) · `calibration_offset` ·
`calibration_at` · `battery_reported_at` · `last_seen_at` · `status`.
Partial unique index ensures **one active sensor per bin per type**:
`UNIQUE (bin_id, sensor_type) WHERE removed_at IS NULL`.

### 5.4 `bin_telemetry` (high-volume, append-only)
`id BIGSERIAL` · `tenant_id` · `bin_id` FK · `sensor_id` FK NULL ·
`recorded_at TIMESTAMPTZ NOT NULL` · `received_at TIMESTAMPTZ NOT NULL DEFAULT now()` ·
`fill_percentage NUMERIC(5,2) NULL CHECK (0 ≤ x ≤ 100)` ·
`weight_kg NUMERIC(12,3) NULL CHECK (>= 0)` ·
`volume_liters NUMERIC(12,3) NULL` ·
`temperature_c NUMERIC(6,2) NULL CHECK (-60 ≤ x ≤ 200)` ·
`humidity_percentage NUMERIC(5,2) NULL` · `battery_percentage NUMERIC(5,2) NULL CHECK (0 ≤ x ≤ 100)` ·
`signal_strength_dbm SMALLINT NULL` · `sensor_status sensor_status` ·
`gateway_id TEXT` · `source telemetry_source` (`SENSOR`,`SIMULATOR`,`MANUAL`,`IMPORT`) ·
`quality_flags TEXT[]` (e.g. `{frozen_value}`, `{out_of_range_rejected_partial}`) ·
`ingestion_batch_id UUID` NULL · `raw_payload JSONB` NULL (bounded size).
`UNIQUE (bin_id, sensor_id, recorded_at)` — the **deduplication key** (BR-03);
duplicate replays resolve to `ON CONFLICT DO NOTHING`, making ingestion
idempotent.

Indexes: `ix_bin_telemetry_latest (tenant_id, bin_id, recorded_at DESC)`,
`ix_bin_telemetry_time_brin` (BRIN on `recorded_at`),
`ix_bin_telemetry_batch (ingestion_batch_id)`.

Retention: configurable (default 24 months raw; aggregates kept indefinitely).

### 5.5 `bin_telemetry_latest` (read model)
One row per bin, upserted on ingest: `bin_id PK` · `tenant_id` ·
`fill_percentage` · `weight_kg` · `temperature_c` · `battery_percentage` ·
`signal_strength_dbm` · `sensor_status` · `recorded_at` · `is_overflow_risk BOOLEAN` ·
`updated_at`. Keeps the operations dashboard O(bins) instead of O(telemetry)
(section 51). Rebuildable from `bin_telemetry`, so a corruption is recoverable.

### 5.6 `ingestion_batches`
`id` · `tenant_id` · `device_gateway_id` · `received_at` · `reading_count` ·
`accepted_count` · `rejected_count` · `duplicate_count` · `error_summary JSONB` ·
`source`. Makes "why did my device's data not appear" answerable.

### 5.7 `bin_alerts`
`id` · `tenant_id` · `bin_id` FK · `alert_type bin_alert_type`
(`OVERFLOW`,`OVERFLOW_RISK`,`SENSOR_OFFLINE`,`LOW_BATTERY`,`TEMPERATURE_HIGH`,
`FIRE_RISK`,`ABNORMAL_FILL`,`SENSOR_FAULT`) · `severity severity` · `status`
(`OPEN`,`ACKNOWLEDGED`,`RESOLVED`,`SUPPRESSED`) · `triggered_at` ·
`trigger_value NUMERIC` · `threshold_value NUMERIC` · `rule_code TEXT` ·
`acknowledged_by`/`acknowledged_at` · `resolved_at` · `resolution_note` ·
`dedup_key TEXT` (`UNIQUE (tenant_id, dedup_key, open_state)` partial unique
index on open alerts prevents alert storms).

### 5.8 `bin_maintenance`
`id` · `tenant_id` · `bin_id` FK · `maintenance_type` (`CLEANING`,`REPAIR`,
`CALIBRATION`,`SENSOR_REPLACEMENT`,`INSPECTION`) · `status` · `reported_at` ·
`scheduled_for` · `completed_at` · `performed_by` · `cost NUMERIC(12,2)` ·
`notes` · `parts_replaced JSONB`.

---

## 6. Collections, fleet, workforce, routing

### 6.1 `collection_requests`
`id` · `tenant_id` · `request_code` · `bin_id` NULL · `zone_id` NULL ·
`address_id` NULL · `waste_category_id` · `requested_by_user_id` NULL ·
`source collection_request_source` (`MANUAL`,`CITIZEN`,`SENSOR_ALERT`,
`SCHEDULED`,`COMPLAINT`,`AI_RECOMMENDATION`) ·
`priority priority_level` · `requested_for_date DATE` ·
`status request_status` (`PENDING`,`SCHEDULED`,`IN_PROGRESS`,`FULFILLED`,
`REJECTED`,`CANCELLED`) · `description` · `estimated_quantity_kg NUMERIC(12,3)` NULL ·
`fulfilled_by_task_id` NULL · timestamps.
`CHECK (bin_id IS NOT NULL OR address_id IS NOT NULL OR zone_id IS NOT NULL)` —
a request must point at something collectable.

### 6.2 `collection_schedules`
`id` · `tenant_id` · `service_area_id` FK · `waste_category_id` FK ·
`recurrence_rule TEXT` (RFC-5545 RRULE, validated by `dateutil`) · `start_date` ·
`end_date` NULL · `service_window_start/end TIME` · `is_active` · `last_generated_at`.
The scheduler materialises `collection_tasks` forward (default 14 days) and is
idempotent on `(schedule_id, scheduled_date)`.

### 6.3 `collection_tasks`
`id` · `tenant_id` · `task_code` (`UNIQUE (tenant_id, task_code)`) ·
`collection_request_id` NULL · `schedule_id` NULL · `bin_id` FK NULL ·
`address_id` NULL · `zone_id` FK · `waste_category_id` FK ·
`route_id` FK NULL · `route_stop_id` FK NULL (set when sequenced) ·
`assigned_vehicle_id` FK NULL · `assigned_driver_id` FK NULL ·
`planned_date DATE NOT NULL` · `planned_window_start/end TIMESTAMPTZ` ·
`estimated_quantity_kg NUMERIC(12,3)` ·
`status collection_task_status` (the 10 states of §4.2 of the domain model) ·
`dispatched_at`,`started_at`,`arrived_at`,`completed_at` ·
`priority_score NUMERIC(8,4)` NULL (from the explainable `bin_intelligence`
scorer) · `priority_factors JSONB` NULL (**the factor breakdown — the
explanation**) · `failure_reason TEXT` NULL · `failure_notes` ·
`rescheduled_from_id` NULL (self-FK) · `version`.

Indexes: `ix_tasks_tenant_date_status`, `ix_tasks_route`, `ix_tasks_driver_date`,
`ix_tasks_bin_date`, `ix_tasks_overdue (tenant_id, planned_date) WHERE status NOT IN (completed states)`.

`CHECK (status <> 'FAILED' OR failure_reason IS NOT NULL)` — BR-07 encoded in
the database.

### 6.4 `collection_events` (facts)
`id` · `tenant_id` · `task_id` FK · `event_type` (`COLLECTED`,`PARTIAL`,
`SKIPPED`,`CONTAMINATED`,`OVERFLOW_FOUND`,`BIN_MISSING`,`ACCESS_DENIED`) ·
`occurred_at TIMESTAMPTZ NOT NULL` · `quantity_kg NUMERIC(12,3) NULL CHECK (>=0)` ·
`volume_liters NUMERIC(12,3)` · `fill_level_at_collection NUMERIC(5,2)` ·
`waste_category_id` (may differ from the planned one — contamination) ·
`contamination_level` (`NONE`,`LOW`,`MEDIUM`,`HIGH`) ·
`recorded_by_user_id` · `certification_source event_source`
(`MEASURED_ONBOARD`,`MANUAL_ENTRY`,`WEIGHBRIDGE`,`ESTIMATED`) ·
`notes` · `latitude/longitude` NULL (the recorded GPS at the stop) ·
`evidence_file_ids UUID[]` · `sync_state` (offline driver sync) · `client_uuid`
`UNIQUE (tenant_id, client_uuid)` — makes offline driver sync idempotent.

### 6.5 `vehicles`
`id` · `tenant_id` · `registration_number TEXT` (`UNIQUE (tenant_id, registration_number)`) ·
`vehicle_type_id` FK · `fleet_code` · `capacity_kg NUMERIC(12,3) NOT NULL CHECK (> 0)` ·
`capacity_m3 NUMERIC(10,3)` · `fuel_type fuel_type`
(`DIESEL`,`PETROL`,`CNG`,`ELECTRIC`,`HYBRID`,`HUMAN_POWERED`) ·
`status vehicle_status` (the 7 states of §4.3) · `ownership`
(`OWNED`,`LEASED`,`CONTRACTOR`) · `acquisition_date` · `odometer_km NUMERIC(12,1)` ·
`last_maintenance_at` · `next_maintenance_due` · `current_latitude/longitude` NULL ·
`current_location_updated_at` NULL · `has_compactor`,`has_weighbridge` BOOLEAN ·
`telematics_device_id` NULL · `version` · `deleted_at`.

### 6.6 `vehicle_types`
`id` · `tenant_id` NULL · `code` · `name` · `capacity_kg` · `capacity_m3` ·
`description` · `axle_configuration` · `typical_crew_size`.

### 6.7 `vehicle_telemetry`
`id BIGSERIAL` · `tenant_id` · `vehicle_id` FK · `recorded_at` ·
`latitude NUMERIC(9,6)` · `longitude NUMERIC(10,7)` · `speed_kph NUMERIC(6,2)` ·
`heading_degrees NUMERIC(5,2)` · `odometer_km` · `fuel_level_percentage` ·
`engine_hours` · `load_weight_kg NUMERIC(12,3)` (from onboard weighing) ·
`load_volume_m3` · `source telemetry_source` · `raw_payload JSONB`.
`UNIQUE (vehicle_id, recorded_at)`. Labelled `SIMULATOR` when simulated
(section 62 forbids presenting simulated positions as live).

### 6.8 `vehicle_capacities` (configuration history)
Effective-dated capacity overrides (e.g. a trailer change):
`vehicle_id` · `effective_from` · `effective_to` NULL · `capacity_kg` ·
`capacity_m3` · `reason`. Route planning uses the capacity effective on the
service date — the reason a simple column is not enough.

### 6.9 `vehicle_maintenance`
`id` · `vehicle_id` · `maintenance_type` (`PREVENTIVE`,`CORRECTIVE`,`INSPECTION`,
`TYRE`,`ENGINE`,`BODYWORK`) · `status` · `reported_at` · `scheduled_for` ·
`completed_at` · `cost NUMERIC(12,2)` · `odometer_at_service` · `vendor` ·
`parts JSONB` · `notes`.

### 6.10 `drivers`
`id` · `tenant_id` · `user_id` FK NULL (a driver may or may not have app access) ·
`employee_code` (`UNIQUE (tenant_id, employee_code)`) · `full_name` · `phone` ·
`licence_number` · `licence_class` · `licence_expiry DATE` ·
`status driver_status` (`ACTIVE`,`ON_LEAVE`,`SUSPENDED`,`INACTIVE`) ·
`home_depot_facility_id` NULL · `default_vehicle_id` NULL ·
`shift_preference` · `certifications TEXT[]` · `deleted_at`.

### 6.11 `driver_assignments`
`id` · `tenant_id` · `driver_id` FK · `vehicle_id` FK · `route_id` FK NULL ·
`assignment_date DATE` · `shift_start TIMESTAMPTZ` · `shift_end TIMESTAMPTZ` ·
`status` (`SCHEDULED`,`ACTIVE`,`COMPLETED`,`CANCELLED`,`NO_SHOW`) ·
`started_at`/`ended_at` · `notes`.
**Overlap guard:** exclusion constraint
`EXCLUDE USING gist (driver_id WITH =, tstzrange(shift_start, shift_end) WITH &&)`
(`btree_gist` unavailable → enforced by a partial unique index on
`(driver_id, assignment_date)` plus a service-layer overlap check; recorded as
an explicit limitation in Appendix A).

### 6.12 `routes`
`id` · `tenant_id` · `route_code` (`UNIQUE (tenant_id, route_code)`) ·
`route_date DATE NOT NULL` · `zone_id` FK NULL · `service_area_id` NULL ·
`vehicle_id` FK NULL · `driver_id` FK NULL · `status route_status` ·
`planned_start_at`/`planned_end_at` · `actual_start_at`/`actual_end_at` ·
`planned_distance_km NUMERIC(10,3)` · `actual_distance_km NUMERIC(10,3)` ·
`planned_duration_minutes INTEGER` · `actual_duration_minutes` ·
`planned_load_kg NUMERIC(12,3)` · `actual_load_kg NUMERIC(12,3)` ·
`stop_count INTEGER` · `completed_stop_count INTEGER` ·
`optimization_run_id` FK NULL (which solver run produced this plan) ·
`baseline_route_id` NULL (self-FK: what it is compared against) ·
`is_optimized BOOLEAN` · `notes` · `version`.

`CHECK (planned_load_kg IS NULL OR vehicle capacity not exceeded)` is enforced
in the service layer because capacity is effective-dated (BR-06).

### 6.13 `route_stops`
`id` · `tenant_id` · `route_id` FK · `stop_sequence INTEGER NOT NULL CHECK (> 0)` ·
`bin_id` FK NULL · `address_id` NULL · `collection_task_id` FK NULL ·
`latitude/longitude` (snapshot at planning time — the plan is reproducible even
if the bin later moves) · `planned_arrival_at` · `planned_departure_at` ·
`service_duration_minutes INTEGER CHECK (>= 0)` ·
`estimated_quantity_kg NUMERIC(12,3)` · `actual_arrival_at` · `actual_departure_at` ·
`status stop_status` (`PLANNED`,`ARRIVED`,`COMPLETED`,`SKIPPED`,`FAILED`) ·
`distance_from_previous_km NUMERIC(10,3)` · `travel_time_from_previous_minutes` ·
`skip_reason`.
`UNIQUE (route_id, stop_sequence)`, `UNIQUE (route_id, bin_id)`,
`UNIQUE (route_id, collection_task_id) WHERE collection_task_id IS NOT NULL`.

### 6.14 `route_optimization_runs` (append-only — ADR-0010)
`id` · `tenant_id` · `run_code` · `requested_by_user_id` · `status`
(`QUEUED`,`RUNNING`,`COMPLETED`,`FAILED`,`INFEASIBLE`,`TIMEOUT`) ·
`algorithm TEXT` (`ortools_cvrptw`) · `algorithm_version TEXT` ·
`objective_description TEXT` · `objective_weights JSONB` ·
`input_snapshot JSONB NOT NULL` (stops, capacities, windows, priorities,
depot — the exact input, so the run is reproducible) ·
`constraints JSONB` (capacity, time windows, max vehicles, max duration,
priority penalties) · `solver_status TEXT` · `is_optimal BOOLEAN` ·
`objective_value NUMERIC(14,3)` · `total_distance_km NUMERIC(12,3)` ·
`total_duration_minutes INTEGER` · `vehicles_used INTEGER` ·
`unassigned_stop_count INTEGER` · `execution_ms INTEGER` ·
`started_at`/`finished_at` · `error_message` ·
`baseline_run_id` NULL · `comparison JSONB` NULL (computed metrics vs baseline) ·
`created_at`. Never updated after `COMPLETED` (enforced by a trigger).

### 6.15 `route_assignments`
`id` · `tenant_id` · `route_id` FK · `vehicle_id` FK · `driver_id` FK ·
`assigned_by` · `assigned_at` · `unassigned_at` NULL · `reason` ·
`is_current BOOLEAN` (partial unique index: one current assignment per route).

### 6.16 `route_comparisons` (materialised comparison results — ADR-0010)
`id` · `tenant_id` · `optimized_route_id` FK · `baseline_type`
(`PREVIOUS_ROUTE`,`MANUAL_PLAN`,`NAIVE_PLAN`,`ALTERNATE_OPTIMIZATION`) ·
`baseline_route_id` FK NULL · `distance_delta_km` · `duration_delta_minutes` ·
`stops_delta` · `utilization_delta_pct` · `fuel_delta_liters` ·
`emissions_delta_kgco2e` · `priority_coverage_pct` ·
`metric_provenance JSONB` (each metric labelled estimated/measured) ·
`created_at`.

---

## 7. Facilities, loads, recovery, environment

### 7.1 `facility_types`
`id` · `tenant_id` NULL · `code` · `name` · `category facility_category`
(`TRANSFER_STATION`,`MATERIAL_RECOVERY`,`RECYCLING_CENTER`,`COMPOSTING`,
`TREATMENT_PLANT`,`WASTE_TO_ENERGY`,`LANDFILL`,`SPECIALIZED`).

### 7.2 `facilities`
`id` · `tenant_id` · `facility_code` (`UNIQUE (tenant_id, facility_code)`) ·
`name` · `facility_type_id` FK · `operating_entity` (`TENANT`,`THIRD_PARTY`) ·
`address_id` FK · `latitude/longitude` · `status facility_status`
(`OPERATIONAL`,`LIMITED`,`MAINTENANCE`,`CLOSED`,`DECOMMISSIONED`) ·
`daily_capacity_kg NUMERIC(14,3)` · `daily_capacity_m3` ·
`current_utilization_kg NUMERIC(14,3)` (derived, refreshed on load receipt) ·
`operating_hours JSONB` (`{"mon":{"open":"06:00","close":"20:00"},...}`) ·
`contact_name`/`contact_phone`/`contact_email` · `permit_number` ·
`permit_expiry` · `weighbridge_available BOOLEAN` ·
`acceptance_notes` · `deleted_at`.

### 7.3 `facility_capabilities`
`facility_id` FK · `waste_category_id` FK · `waste_material_id` NULL ·
`max_daily_kg NUMERIC(14,3)` · `processing_cost_per_kg NUMERIC(12,4)` ·
`is_primary_route BOOLEAN`. PK `(facility_id, waste_category_id, COALESCE(material))`.
Enforces BR-10: a load may only be sent where capability exists.

### 7.4 `facility_capacity_utilization` (daily rollup)
`facility_id` · `date` · `received_kg` · `processed_kg` · `capacity_kg` ·
`utilization_pct NUMERIC(5,2)` · `rejected_kg`. PK `(facility_id, date)`.

### 7.5 `waste_loads` (traceability spine — section 19)
`id` · `tenant_id` · `load_code TEXT` (`UNIQUE (tenant_id, load_code)`) ·
`origin_type` (`COLLECTION`,`TRANSFER`,`DIRECT_DELIVERY`,`FACILITY_INTAKE`) ·
`origin_collection_event_id` FK NULL · `origin_task_id` NULL ·
`origin_zone_id` NULL · `origin_facility_id` NULL ·
`vehicle_id` FK NULL · `driver_id` FK NULL ·
`departed_at` · `arrived_at` NULL · `closed_at` NULL ·
`declared_weight_kg NUMERIC(12,3)` · `measured_weight_kg NUMERIC(12,3)` NULL ·
`volume_m3 NUMERIC(10,3)` NULL · `weighbridge_ticket_number` ·
`destination_facility_id` FK NULL · `status load_status`
(`FORMING`,`IN_TRANSIT`,`RECEIVED`,`PROCESSING`,`CLOSED`,`REJECTED`) ·
`rejection_reason` · `contamination_level` · `chain_of_custody JSONB`
(append-only array of custody handoffs with actor/timestamp) · `version`.
`CHECK (measured_weight_kg IS NULL OR measured_weight_kg >= 0)`.

### 7.6 `waste_load_items` (composition)
`id` · `tenant_id` · `waste_load_id` FK · `waste_category_id` FK ·
`waste_material_id` NULL · `weight_kg NUMERIC(12,3) CHECK (>= 0)` ·
`percentage NUMERIC(5,2) CHECK (0..100)` · `source`
(`MEASURED`,`ESTIMATED_VISUAL`,`SORTING_ANALYSIS`,`DEFAULT_MIX`) ·
`classification_id` FK NULL (when composition came from CV classification).
Service rule BR-08 enforces Σ percentage = 100 ± 0.01 across a load.

### 7.7 `waste_transfers` (custody handoffs)
`id` · `tenant_id` · `waste_load_id` FK · `from_facility_id` NULL ·
`to_facility_id` FK · `transferred_at` · `weight_kg NUMERIC(12,3)` ·
`vehicle_id` NULL · `handover_user_id` · `receiving_user_id` ·
`receiving_confirmed_at` · `document_file_id` NULL · `notes`.

### 7.8 Processing outcome tables (one logical pattern, four physical tables)

`recovery_events` · `composting_events` · `treatment_events` · `disposal_events`

Shared columns: `id` · `tenant_id` · `waste_load_id` FK · `facility_id` FK ·
`waste_category_id` FK · `waste_material_id` NULL · `occurred_at` ·
`input_weight_kg NUMERIC(12,3)` · `output_weight_kg NUMERIC(12,3)` ·
`recovery_rate NUMERIC(5,2)` · `process_method TEXT` · `batch_reference` ·
`recorded_by_user_id` · `provenance provenance_kind` ·
`notes` · `created_at`.

Outcome-specific columns:
* `recovery_events`: `recovery_type recovery_type`
  (`RECYCLED`,`REUSED`,`ENERGY_RECOVERY`,`MATERIAL_RECOVERY`,`OTHER_RECOVERY`) ·
  `material_grade` · `revenue NUMERIC(14,2)` NULL · `buyer_name`.
* `composting_events`: `compost_grade` · `curing_days` · `moisture_pct` ·
  `output_weight_kg` (compost produced).
* `treatment_events`: `treatment_type`
  (`INCINERATION_WITH_RECOVERY`,`ANAEROBIC_DIGESTION`,`CHEMICAL`,`STERILIZATION`,
  `AUTOCLAVE`) · `energy_recovered_kwh NUMERIC(14,3)` NULL · `residue_weight_kg`.
* `disposal_events`: `disposal_type` (`LANDFILL`,`INCINERATION_NO_RECOVERY`,
  `OPEN_DUMP`,`SPECIAL_HANDLING`) · `landfill_cell` · `residue_weight_kg`.

> Why four tables instead of one polymorphic table: each has genuinely distinct
> attributes, the reporting queries filter by family, and a single table with
> half-null columns cannot carry meaningful `CHECK` constraints. A database
> `VIEW` (`v_processing_outcomes`) unifies them for analytics, keeping BR-09
> enforceable per family and the analytics path simple.

### 7.9 `emission_factors` (versioned — BR-11)
`id` · `tenant_id` NULL (NULL = platform baseline library) · `factor_code` ·
`name` · `activity_type` (`FUEL_COMBUSTION`,`ELECTRICITY`,`TRANSPORT`,
`WASTE_TREATMENT`,`LANDFILL_AVOIDED`,`MATERIAL_RECOVERY`,`COMPOSTING`) ·
`activity_unit` · `factor_value NUMERIC(16,8)` ·
`result_unit` (`KG_CO2E`,`KG_CO2E_PER_KG`,`KG_CO2E_PER_LITER`,`KG_CO2E_PER_KWH`) ·
`source TEXT NOT NULL` (e.g. "IPCC 2006 Guidelines, Vol 5") ·
`source_url` · `geography TEXT` (`GLOBAL`,`IN`,`US`,…) ·
`methodology TEXT` · `effective_from DATE NOT NULL` · `effective_to DATE NULL` ·
`is_active` · `superseded_by_id` NULL · `created_by` · `created_at`.
`UNIQUE (COALESCE(tenant_id,'...'), factor_code, effective_from)`.
No emission number ever appears as a literal in application code.

### 7.10 `carbon_estimates` (append-only)
`id` · `tenant_id` · `estimate_type` (`COLLECTION_TRANSPORT`,`FACILITY_PROCESSING`,
`AVOIDED_DISPOSAL`,`RECYCLING_OFFSET`,`TOTAL_OPERATION`) ·
`subject_type` (`ROUTE`,`COLLECTION_TASK`,`WASTE_LOAD`,`FACILITY`,`ZONE`,`TENANT`) ·
`subject_id` · `period_start`/`period_end` ·
`activity_quantity NUMERIC(16,4)` · `activity_unit` ·
`emission_factor_id` FK NOT NULL · `factor_value_snapshot NUMERIC(16,8)`
(the factor as used, frozen) · `emitted_kgco2e NUMERIC(16,4)` ·
`avoided_kgco2e NUMERIC(16,4)` NULL · `net_kgco2e NUMERIC(16,4)` ·
`calculation_method TEXT` · `assumptions JSONB` ·
`provenance provenance_kind` (`ESTIMATED` in practice) · `calculated_at`.
Index: `(tenant_id, subject_type, subject_id, period_start DESC)`.

### 7.11 `environmental_metrics` (period rollups)
`id` · `tenant_id` · `period_type` (`DAY`,`WEEK`,`MONTH`,`QUARTER`,`YEAR`) ·
`period_start`/`period_end` · `scope_type` (`TENANT`,`ZONE`,`FACILITY`,`CATEGORY`) ·
`scope_id` NULL · `metric_code` (references the definition registry) ·
`metric_value NUMERIC(18,6)` · `unit` · `provenance provenance_kind` ·
`computation_definition_version TEXT` · `is_partial_period BOOLEAN` ·
`computed_at`. `UNIQUE (tenant_id, period_type, period_start, scope_type, scope_id, metric_code)`.
Storing the `computation_definition_version` is what prevents silently comparing
metrics computed under different definitions (section 20).

---

## 8. Intelligence: forecasts, anomalies, classification, recommendations

### 8.1 `ai_models` (registry root)
`id` · `tenant_id` NULL (NULL = platform-provided model) · `code` ·
`name` · `model_type` (`WASTE_CLASSIFICATION`,`FILL_FORECAST`,`VOLUME_FORECAST`,
`ANOMALY_DETECTION`,`OVERFLOW_RISK`) · `task_description` ·
`is_system` · `status` (`ACTIVE`,`DEPRECATED`,`ARCHIVED`) · `created_at`.

### 8.2 `ai_model_versions`
`id` · `model_id` FK · `version TEXT NOT NULL` · `status model_version_status`
(`CANDIDATE`,`ACTIVE`,`RETIRED`,`FAILED`) ·
`algorithm_family TEXT` (`CLASSICAL_CV`,`GBT_REGRESSOR`,`SEASONAL_NAIVE`,
`EXPONENTIAL_SMOOTHING`,`ISOLATION_FOREST`,`ZSCORE`,`LOGISTIC_RISK`) ·
`framework` · `framework_version` · `hyperparameters JSONB` ·
`feature_definition JSONB NOT NULL` (the feature contract) ·
`artifact_path TEXT` · `artifact_checksum TEXT` (SHA-256) ·
`training_dataset_id` FK · `training_started_at`/`training_completed_at` ·
`training_duration_seconds` · `trained_by_user_id` NULL ·
`promoted_at`/`promoted_by` · `retired_at` · `notes`.
**Partial unique index:** `UNIQUE (model_id) WHERE status = 'ACTIVE'` — BR-14
enforced by the database, not by convention.

### 8.3 `ml_datasets`
`id` · `tenant_id` NULL · `name` · `version` · `dataset_type`
(`LABELLED_IMAGES`,`TELEMETRY_HISTORY`,`COLLECTION_HISTORY`,`SYNTHETIC`) ·
`row_count` · `date_range_start`/`date_range_end` · `checksum` ·
`storage_path` · `is_synthetic BOOLEAN NOT NULL` ·
`generation_parameters JSONB` (seed, distribution — required when synthetic) ·
`created_at`. Section 49's "training dataset version" lives here; `is_synthetic`
is never optional, so synthetic-corpus evaluation can never masquerade as field
validation.

### 8.4 `model_metrics`
`id` · `model_version_id` FK · `dataset_id` FK NOT NULL ·
`evaluation_type` (`TRAINING`,`VALIDATION`,`TEST`,`HOLDOUT`,`SYNTHETIC_BENCH`) ·
`metric_name` (`accuracy`,`precision_macro`,`recall_macro`,`f1_macro`,`mae`,`rmse`,
`mape`,`r2`,`auc`,`coverage`) · `metric_value NUMERIC(10,6)` · `per_class JSONB` NULL ·
`confusion_matrix JSONB` NULL · `sample_count` · `computed_at`. `UNIQUE (model_version_id, dataset_id, evaluation_type, metric_name)`.
`evaluation_type='TRAINING'` results are stored but **never** presented as
validation performance (section 49).

### 8.5 `forecast_runs` (append-only)
`id` · `tenant_id` · `model_version_id` FK · `status run_status` ·
`subject_type` (`BIN`,`ZONE`,`TENANT`,`CATEGORY`) · `subject_id` NULL ·
`target_metric` (`WASTE_VOLUME_L`,`WASTE_WEIGHT_KG`,`BIN_FILL_PCT`,
`COLLECTION_COUNT`) · `granularity` (`HOUR`,`DAY`,`WEEK`,`MONTH`) ·
`horizon_periods INTEGER NOT NULL CHECK (> 0)` · `horizon_start`/`horizon_end` ·
`input_window_start`/`input_window_end` · `input_record_count` ·
`feature_definition_snapshot JSONB` · `random_seed BIGINT NULL` ·
`started_at`/`finished_at` · `execution_ms` · `error_message` ·
`is_backtest BOOLEAN` · `created_at`.

### 8.6 `forecasts`
`id` · `tenant_id` · `forecast_run_id` FK · `forecast_for TIMESTAMPTZ NOT NULL` ·
`horizon_step INTEGER NOT NULL` · `predicted_value NUMERIC(16,4)` ·
`lower_bound`/`upper_bound NUMERIC(16,4)` NULL (**uncertainty interval**) ·
`confidence_level NUMERIC(4,3)` NULL (e.g. 0.80) ·
`baseline_value NUMERIC(16,4)` NULL (e.g. seasonal-naive, for comparison) ·
`provenance provenance_kind` (always `PREDICTED`) · `created_at`.
`UNIQUE (forecast_run_id, forecast_for)`.

### 8.7 `anomalies`
`id` · `tenant_id` · `detected_at` · `occurred_at` ·
`subject_type` (`BIN`,`VEHICLE`,`ROUTE`,`FACILITY`,`ZONE`,`TENANT`) · `subject_id` ·
`metric_name` · `observed_value NUMERIC(18,6)` · `expected_value NUMERIC(18,6)` NULL ·
`deviation NUMERIC(18,6)` · `deviation_unit` (`SIGMA`,`PERCENT`,`ABSOLUTE`) ·
`detection_method` (`ZSCORE`,`IQR`,`MOVING_BASELINE`,`ISOLATION_FOREST`) ·
`method_parameters JSONB` · `baseline_window_start`/`end` ·
`score NUMERIC(10,6)` · `threshold NUMERIC(10,6)` ·
`severity severity` · `status` (`OPEN`,`ACKNOWLEDGED`,`RESOLVED`,`FALSE_POSITIVE`) ·
`reviewed_by`/`reviewed_at` · `notes` · `model_version_id` FK NULL ·
`created_at`. `UNIQUE (tenant_id, subject_type, subject_id, metric_name, occurred_at, detection_method)`.

### 8.8 `anomaly_events` (correlation/grouping)
`id` · `tenant_id` · `title` · `description` · `severity` · `status` ·
`first_detected_at` · `last_seen_at` · `anomaly_ids UUID[]` ·
`affected_zones UUID[]` · `root_cause_hypothesis TEXT` · `assigned_to` ·
`resolution_note`. Groups related anomalies into an incident for triage.

### 8.9 `waste_classifications`
`id` · `tenant_id` · `file_asset_id` FK NOT NULL (the image) ·
`bin_id` NULL · `collection_event_id` NULL · `waste_load_id` NULL ·
`model_version_id` FK NOT NULL · `predicted_category_id` FK ·
`predicted_material_id` NULL · `confidence NUMERIC(5,4) NOT NULL CHECK (0..1)` ·
`top_k JSONB` (ranked alternatives with scores) ·
`classification_method` (`CLASSICAL_CV`,`DEEP_LEARNING`,`MANUAL`) ·
`inference_ms INTEGER` · `image_hash TEXT` (dedup/caching) ·
`needs_review BOOLEAN NOT NULL DEFAULT false` · `review_status`
(`NOT_REQUIRED`,`PENDING`,`CONFIRMED`,`CORRECTED`) ·
`reviewed_by`/`reviewed_at` · `corrected_category_id` NULL ·
`corrected_material_id` NULL · `review_notes` ·
`provenance provenance_kind` (`PREDICTED` for model output, `USER_ENTERED` for
corrections) · `created_at`, `human_corrected_at` (section 8 of the master
prompt: "human verification status").

### 8.10 `classification_feedback`
`id` · `tenant_id` · `waste_classification_id` FK · `feedback_type`
(`CORRECT`,`INCORRECT`,`RELABELLED`,`LOW_QUALITY_IMAGE`) ·
`corrected_label TEXT` · `comment` · `provided_by` · `provided_at` ·
`used_in_training_dataset_id` NULL. Closed loop for future retraining —
tracked so that a future model can cite which feedback trained it.

### 8.11 `recommendations`
`id` · `tenant_id` · `recommendation_code` · `type recommendation_type`
(`COLLECTION_PRIORITY`,`ROUTE_OPTIMIZATION`,`OVERFLOW_PREVENTION`,
`MAINTENANCE`,`FACILITY_REBALANCE`,`CAPACITY_PLANNING`,`ANOMALY_INVESTIGATION`,
`FUEL_REDUCTION`) · `title` · `description` · `priority priority_level` ·
`status recommendation_status` (the 6 states of §4.5) · `confidence NUMERIC(5,4)` NULL ·
`evidence JSONB NOT NULL` (**required**: metric names, values, source windows,
ids of the rows consulted) · `source_metrics JSONB` ·
`generated_by model_version_id` NULL · `generator`
(`RULE_ENGINE`,`STATISTICAL_MODEL`,`ASSISTANT`) · `valid_until` ·
`estimated_impact JSONB` NULL (with provenance labels) ·
`actions JSONB` (deep-link targets, e.g. "open route optimizer with these
stops") · `created_at` · `executed_at` · `executed_reference_type`/`_id` ·
`expires_at`.
A `CHECK` requires `jsonb_array_length(evidence->'items') > 0` — an evidence-free
recommendation cannot be inserted (BR-16).

### 8.12 `recommendation_feedback`
`id` · `tenant_id` · `recommendation_id` FK · `user_id` · `feedback`
(`ACCEPTED`,`REJECTED`,`NOT_USEFUL`,`ALREADY_DONE`) · `reason_code` ·
`comment` · `created_at`.

---

## 9. Notifications, reporting, files, integrations

### 9.1 `notifications`
`id` · `tenant_id` · `recipient_user_id` FK · `notification_type notification_type`
(the 10 types of section 26) · `severity severity` · `title` · `body` ·
`action_url` · `action_label` · `resource_type`/`resource_id` NULL ·
`channel` (`IN_APP`,`EMAIL`,`PUSH`,`WEBHOOK`) · `status`
(`PENDING`,`SENT`,`FAILED`,`READ`,`DISMISSED`) ·
`dedup_key TEXT NULL` with `UNIQUE (tenant_id, recipient_user_id, dedup_key)`
partial index (deduplication requirement) · `read_at` · `sent_at` ·
`delivery_attempts SMALLINT` · `last_error` · `expires_at` · `created_at`.

### 9.2 `notification_preferences`
`id` · `tenant_id` · `user_id` FK · `notification_type` ·
`in_app_enabled`,`email_enabled`,`push_enabled`,`webhook_enabled` BOOLEAN ·
`min_severity severity` · `quiet_hours_start`/`end TIME` NULL ·
`digest_frequency` (`INSTANT`,`HOURLY`,`DAILY`,`WEEKLY`).
`UNIQUE (user_id, notification_type)`.

### 9.3 `notification_templates`
`id` · `tenant_id` NULL · `notification_type` · `channel` · `locale` ·
`subject_template` · `body_template` · `variables JSONB` ·
`UNIQUE (COALESCE(tenant_id,'...'), notification_type, channel, locale)`.
Templates hold user-facing copy, supporting i18n readiness (section 54).

### 9.4 `report_definitions`
`id` · `tenant_id` NULL · `code` · `name` · `description` · `report_type`
(`OPERATIONAL`,`WASTE_GENERATION`,`COLLECTION_PERFORMANCE`,`RECYCLING`,
`ENVIRONMENTAL`,`VEHICLE`,`FACILITY`,`EXECUTIVE_SUMMARY`) ·
`parameter_schema JSONB NOT NULL` (validated at request time) ·
`data_provider TEXT` (the service function that builds it) ·
`is_system` · `status`.

### 9.5 `report_runs` (append-only)
`id` · `tenant_id` · `report_definition_id` FK · `parameters JSONB NOT NULL` ·
`requested_by_user_id` · `status` (`QUEUED`,`RUNNING`,`COMPLETED`,`FAILED`) ·
`row_count` · `payload JSONB` (the structured result — rendering is separate,
section 43) · `export_file_id` FK NULL · `export_format`
(`CSV`,`XLSX`,`PDF`,`JSON`) · `started_at`/`finished_at` · `error_message`.

### 9.6 `file_assets`
`id` · `tenant_id` · `owner_type` (`BIN`,`COLLECTION_EVENT`,`WASTE_LOAD`,
`CLASSIFICATION`,`REPORT_RUN`,`ORGANIZATION`,`MAINTENANCE`,`USER_AVATAR`) ·
`owner_id` NULL · `original_filename TEXT` (stored for display **only**) ·
`stored_filename TEXT NOT NULL` (server-generated UUID — never user input) ·
`storage_provider` · `storage_path TEXT NOT NULL` · `content_type TEXT NOT NULL`
(detected by content sniffing, not by the client) · `size_bytes BIGINT CHECK (> 0)` ·
`checksum_sha256 TEXT` · `width_px`/`height_px` INTEGER (images) ·
`uploaded_by` · `scan_status` (`PENDING`,`CLEAN`,`REJECTED`,`SKIPPED`) ·
`scan_detail TEXT` · `deleted_at` · `created_at`.
Path-traversal defence: `CHECK (stored_filename !~ '[/\\]')` and the storage
adapter refuses any path escaping the configured root.

### 9.7 `integrations`
`id` · `tenant_id` NULL · `code` · `name` · `integration_type`
(`ROUTING`,`WEATHER`,`EMAIL`,`SMS`,`IOT_GATEWAY`,`FLEET_TRACKING`,
`MUNICIPAL_SYSTEM`,`STORAGE`,`LLM`) · `adapter_class TEXT NOT NULL` ·
`configuration JSONB` (**secrets referenced by key name, values stored
encrypted/out-of-band — never plaintext in this column**) ·
`is_enabled` · `last_health_check_at` · `last_health_status` · `status`.

### 9.8 `webhooks`
`id` · `tenant_id` · `event_type` · `target_url TEXT NOT NULL`
(`CHECK (target_url ~ '^https://')` in production mode) ·
`secret_hash TEXT NOT NULL` (HMAC signing secret) · `is_active` ·
`failure_count` · `last_success_at` · `last_failure_at` · `disabled_at`.

### 9.9 `webhook_deliveries`
`id` · `tenant_id` · `webhook_id` FK · `event_id UUID NOT NULL` · `event_type` ·
`payload JSONB` · `status` (`PENDING`,`DELIVERED`,`FAILED`,`DEAD_LETTER`) ·
`attempt_count` · `response_status` · `response_body_excerpt` ·
`next_retry_at` · `delivered_at`. `UNIQUE (webhook_id, event_id)` —
idempotent delivery under retries.

### 9.10 `domain_events` (transactional outbox)
`id UUID` · `tenant_id` NULL · `event_type TEXT NOT NULL` ·
`aggregate_type`/`aggregate_id` · `payload JSONB NOT NULL` ·
`occurred_at` · `published_at` NULL · `attempt_count` · `last_error`.
Index: `(published_at NULLS FIRST, occurred_at)` for the dispatcher sweep.

### 9.11 `job_runs` (ADR-0009)
`id` · `tenant_id` NULL · `job_name TEXT NOT NULL` · `job_key TEXT`
(natural idempotency key) · `payload JSONB` · `status` (`QUEUED`,`RUNNING`,
`SUCCEEDED`,`FAILED`,`SKIPPED_DUPLICATE`) · `attempt` · `max_attempts` ·
`scheduled_at`/`started_at`/`finished_at` · `duration_ms` · `result JSONB` ·
`error_message`. `UNIQUE (job_name, job_key)` where `job_key IS NOT NULL`
prevents duplicate scheduling on retry.

### 9.12 `scoring_configurations` (explainability of §7.1)
`id` · `tenant_id` · `score_type` (`COLLECTION_PRIORITY`,`OVERFLOW_RISK`) ·
`weights JSONB NOT NULL` · `thresholds JSONB` · `version TEXT` ·
`is_active` · `updated_by`. Partial unique index on `(tenant_id, score_type)
WHERE is_active`.

### 9.13 `data_retention_policies`
`id` · `tenant_id` NULL · `data_class` (`BIN_TELEMETRY`,`VEHICLE_TELEMETRY`,
`AUDIT_LOG`,`NOTIFICATION`,`JOB_RUN`,`ANOMALY`,`REPORT_RUN`) ·
`retention_days INTEGER NOT NULL CHECK (> 0)` · `archive_before_delete BOOLEAN` ·
`last_enforced_at`. Makes section 68 (retention) configuration rather than a
promise.

---

## 10. Entity-relationship overview (principal relationships)

```
tenants ─┬─< users ─┬─< sessions
         │          ├─< user_roles >─ roles ─< role_permissions >─ permissions
         │          └─< notifications
         ├─< zones ─< service_areas
         ├─< bins >─ bin_types, waste_categories
         │    └─< bin_sensors ─< bin_telemetry
         │    └─< bin_alerts, bin_maintenance
         ├─< collection_schedules ─< collection_tasks
         ├─< collection_requests ─< collection_tasks ─< collection_events
         ├─< routes ─< route_stops
         │     ├── vehicle_id ─> vehicles ─< vehicle_telemetry, vehicle_maintenance
         │     ├── driver_id  ─> drivers  ─< driver_assignments
         │     └── optimization_run_id ─> route_optimization_runs
         ├─< waste_loads ─< waste_load_items >─ waste_materials >─ waste_categories
         │     ├─< waste_transfers
         │     └─< recovery_events | composting_events | treatment_events | disposal_events
         ├─< facilities ─< facility_capabilities >─ waste_categories
         ├─< emission_factors ─< carbon_estimates
         ├─< environmental_metrics
         ├─< forecast_runs ─< forecasts
         ├─< anomalies ─< anomaly_events
         ├─< waste_classifications ─< classification_feedback
         ├─< recommendations ─< recommendation_feedback
         ├─< report_runs >─ report_definitions
         └─< audit_logs, file_assets, integrations, webhooks, job_runs
```

---

## Appendix A — Plan vs implemented status

Updated at each phase gate; a schema change requires a migration, never a
manual edit.

| Area | Tables | Status |
|---|---|---|
| Identity/tenancy/access | 12 | planned (Phase 2) |
| Geography | 4 | planned (Phase 3) |
| Waste taxonomy | 3 | planned (Phase 3) |
| Bins/sensors/telemetry | 8 | planned (Phase 3–4) |
| Collections/fleet/routing | 16 | planned (Phase 3–6) |
| Facilities/loads/recovery/env | 11 | planned (Phase 7–10) |
| Intelligence | 12 | planned (Phase 8–9) |
| Notifications/reporting/integration | 13 | planned (Phase 11) |

**Known schema limitations (disclosed, not hidden):**

1. `btree_gist` is unavailable in the sandbox PostgreSQL build, so the
   driver-assignment overlap exclusion constraint is enforced by a partial
   unique index plus a service-layer check rather than by the engine. On a
   PostgreSQL build with `btree_gist`, a migration can upgrade this to a true
   `EXCLUDE` constraint.
2. Table partitioning for `bin_telemetry`/`vehicle_telemetry` is documented and
   indexed-for but not enabled, because the sandbox volume does not exercise it.
   The migration includes the partitioning strategy in a comment so enabling it
   later is a mechanical change.
3. Audit log archival targets local storage in development; production requires
   the configured object-store provider.
