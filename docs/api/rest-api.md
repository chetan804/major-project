# EcoMind-AI — REST API Plan

**Base path:** `/api/v1` · **Style:** REST + OpenAPI 3.1 (auto-generated, then augmented with examples)
**Related:** `../security/rbac.md`, `../architecture/domain-model.md`, `../api/error-catalogue.md`

---

## 1. Conventions (binding for every endpoint)

| Concern | Rule |
|---|---|
| Versioning | Path-versioned: `/api/v1/...`. A breaking change means `/api/v2`; additive changes stay in v1. |
| Resource naming | Plural nouns, kebab-case for multi-word (`/waste-loads`, `/optimization-runs`). |
| IDs | UUID strings internally; human-readable `code` fields (e.g. `BIN-00042`) accepted and returned for UI/CSV friendliness. |
| Pagination | `?page=1&page_size=25` (max 100) with a standard envelope (below). Cursor pagination (`?cursor=`) for telemetry and audit streams, where offsets degrade. |
| Sorting | `?sort=-created_at,name` (`-` = descending). Only allow-listed fields per resource — no raw column passthrough. |
| Filtering | Explicit, typed query parameters (`?status=ACTIVE&zone_id=…&category=PLASTIC`). No generic filter expression language (an injection and abuse surface). |
| Date ranges | `?from=2026-01-01T00:00:00Z&to=…` (ISO-8601, UTC). `?granularity=day\|week\|month`. |
| Partial updates | `PATCH` with explicit optional fields; `extra="forbid"` everywhere (mass-assignment defence). |
| Idempotency | Mutating endpoints accept `Idempotency-Key`; POST-heavy flows (driver sync, telemetry ingest, report generation) are idempotent by natural key. |
| Concurrency | `ETag`/`If-Match` on mutable resources using the `version` column; a stale write returns `409 STALE_RESOURCE`. |
| Request IDs | Every response carries `X-Request-ID` (echoed or generated); it also appears in the error body and in logs. |
| Timeouts for long work | Optimize/forecast/report/import return `202 Accepted` with a job or run resource, plus `Location` of the status endpoint. |
| Provenance | Any response containing estimated/predicted/simulated values includes a `provenance` field per value or per block. |
| Rate limits | Per-identity and per-IP; `429` with `Retry-After`. Stricter for auth, assistant, exports and uploads. |
| Permissions | Each endpoint documents and enforces required permissions (`../security/rbac.md`). |

### 1.1 Success envelope

For single resources, the resource object is returned directly (predictable for
clients). For collections:

```json
{
  "items": [ ... ],
  "pagination": { "page": 1, "page_size": 25, "total_items": 412, "total_pages": 17 },
  "meta": { "request_id": "...", "generated_at": "2026-09-24T10:15:00Z", "filters_applied": {...} }
}
```

For analytics, `meta` additionally carries the aggregation basis:

```json
"meta": {
  "period": {"from": "...", "to": "...", "timezone": "Asia/Kolkata"},
  "data_source": "database_aggregation",
  "provenance": "MEASURED",
  "partial_period": false,
  "definitions_version": "metrics-v1"
}
```

### 1.2 Error contract (section 34 — implemented once, globally)

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Bin not found",
    "details": { "bin_id": "…" },
    "request_id": "01J…",
    "timestamp": "2026-09-24T10:15:00Z"
  }
}
```

Never returned: stack traces, SQL, file paths, secrets, internal hostnames,
dependency versions. Operational detail goes to the logs, correlated by
`request_id`. The code catalogue lives in `docs/api/error-catalogue.md` and in
`app/core/errors.py` (a closed enum, so an undocumented error code cannot be
raised).

| HTTP | Representative codes |
|---|---|
| 400 | `VALIDATION_ERROR`, `INVALID_DATE_RANGE`, `MALFORMED_REQUEST` |
| 401 | `AUTHENTICATION_REQUIRED`, `INVALID_CREDENTIALS`, `TOKEN_EXPIRED`, `SESSION_REVOKED` |
| 403 | `PERMISSION_DENIED`, `TENANT_ACCESS_DENIED`, `ACCOUNT_SUSPENDED`, `BREAK_GLASS_REQUIRED` |
| 404 | `RESOURCE_NOT_FOUND` (also used for cross-tenant probes) |
| 409 | `CONFLICT`, `STALE_RESOURCE`, `INVALID_STATE_TRANSITION`, `DUPLICATE_RESOURCE` |
| 413/415 | `FILE_TOO_LARGE`, `UNSUPPORTED_MEDIA_TYPE` |
| 422 | `BUSINESS_RULE_VIOLATION`, `INSUFFICIENT_DATA`, `CAPACITY_EXCEEDED` |
| 429 | `RATE_LIMIT_EXCEEDED` |
| 500 | `INTERNAL_ERROR` (generic to the client; detailed in logs) |
| 503 | `DEPENDENCY_UNAVAILABLE` (DB/Redis/model/solver down) |

---

## 2. Endpoint plan by module

Endpoints are listed as `METHOD path — permission — notes`. Read endpoints are
subject to the pagination/filter conventions above without restating them.

### 2.1 Auth & session — `/api/v1/auth`
| Method | Path | Permission | Notes |
|---|---|---|---|
| POST | `/register` | public | Tenant self-service signup (configurable); creates tenant + TENANT_ADMIN, `status=TRIAL`. Rate-limited, audited. |
| POST | `/login` | public | Returns short-lived access token + rotating refresh token. Generic failure message (no user enumeration). Lockout after N failures. |
| POST | `/refresh` | refresh token | Rotates; reuse of an old token revokes the family and audits a security event. |
| POST | `/logout` | authenticated | Revokes the current session. |
| POST | `/logout-all` | authenticated | Revokes every session of the user. |
| GET | `/me` | authenticated | Current user, memberships, effective permissions, tenant context. |
| PATCH | `/me` | authenticated | Profile, locale, timezone. |
| POST | `/password/change` | authenticated | Requires current password; revokes other sessions. |
| POST | `/password/reset-request` | public | Architecture + provider adapter; always returns 202 (no enumeration). |
| POST | `/password/reset-confirm` | public | Single-use, expiring token. |
| POST | `/email/verify-request` | authenticated | Token dispatch via adapter. |
| POST | `/email/verify-confirm` | public | Marks verified. |
| GET | `/sessions` | `sessions.read` | Active sessions with device/ip/last-used. |
| DELETE | `/sessions/{id}` | `sessions.revoke` | Revoke one session. |

### 2.2 Tenants & settings — `/api/v1/tenants`, `/api/v1/settings`
`GET /tenants/current` · `PATCH /tenants/current` (`settings.write`) ·
`GET /settings` · `PUT /settings/{key}` (`settings.write`) ·
`GET|POST /scoring-configurations` (`scoring.read`/`scoring.configure`) ·
`POST /scoring-configurations/{id}/activate`.
Platform: `GET|POST /platform/tenants`, `GET|PATCH /platform/tenants/{id}`,
`POST /platform/tenants/{id}/suspend`, `POST /platform/break-glass` (audited,
time-boxed) — all `platform.*`.

### 2.3 Users, roles — `/api/v1/users`, `/api/v1/roles`
`GET /users` · `POST /users/invite` · `GET /users/{id}` · `PATCH /users/{id}` ·
`DELETE /users/{id}` (soft) · `POST /users/{id}/roles` · `DELETE /users/{id}/roles/{role_id}` ·
`GET /users/me/permissions`.
`GET /roles` · `POST /roles` (clone/custom) · `PATCH /roles/{id}` ·
`PUT /roles/{id}/permissions` · `GET /permissions` (catalogue, for the role editor).

### 2.4 Geography — `/api/v1/zones`, `/api/v1/service-areas`
Full CRUD under `settings.write`/`bins.write` families as declared in the
permission catalogue. `GET /zones/{id}/statistics` returns zone KPIs
(`analytics.read`). `GET /geo/nearby?lat=&lng=&radius_m=` returns bins,
facilities and points within a radius (`bins.read`), implemented by the
dialect-aware geo repository (ADR-0005).

### 2.5 Bins — `/api/v1/bins`
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/bins` | `bins.read` | Filters: zone, status, category, sensorized, fill range; `bbox=` for map viewport loading. |
| POST | `/bins` | `bins.write` | Validated; rejects out-of-range coordinates. |
| GET | `/bins/{id}` | `bins.read` | Includes current state + sensor summary. |
| PATCH | `/bins/{id}` | `bins.write` | If-Match supported. |
| DELETE | `/bins/{id}` | `bins.delete` | Soft delete; refuses if open tasks reference it (until rescheduled). |
| GET | `/bins/{id}/telemetry` | `bins.telemetry.read` | Cursor-paginated time series with `from/to`. |
| GET | `/bins/{id}/state` | `bins.read` | Latest state with `age_seconds` and staleness flag. |
| GET | `/bins/{id}/history` | `bins.read` | Collection + alert + maintenance timeline. |
| GET | `/bins/{id}/risk` | `scoring.read` | Overflow risk with factor contributions. |
| GET | `/bins/priority` | `scoring.read` | Ranked collection priorities with factor breakdowns. |
| POST | `/bins/import` | `data.import` | CSV, all-or-nothing report. |
| GET | `/bins/export` | `data.export` | CSV, streamed. |
| GET/POST | `/bins/{id}/maintenance` | `bins.maintenance.write` | Maintenance records. |

### 2.6 Telemetry — `/api/v1/telemetry`
| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/telemetry/ingest` | API key / device auth | Batch of readings; per-reading validation, dedup, partial acceptance with a rejected-readings report. Never silently drops. |
| POST | `/telemetry/ingest/single` | API key | Convenience for constrained devices. |
| GET | `/telemetry/batches` | `bins.telemetry.read` | Ingestion audit: accepted/rejected/duplicate counts. |
| GET | `/telemetry/latest` | `bins.read` | Latest reading per bin (read-model table) for the live board. |
| GET | `/telemetry/aggregate` | `bins.telemetry.read` | Server-side hourly/daily aggregates; never returns raw rows. |

### 2.7 Alerts & notifications — `/api/v1/alerts`, `/api/v1/notifications`
`GET /alerts` · `POST /alerts/{id}/acknowledge` · `POST /alerts/{id}/resolve` ·
`POST /alerts/{id}/suppress` (with expiry) · `GET /alerts/summary` (counts by
severity/type for dashboard badges).
`GET /notifications` · `PATCH /notifications/{id}` (read/dismiss) ·
`POST /notifications/read-all` · `GET|PUT /notifications/preferences`.

### 2.8 Collections — `/api/v1/collections`
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/collections/tasks` | `collections.read[.own]` | Driver sees only own stops. |
| POST | `/collections/requests` | `collections.create` | Citizen/manual request intake. |
| GET | `/collections/requests` | `collections.read` | |
| POST | `/collections/requests/{id}/schedule` | `collections.create` | Converts a request into tasks. |
| GET | `/collections/tasks/{id}` | `collections.read[.own]` | |
| PATCH | `/collections/tasks/{id}` | `collections.update` | Reschedule/reassign. Illegal state change → 409. |
| POST | `/collections/tasks/{id}/start` | `collections.update` | ASSIGNED/DISPATCHED → EN_ROUTE. |
| POST | `/collections/tasks/{id}/arrive` | `collections.update` | |
| POST | `/collections/tasks/{id}/complete` | `collections.complete.own` | Requires quantity **or** exception reason (BR-07). |
| POST | `/collections/tasks/{id}/fail` | `collections.complete.own` | Requires controlled failure reason. |
| POST | `/collections/tasks/{id}/reschedule` | `collections.update` | Creates a successor task. |
| POST | `/collections/tasks/{id}/evidence` | `files.upload` | Photo/attachment linked to the event. |
| POST | `/collections/events/sync` | `collections.complete.own` | Offline driver batch sync; idempotent on `client_uuid`. |
| GET/POST/PATCH | `/collections/schedules` | `collections.schedule.write` | Recurring schedules (RRULE). |
| GET | `/collections/calendar` | `collections.read` | Date-range view of planned work. |

### 2.9 Routes & optimization — `/api/v1/routes`
| Method | Path | Permission | Notes |
|---|---|---|---|
| GET | `/routes` | `routes.read[.own]` | Filters: date, status, vehicle, driver, zone. |
| POST | `/routes` | `routes.create` | Manual route. |
| GET | `/routes/{id}` | `routes.read[.own]` | Includes ordered stops with coordinates (navigation-ready). |
| PATCH | `/routes/{id}` | `routes.update` | Edit stops/sequence; capacity re-validated (BR-06). |
| GET | `/routes/{id}/stops` | `routes.read[.own]` | |
| POST | `/routes/{id}/assign` | `routes.assign` | Vehicle + driver; validates availability, capacity, licence expiry. |
| POST | `/routes/{id}/dispatch` | `routes.dispatch` | DRAFT → DISPATCHED; notifies the driver. |
| POST | `/routes/{id}/complete` | `routes.complete.own` | |
| POST | `/routes/optimize` | `routes.optimize` | **202** + `optimization_run_id`. Body: date, zone(s), vehicle ids, depot, constraints, weights. |
| GET | `/routes/optimization-runs` | `routes.read` | History (never overwritten — ADR-0010). |
| GET | `/routes/optimization-runs/{id}` | `routes.read` | Status, solver status, objective, duration, input snapshot digest. |
| GET | `/routes/optimization-runs/{id}/result` | `routes.read` | Produced routes/stops, unassigned stops with reasons. |
| POST | `/routes/optimization-runs/{id}/apply` | `routes.create` | Materialises the plan as DRAFT routes (explicit human step, section 23). |
| POST | `/routes/{id}/compare` | `routes.read` | Compare against previous/manual/naive baseline → `route_comparisons` row with per-metric provenance. |
| GET | `/routes/compare/{comparison_id}` | `routes.read` | Stored comparison (historical, reproducible). |

Route optimization request example:

```json
{
  "route_date": "2026-09-25",
  "depot": { "facility_id": "…", "latitude": 17.385, "longitude": 78.4867 },
  "vehicle_ids": ["…", "…"],
  "zone_ids": ["…"],
  "stop_selection": { "strategy": "PRIORITY_THRESHOLD", "min_priority_score": 0.55, "max_stops": 120 },
  "constraints": { "enforce_time_windows": true, "max_route_duration_minutes": 480, "allow_overtime": false },
  "objective_weights": { "distance": 1.0, "vehicle_count": 50.0, "priority_penalty": 120.0 }
}
```

Application eligibility in the request body is validated server-side: unknown
vehicle ids, foreign-tenant ids and unavailable vehicles are rejected — client
input never determines scope.

### 2.10 Vehicles & drivers — `/api/v1/vehicles`, `/api/v1/drivers`
`GET|POST /vehicles` · `GET|PATCH|DELETE /vehicles/{id}` ·
`GET /vehicles/{id}/telemetry` (`vehicles.telemetry.read`) ·
`POST /vehicles/{id}/telemetry` (device/tracking auth) ·
`GET|POST /vehicles/{id}/maintenance` · `POST /vehicles/{id}/status`.
`GET|POST /drivers` · `GET|PATCH /drivers/{id}` · `GET|POST /drivers/assignments` ·
`GET /drivers/me/route` (driver self-view: today's route + stops + navigable
coordinates, minimum necessary payload) · `GET /drivers/me/summary`.

### 2.11 Facilities, loads, recovery — `/api/v1/facilities`, `/api/v1/waste-loads`, `/api/v1/recovery`
`GET|POST /facilities` · `GET|PATCH /facilities/{id}` ·
`PUT /facilities/{id}/capabilities` · `GET /facilities/{id}/utilization` ·
`GET /facilities/{id}/intake` · `GET /facilities/nearby?lat=&lng=&category=`.
`GET|POST /waste-loads` · `GET|PATCH /waste-loads/{id}` ·
`PUT /waste-loads/{id}/composition` · `POST /waste-loads/{id}/transfer` ·
`POST /waste-loads/{id}/receive` (facility intake) ·
`GET /waste-loads/{id}/trace` (full chain of custody — "where did this waste go?").
`POST /recovery/events` · `POST /recovery/composting` · `POST /recovery/treatment` ·
`POST /recovery/disposal` · `GET /recovery/events` · `GET /recovery/summary`.
Waste taxonomy: `GET|POST /waste/categories` · `GET|POST /waste/materials` ·
`POST /waste/classify` (image → classification result) ·
`GET /waste/classifications` · `POST /waste/classifications/{id}/review` ·
`GET /waste/classification-models` · `GET /waste/classification-models/{id}/metrics`.

### 2.12 Analytics — `/api/v1/analytics`
All `analytics.read`, all return aggregates with `meta` provenance, all accept
`from`, `to`, `granularity`, and scope filters (`zone_id`, `facility_id`,
`vehicle_id`, `route_id`, `category`).

| Endpoint | Returns |
|---|---|
| `GET /analytics/overview` | KPI set for the executive dashboard (generated, collected, diversion, overflow incidents, active vehicles, completed collections, estimated CO2e) — each with provenance and source-of-truth pointer. |
| `GET /analytics/waste-generation` | Trend by period, optionally by category/zone. |
| `GET /analytics/composition` | Category share with `MEASURED`/`ESTIMATED` labels per slice. |
| `GET /analytics/collection` | Planned vs completed, efficiency, missed rate, on-time. |
| `GET /analytics/recycling` | Recovery by type, rates, top materials. |
| `GET /analytics/routes` | Distance, duration, stops, utilization, efficiency vs baseline. |
| `GET /analytics/vehicles` | Utilization, distance, fuel, maintenance downtime. |
| `GET /analytics/environment` | Diversion rate (with the active definition), CO2e breakdown by source, avoided disposal. |
| `GET /analytics/forecast` | Forecast vs actual comparison for a completed period (backtest view). |
| `GET /analytics/anomalies` | Anomaly counts/trends by type and severity. |
| `GET /analytics/zones` | Zone league table with composite performance. |
| `GET /analytics/executive-summary` | Single call powering the executive page. |

### 2.13 Forecasts, anomalies, models, recommendations
`POST /forecasts/run` (`forecasts.execute`, 202 + run id) · `GET /forecasts/runs` ·
`GET /forecasts/runs/{id}` · `GET /forecasts/latest?subject=…` ·
`GET /forecasts/runs/{id}/explain` (model, version, input window, features,
uncertainty, assumptions).
`GET /anomalies` · `GET /anomalies/{id}` · `POST /anomalies/{id}/acknowledge` ·
`POST /anomalies/{id}/resolve` · `POST /anomalies/{id}/mark-false-positive` ·
`GET /anomaly-events` · `PATCH /anomaly-events/{id}`.
`GET /models` · `GET /models/{id}/versions` · `GET /models/{id}/versions/{v}/metrics` ·
`POST /models/{id}/versions/{v}/promote` (platform) · `POST /models/{id}/rollback` (platform).
`GET /recommendations` · `GET /recommendations/{id}` ·
`POST /recommendations/{id}/view|accept|reject|execute` ·
`POST /recommendations/{id}/feedback` · `POST /recommendations/generate` (rule
engine run, 202).

### 2.14 Assistant — `/api/v1/assistant`
`POST /assistant/conversations` · `GET /assistant/conversations` ·
`GET /assistant/conversations/{id}` (message history) ·
`POST /assistant/conversations/{id}/messages` (question → answer + tool trace) ·
`DELETE /assistant/conversations/{id}`.
Response contract (this shape is what makes "no invented metrics" verifiable):

```json
{
  "message_id": "…",
  "answer": "Zone North has the highest overflow risk (4 bins above 0.75).",
  "statements": [
    {
      "text": "Zone North has the highest overflow risk",
      "type": "MODEL_PREDICTION",
      "confidence": 0.81,
      "evidence": {
        "tool": "get_overflow_risk_by_zone",
        "arguments": { "window_hours": 24 },
        "source_ids": ["bin:…", "bin:…"],
        "metric": "overflow_risk_score",
        "model_version": "overflow-risk/v3"
      }
    }
  ],
  "tools_used": [ { "name": "get_overflow_risk_by_zone", "latency_ms": 41, "rows": 4 } ],
  "data_sources": ["bin_telemetry", "bin_telemetry_latest"],
  "limitations": ["Overflow risk is predicted from telemetry; 12 of 96 bins have no sensor."],
  "provider": "local_deterministic",
  "conversation_id": "…"
}
```
If the tools return nothing, the answer is `UNKNOWN` with the reason — never a
plausible-sounding invention.

### 2.15 Reports, audit, jobs, files, health
`GET /reports/definitions` · `POST /reports/generate` (202) ·
`GET /reports/runs` · `GET /reports/runs/{id}` · `GET /reports/runs/{id}/export?format=csv|json`
(`reports.export`) · `POST /reports/schedules`.
`GET /audit-logs` (`audit.read`, read is itself audited) ·
`GET /audit-logs/{id}` · `GET /audit-logs/export` (`data.export`).
`GET /jobs` · `GET /jobs/{id}` · `POST /jobs/{id}/retry` (platform).
`POST /files/upload` (`files.upload`) · `GET /files/{id}` (ownership-checked) ·
`DELETE /files/{id}`.
`GET /health` · `GET /ready` · `GET /metrics` (unauthenticated liveness only;
detailed dependency state in `/health`).

---

## 3. Endpoints deliberately absent (and why)

| Not built | Reason |
|---|---|
| `DELETE /audit-logs/{id}` | Audit is append-only; there is no deletion path by design. |
| Generic `POST /query` or GraphQL | Unbounded query surface = injection/abuse and impossible tenant auditing. |
| `PUT /bins/{id}/fill-level` | Fill level is derived from telemetry, never hand-editable (BR-05). Manual corrections happen by inserting a `MANUAL`-source telemetry reading with an actor, which is auditable. |
| Route mutation inside `/optimize` | Optimization must not silently change operational plans; `apply` is a separate, explicit, permission-checked step. |
| Live GPS websockets | Not in scope for this build; the polling endpoints return `SIMULATED`-labelled positions. |
