# EcoMind-AI — Architecture

**Status:** Phase 0 baseline (approved direction)
**Audience:** engineers, reviewers, and future maintainers
**Related:** `decisions.md` (ADRs), `domain-model.md`, `../database/erd.md`,
`../security/rbac.md`, `../api/rest-api.md`, `../ai/ai-architecture.md`

---

## 1. What the system is

EcoMind-AI turns waste-management data into operational decisions. It supports
the full lifecycle required by the master specification:

```
DATA → COLLECTION → VALIDATION → STORAGE → MONITORING → ANALYSIS
     → PREDICTION → OPTIMIZATION → EXECUTION → VERIFICATION
     → REPORTING → ENVIRONMENTAL INTELLIGENCE
```

**Deployment shape:** a **modular monolith** — one deployable API service with
strict internal module boundaries — plus separately runnable workers and a SPA
frontend. This is the deliberate choice in section 3 of the specification
("start as a modular monolith unless there is a demonstrated technical reason
to split"). No microservice is created in this build. The module boundaries are
enforced mechanically (import rules + tests) so that extraction later is a
packaging exercise, not a rewrite.

---

## 2. System context

```
                    ┌──────────────────────────────────────────────┐
                    │        Browser SPA (React + TS + Vite)       │
                    │  dashboard · operations · maps · AI console  │
                    └───────────────────┬──────────────────────────┘
                                        │  HTTPS, relative /api/v1 URLs
                    ┌───────────────────▼──────────────────────────┐
                    │  Reverse proxy (nginx in prod / Vite in dev) │
                    │  TLS · compression · SPA fallback · proxy    │
                    └───────────────────┬──────────────────────────┘
                                        │
┌───────────────────────────────────────▼───────────────────────────────────┐
│                        API SERVICE (FastAPI, async)                       │
│                                                                           │
│  middleware:  request-id → structured logging → security headers          │
│               → CORS → rate limit → error envelope → audit context        │
│                                                                           │
│  ┌──────────────┬──────────────────┬─────────────────┬─────────────────┐  │
│  │  Identity    │  Core Operations │  Intelligence   │  Governance     │  │
│  │  authn       │  bins/telemetry  │  forecasting    │  audit          │  │
│  │  rbac        │  collections     │  anomaly        │  notifications  │  │
│  │  tenancy     │  routes/fleet    │  classification │  reporting      │  │
│  │  users       │  facilities      │  optimization   │  integrations   │  │
│  │              │  waste loads     │  assistant      │  files          │  │
│  └──────┬───────┴────────┬─────────┴────────┬────────┴────────┬────────┘  │
│         │                │                  │                 │           │
│  ┌──────▼────────────────▼──────────────────▼─────────────────▼────────┐  │
│  │ repository layer (SQLAlchemy 2.x async) — tenant-scoped by default  │  │
│  └──────┬──────────────────────────────────────────────────────────────┘  │
└─────────┼─────────────────────────────────────────────────────────────────┘
          │
   ┌──────▼───────┐   ┌──────────┐   ┌──────────────┐   ┌─────────────────┐
   │ PostgreSQL 16│   │  Redis   │   │Object storage│   │ Adapters        │
   │ + RLS policy │   │ cache +  │   │ local | S3   │   │ routing/weather │
   │ (target)     │   │ broker   │   │              │   │ email/sms/LLM   │
   └──────────────┘   └────┬─────┘   └──────────────┘   └─────────────────┘
                           │
                    ┌──────▼───────────────────────────┐
                    │  WORKER (Celery beat + workers)  │
                    │  forecasts · aggregations ·      │
                    │  anomaly sweeps · notifications ·│
                    │  report rendering · retention    │
                    └──────────────────────────────────┘
                           ▲
                    ┌──────┴───────────────────────────┐
                    │ IoT gateway / SIMULATOR          │
                    │ signed telemetry batches         │
                    └──────────────────────────────────┘
```

**Trust boundaries.** Everything arriving from the left of the API service is
untrusted: browser input, uploaded files, telemetry payloads, webhook bodies,
and content retrieved from external providers. Authorization is decided only
server-side, from the authenticated session — never from a client-supplied
tenant id, user id, or role.

---

## 3. Module decomposition (bounded contexts)

Each module owns its tables, schemas, service and repository code. A module may
call another module's **service interface**, never reach into its tables.

| # | Module | Owns | Key responsibility |
|---|---|---|---|
| M1 | `identity` | Tenant, User, Role, Permission, Session, APIKey | authn, account lifecycle |
| M2 | `authorization` | RolePermission, UserRole | granular permission checks |
| M3 | `tenancy` | OrganizationProfile, TenantSetting | tenant context + isolation |
| M4 | `geography` | Zone, ServiceArea, Address, GeoPoint | spatial organisation |
| M5 | `assets` | WasteCategory, WasteMaterial taxonomy | controlled waste taxonomy |
| M6 | `bins` | Bin, BinType, BinSensor, BinEvent | bin registry + lifecycle |
| M7 | `telemetry` | BinTelemetry, DeviceRegistration, IngestionBatch | ingest, validate, dedupe, latest-state |
| M8 | `bin_intelligence` | priority + overflow risk scores | explainable bin prioritisation |
| M9 | `collections` | CollectionRequest, Task, Event, Schedule | collection lifecycle |
| M10 | `fleet` | Vehicle, VehicleType, VehicleTelemetry, Maintenance | vehicles + capacity |
| M11 | `workforce` | Driver, DriverAssignment, shifts | drivers + driver-visible scope |
| M12 | `routing` | Route, RouteStop, OptimizationRun | routing + optimization history |
| M13 | `facilities` | Facility, FacilityType, Capability, Utilization | receiving + processing |
| M14 | `loads` | WasteLoad, WasteLoadItem, WasteTransfer | chain of custody |
| M15 | `recovery` | Recycling/Composting/Recovery/Disposal/Treatment events | outcome accounting |
| M16 | `analytics` | read models + aggregation services | KPIs, trends, protected metric defs |
| M17 | `forecasting` | ForecastRun, Forecast, ModelVersion | time-series prediction |
| M18 | `anomaly` | Anomaly, AnomalyEvent | anomaly detection + triage |
| M19 | `classification` | Model, ModelVersion, Classification, Feedback | waste image classification |
| M20 | `environment` | EmissionFactor, CarbonEstimate, EnvironmentalMetric | carbon + environmental KPIs |
| M21 | `notifications` | Notification, Preference, Delivery | multi-channel alerting |
| M22 | `recommendations` | AIRecommendation, Feedback | decision support artefacts |
| M23 | `assistant` | conversation + tool registry | permission-bound AI Q&A |
| M24 | `reporting` | ReportDefinition, ReportRun | structured reports + exports |
| M25 | `integrations` | Integration, Webhook, EventOutbox | outbound adapters |
| M26 | `files` | FileAsset | upload validation + storage |
| M27 | `audit` | AuditLog | immutable action trail |
| M28 | `simulation` | scenario + generators | deterministic dev/test data |

### 3.1 Dependency rules (enforced, not aspirational)

```
api (routers) ──► services ──► repositories ──► models
                    │
                    ├──► integrations (adapters, interfaces only)
                    └──► core (config, errors, security, tenancy, events)
```

1. `api` never contains business rules and never touches a session directly.
2. `services` never build SQL strings; they use repositories.
3. `repositories` never import `services` or `api` (no cycles).
4. `models` import nothing from the layers above.
5. Cross-module calls go through the other module's service, never its tables.
6. `simulation` may import any module; **no production module may import
   `simulation`.** Enforced by a test that greps imports.
7. ORM entities are never returned from a router; a Pydantic response schema is
   always used (section 8 of the master prompt).

Enforcement: `backend/tests/test_architecture.py` parses the import graph and
fails the build on a violation. Documentation that is not tested rots.

---

## 4. Request lifecycle

```
1.  Request lands with X-Request-ID (or one is generated).
2.  Structured logging middleware binds request_id, method, path.
3.  Security headers applied; rate limit evaluated (per identity/IP).
4.  CORS evaluated.
5.  Dependency: bearer access token → decoded (HS256, aud/iss/exp/nbf checked)
    → Session row checked (revocation/rotation state) → User loaded.
6.  Dependency: tenant context resolved FROM THE USER RECORD, never the request.
7.  Permission dependency evaluates required granular permissions.
8.  Router validates input with a Pydantic schema (strict, extra="forbid").
9.  Service executes logic inside an explicit transaction.
10. Repository issues tenant-scoped SQL; PostgreSQL RLS is a second line of
    defence.
11. Audit record written for mutations (actor, tenant, action, resource,
    request_id, redacted metadata).
12. Domain events emitted to the outbox (notifications, webhooks, analytics
    invalidation) inside the same transaction.
13. Pydantic response schema serialised; provenance labels included where the
    value is estimated/predicted/simulated.
```

**Failure path.** All exceptions pass through a single handler that maps
domain errors to the standard error envelope
(`{"error": {code, message, details, request_id}}`). Stack traces, SQL, file
paths and secrets are logged internally and never returned (section 34).

---

## 5. Multi-tenancy

Every tenant-owned table carries `tenant_id UUID NOT NULL REFERENCES tenants(id)`
with an index, and every tenant-owned entity inherits `TenantScopedMixin`.

Three independent layers, so no single mistake leaks data:

| Layer | Mechanism |
|---|---|
| Query | `TenantScopedRepository` injects `WHERE tenant_id = :ctx` into every statement; there is no "unscoped" query helper in the codebase. |
| Database | PostgreSQL RLS policies with `USING (tenant_id = current_setting('app.tenant_id')::uuid)`; the session variable is set per transaction by the connection manager. Tests run as a **non-owner** role so RLS genuinely applies. |
| Test | A dedicated cross-tenant suite that authenticates as tenant A and attempts read/update/delete/list/export/telemetry/file access against tenant B's ids, asserting 404 (existence is not leaked). |

Global (non-tenant) tables are explicitly allow-listed in one place
(`app/core/tenancy.py: GLOBAL_TABLES`) so the exception list is auditable.

`SUPER_ADMIN` is a platform role, not a tenant role. It does not silently
bypass tenant scoping: platform-level access requires an explicit, audited
impersonation/break-glass path, and the permission family is disjoint from
`TENANT_ADMIN` permissions.

---

## 6. Data architecture

* **PostgreSQL 16** is the single system of record.
* UUID primary keys (`gen_random_uuid()`), `TIMESTAMPTZ` timestamps in UTC,
  `NUMERIC` for every measured quantity (weights, distances, volumes, carbon,
  money). Floating point is never used for measured or financial values.
* **Soft deletion** (`deleted_at`) only where history matters (bins, users,
  vehicles, facilities, routes). Telemetry and audit rows are immutable and use
  **retention policies** instead of deletion flags.
* **Time-series tables** (`bin_telemetry`, `vehicle_telemetry`) are indexed on
  `(tenant_id, bin_id, recorded_at DESC)` and designed for BRIN/partitioning as
  volume grows; the aggregation path never loads raw series into memory.
* **Immutability by design:** optimization runs, forecast runs, model versions,
  classification results, audit logs and report runs are append-only. History is
  never overwritten — that is what makes "route comparison" and provenance
  possible.
* **Outbox pattern** for side effects: a domain event is written in the same
  transaction as the state change and delivered asynchronously, so a failed
  email or webhook can never roll back or corrupt business state.

See `docs/database/erd.md` for the full entity/relationship plan.

---

## 7. Integration architecture

Every external dependency is behind an interface with a **deterministic local
implementation** and a real implementation for production:

| Interface | Local (dev/test) | Production |
|---|---|---|
| `RoutingProvider` | `HaversineRoutingProvider` (deterministic distance/time) | OSRM / Google / Mapbox |
| `WeatherProvider` | `SyntheticWeatherProvider` (seeded) | OpenWeather |
| `NotificationProvider` | in-app + `ConsoleEmailProvider` | SMTP / SES / push |
| `StorageProvider` | local filesystem | S3 / MinIO |
| `CacheBackend` | fakeredis (labelled) | Redis |
| `LLMProvider` | `LocalDeterministicAssistant` | OpenAI-compatible endpoint |
| `TelemetryProvider` | device gateway + simulator | MQTT/HTTP gateway |

Adapters are selected by configuration, never by branch conditions scattered
through business logic. Every adapter reports its identity so responses can be
labelled (e.g. `"travel_time_source": "estimated_haversine"`).

---

## 8. AI/ML architecture (summary — full detail in `../ai/ai-architecture.md`)

Three deliberate separations:

1. **Deterministic optimization ≠ LLM.** Route optimization is OR-Tools
   (capacity + time windows). Bin priority is a transparent weighted scoring
   function with published factor weights. Where determinism is correct, an LLM
   is never used (section 24).
2. **Predictive models produce labelled estimates.** Forecasting and anomaly
   detection are statistical/ML, versioned in the model registry, and every
   result carries model + version + input window + horizon + uncertainty.
3. **The assistant retrieves, it does not invent.** The LLM layer can only emit
   statements built from structured outputs of permission-checked tools, each
   answer labelled `DATABASE_FACT | MODEL_PREDICTION | ESTIMATE | RECOMMENDATION
   | UNKNOWN`. The model is not given database credentials and cannot widen its
   own scope: tools are bound to the caller's tenant and permission set, and
   cross-tenant tool calls are unrepresentable (every tool signature takes the
   tenant context as a server-side parameter the model cannot supply).

---

## 9. Background processing

Long-running work never blocks a request: predict/optimize/report endpoints
return a `job_id` and the work is dispatched. Job functions are pure,
idempotent, tenant-scoped callables registered in one place, runnable either
through Celery (`JOB_RUNNER=celery`) or inline (`JOB_RUNNER=inline`, the
sandbox default). Idempotency comes from natural keys + unique constraints +
`ON CONFLICT DO NOTHING` semantics, not from hoping retries do not happen.

---

## 10. Observability

* `/health` — process liveness, version, adapter identities (including which
  components are simulated).
* `/ready` — checks the database and cache, reporting degraded (not healthy)
  when a dependency is down.
* `/metrics` — Prometheus counters/histograms: request latency by route,
  error rate, DB pool saturation, job success/failure, model invocation
  failures, telemetry ingest rate.
* Structured JSON logs with `request_id`, `tenant_id`, `user_id`, `route`,
  `latency_ms`. Secrets and PII are redacted by a logging processor.
* Audit log is the compliance-facing record; it is separate from operational
  logs and is append-only.

---

## 11. Security posture (summary — full detail in `../security/security-model.md`)

AuthN: Argon2id password hashing, short-lived access tokens (HS256), rotating
refresh tokens with reuse detection and family revocation, session revocation,
account status gating, email-verification architecture.
AuthZ: granular permission families, backend-enforced, deny-by-default.
Transport/input: strict Pydantic validation, mass-assignment prevention,
parameterised queries only, upload validation by content sniffing rather than
client MIME, rate limiting, CORS allow-list, CSRF strategy documented for the
cookie-based refresh flow, secure headers.
Data: tenant isolation at query + RLS + test layers.
AI: prompt-injection containment, tool allow-listing, no destructive actions
without explicit human confirmation, output-schema validation.

---

## 12. Scalability and evolution

The modular monolith scales outward along axes that already exist:

| Pressure | First response | Later extraction |
|---|---|---|
| Read volume | cache analytics aggregates; read replicas | split `analytics` |
| Telemetry write volume | batch ingestion, `COPY`-style bulk insert, partitioning, retention | split `telemetry` + ingest gateway |
| Optimization CPU | bounded solver time, job queue, dedicated worker pool | split `routing` worker |
| ML inference | batch + cache; on-demand only for single images | split `classification` service |
| Multi-region | per-tenant routing, read replicas | regional deployments |

Because every module already communicates through service interfaces and owns
its tables, extraction is packaging work. No module in this build is a
distributed system pretending to be a monolith.

---

## 13. Explicit non-goals of this build

Stated so that "missing" is never mistaken for "forgotten":

1. **No microservices, no Kubernetes manifests beyond documented examples.**
2. **No deep-learning vision model in ACTIVE state** until a real labelled
   corpus exists (see ADR-0008).
3. **No real-time vehicle GPS feed** — vehicle movement is simulated and
   labelled; the ingestion API is real and hardware-ready.
4. **No fabricated accuracy, savings or emission-reduction claims.** Every
   environmental figure is labelled measured/estimated/predicted/simulated.
5. **No PostGIS-required path** (ADR-0005).
