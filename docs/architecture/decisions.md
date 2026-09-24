# Architecture Decision Records

Every consequential decision in this project is recorded here with the
alternatives that were rejected and why. When reality changes, the ADR is
superseded — not quietly edited away.

Format: **ADR-nnnn — Title** · Status · Context · Decision · Consequences · Alternatives rejected.

Verified-environment facts referenced below are recorded with evidence in
`../environment.md`.

---

## ADR-0001 — Modular monolith, not microservices

**Status:** accepted

**Context.** The specification demands a multi-tenant platform with ~28
subsystems (telemetry, optimization, ML, reporting, assistant) and also
explicitly warns against premature microservices.

**Decision.** One FastAPI application composed of 28 strictly bounded modules,
plus independently runnable worker processes. Module boundaries are enforced by
an import-graph test, not by convention.

**Consequences.** Atomic transactions across contexts (e.g. completing a
collection that also writes a waste load, an audit row and an outbox event);
one deployable to debug; extraction later is packaging work because modules
already communicate through interfaces and own their tables.

**Rejected.** Microservices from day one: 28 services with 2 vCPUs and one
engineer is an operations burden with no benefit at this stage, and it makes
cross-context consistency (collection → load → recovery → carbon) a distributed
transaction problem.

---

## ADR-0002 — Real PostgreSQL 16 in development and tests via `pgserver`

**Status:** accepted

**Context.** Docker is unavailable in the sandbox and apt is blocked, but the
platform depends on PostgreSQL-specific behaviour: `NUMERIC` exactness,
`CHECK` constraints, partial indexes, `TIMESTAMPTZ` semantics, row-level
security, window functions, `ON CONFLICT`.

**Decision.** Install `pgserver` (bundles official PostgreSQL 16.2 binaries) and
run a real server for development and the entire test suite. `DATABASE_URL`
points at it through a unix socket. Production uses a normal PostgreSQL 16
service; the URL is configuration, not code.

**Evidence.** `SELECT version()` → `PostgreSQL 16.2`; a `CHECK (fill BETWEEN 0
AND 100)` genuinely rejects `150`; `gen_random_uuid()` and `NUMERIC(12,4)`
round-tripping verified in `docs/environment.md §1.1`.

**Consequences.** Tests cannot pass on a database that ignores constraints, so
"tests pass" means something. RLS policies are genuinely exercised. Cost: the
test bootstrap starts a cluster (~1 s) and every contributor needs the same
Python package.

**Rejected.** (a) SQLite for tests — silently tolerates invalid data and has no
RLS, so tenant-isolation tests would be theatre. (b) Skipping the database
entirely with mocks — violates "no fake success" and would prove nothing.

---

## ADR-0003 — Tenant isolation enforced three times, deliberately

**Status:** accepted

**Context.** Cross-tenant leakage is the highest-severity failure mode in a
multi-tenant SaaS. A single missed `WHERE tenant_id = ...` is a breach.

**Decision.** (1) All tenant data access goes through
`TenantScopedRepository`, which injects the tenant predicate from the request
context; no unscoped query helper exists. (2) PostgreSQL RLS policies with
`current_setting('app.tenant_id')` are enabled on tenant tables, and tests
connect as a non-owner role so the policy actually applies. (3) A dedicated
adversarial test suite authenticates as tenant A and attacks tenant B's
resources by raw id across read/update/delete/list/export/file/telemetry paths.

**Consequences.** Defence in depth: a query-construction bug still fails at the
database. Cross-tenant probes return `404`, never `403`, so resource existence
is not leaked. Cost: RLS adds a policy evaluation per row and requires careful
role/session-variable management.

**Rejected.** Application-layer filtering only (one bug = one breach);
tenant-per-schema or tenant-per-database (migration and connection-pool
complexity that does not pay off at this stage).

---

## ADR-0004 — Server-derived tenant context; `SUPER_ADMIN` is not a bypass

**Status:** accepted

**Context.** Section 12 forbids trusting client-provided tenant ids, user ids,
roles or permissions.

**Decision.** The tenant context is derived from the authenticated user's
membership records on every request. Request bodies and query strings cannot
set it. A `X-Tenant-Id` header is accepted **only** to disambiguate which tenant
an authenticated multi-tenant user is acting in, and it is validated against
that user's active memberships — an unowned value yields `403` and an audit
event. `SUPER_ADMIN` has a disjoint permission family and must use an explicit,
audited break-glass flow to act inside a tenant.

**Consequences.** Privilege-escalation and IDOR classes are structurally
difficult. Cost: platform support operations need the (logged) break-glass path
rather than a silent bypass — which is the intended trade-off.

---

## ADR-0005 — Dialect-aware geo layer; PostGIS optional, never required

**Status:** accepted

**Context.** The specification asks for PostGIS, but the verified environment
exposes **zero** PostgreSQL extensions (`pg_available_extensions` returns no
`postgis` row). Storing coordinates as strings is explicitly forbidden.

**Decision.** Store coordinates as validated `NUMERIC(9,6)` / `NUMERIC(10,7)`
columns with `CHECK` bounds; run proximity/containment queries through a geo
repository that emits either (a) a bounding-box pre-filter using a
`btree` index plus a haversine expression, or (b) PostGIS `ST_DWithin` when
`GEO_ENABLE_POSTGIS=true` and the extension is present. One service interface,
two SQL strategies, identical results; the response reports the strategy used.

**Consequences.** The platform runs anywhere PostgreSQL runs and still answers
"which bins are within 500 m of this vehicle" without loading the world into
memory. PostGIS can be enabled later purely as an index/performance upgrade.

**Rejected.** (a) Hard PostGIS dependency — the application would not start in
this environment. (b) lat/lng as text or float — forbidden by sections 8 and 25
and loses precision.

---

## ADR-0006 — Two-tier RBAC with granular permission strings

**Status:** accepted (detail in `../security/rbac.md`)

**Context.** Ten tenant-facing roles plus a platform role; tenants may not need
all roles; several workflows need different rights on the same resource (a
DRIVER may complete a stop but not create a route).

**Decision.** `Role` → `RolePermission` → permission string
(`resource.action[.scope]`), plus direct `UserRole` assignment. Authorization
checks the **permission set**, never the role name. Permissions are seeded as
data (migration), so tenants can define custom roles without code changes.
Deny-by-default: an endpoint without a declared permission requirement fails a
startup self-check.

**Consequences.** Frontend navigation and action visibility are derived from the
same permission catalogue the API enforces, so the UI cannot drift from the
backend. Cost: a route inventory test must be maintained — which is itself
valuable, since it makes an unprotected endpoint a build failure.

**Rejected.** Role-name checks scattered in handlers (unmaintainable, easy to
get wrong, impossible to customise per tenant).

---

## ADR-0007 — OR-Tools for route optimization; explicit objective and constraints

**Status:** accepted

**Context.** Section 14 forbids "sort bins by ID" and requires capacity, time
windows, priorities, multiple vehicles and depots.

**Decision.** Model collection routing as a capacitated VRP with time windows
(CVRPTW) using OR-Tools routing. The objective is an explicit weighted sum
(distance, vehicle count, priority penalty for skipping a high-priority stop,
overtime). Every run stores the input snapshot, constraint set, algorithm,
solver status, objective value, execution duration, resulting routes and
whether optimality was proven or the time limit was hit.

**Consequences.** Real, explainable, reproducible optimization with a stored
audit trail; route comparison against previous/baseline plans is possible
because nothing is overwritten. Cost: solver CPU is bounded
(`OPTIMIZER_MAX_SOLVE_SECONDS`) and optimization therefore runs as a job, not
inside the request.

**Rejected.** A greedy nearest-neighbour heuristic (ignores capacity/time
windows properly, cannot prove quality); an LLM (section 25 forbids using an LLM
for numerical optimization).

---

## ADR-0008 — Classical CV waste classification, pluggable backend, no invented accuracy

**Status:** accepted

**Context.** Section 12 requires a computer-vision-ready classification
architecture and forbids fabricating accuracy. The environment has no GPU, no
labelled corpus, and a 529 MB torch wheel.

**Decision.** Define `ClassificationBackend` with two implementations:
`ClassicalCVBackend` (colour histogram, texture/LBP, edge-density, spatial
descriptors → scikit-learn estimator, actively chosen today) and
`TorchvisionBackend` (optional extra, `CLASSIFICATION_BACKEND=torchvision`).
The classical backend is genuinely trained and evaluated on a **documented,
deterministic synthetic corpus**; its measured per-class precision/recall/F1 and
confusion matrix are published verbatim in `../ai/model-cards.md`, together with
the honest statement that synthetic-corpus metrics are a pipeline validation,
not a claim of field accuracy. Deep models register as `CANDIDATE`, never
`ACTIVE`, until trained on real data.

**Consequences.** The full pipeline (upload → validate → preprocess → predict →
confidence → low-confidence review queue → human correction → feedback →
metrics → registry → rollback) is real and testable now, and swapping in a
trained CNN is a configuration change. No number in the UI is invented.

**Rejected.** Shipping a pretrained ImageNet backbone and reporting its
ImageNet accuracy as waste-classification accuracy (dishonest); shipping a
random-weight model labelled "AI" (forbidden by sections 12/62).

---

## ADR-0009 — Job abstraction with inline and Celery runners

**Status:** accepted

**Context.** Redis is absent in the sandbox, but forecasts, aggregations,
notifications and reports must run outside the request path in production.

**Decision.** Job functions are pure, idempotent, tenant-scoped callables
registered in a single registry with declared payload schemas. Two runners:
`inline` (sandbox/dev/test — executes synchronously, deterministic, makes
end-to-end tests possible without a broker) and `celery` (production). Job runs
are recorded in a `job_run` table with status, attempt count and error summary.

**Consequences.** Retry-safety is provable in tests (run the job twice, assert
no duplicate rows). Production gets real queueing without the job logic
changing. `/health` reports which runner is active so nobody confuses the
inline dev runner with a real queue.

**Rejected.** Tying job code to Celery decorators (untestable without a broker,
and locks the codebase to one broker).

---

## ADR-0010 — Append-only intelligence artefacts, with provenance

**Status:** accepted (implements specification sections 22, 51, 63)

**Context.** Route comparison, forecast explanation, model rollback and
environmental accounting all require history. Overwriting destroys it.

**Decision.** `route_optimization_run`, `forecast_run`, `ai_model_version`,
`waste_classification`, `carbon_estimate`, `report_run` and `audit_log` are
append-only: new rows, never updates to results. Each carries its inputs,
algorithm/model version, timestamp, and a `provenance` label from a closed
vocabulary: `MEASURED`, `ESTIMATED`, `PREDICTED`, `SIMULATED`, `USER_ENTERED`,
`DERIVED`. Emission factors are versioned rows (factor, unit, source,
geography, methodology, effective-from/to) — never constants in code.

**Consequences.** "How did we get this number?" is answerable end to end; the UI
can label every figure honestly; model rollback is a pointer change. Cost:
storage growth, mitigated by retention policies on telemetry and logs.

**Rejected.** Recomputing metrics on read without storing inputs (unreproducible
and untrendable); a single `metrics` table with an untyped JSON blob (no
integrity, no query-ability).

---

## ADR-0011 — Vite dev server proxies the API; browser never sees `localhost`

**Status:** accepted

**Context.** The platform serves the app through a preview proxy; the user's
browser is not the sandbox host.

**Decision.** All frontend code uses relative URLs (`/api/v1/...`). The Vite dev
server proxies `/api` server-side to the backend, and nginx does the same in
production. Servers bind `0.0.0.0`. `server.allowedHosts` is not restricted
(it would reject the preview host) and CORS is driven by `CORS_ALLOWED_ORIGINS`.
WebSocket/SSE endpoints (if added) go through the same proxy path.

**Consequences.** One code path works in sandbox preview, local dev, and
production; no `localhost` leak into browser code; no host/origin rejections.

**Rejected.** Absolute `http://localhost:8000` API base URLs — they work on the
developer's machine and break everywhere else.

---

## ADR-0012 — Testing strategy: real database, adversarial security suite, AI safety suite

**Status:** accepted (detail in `../testing/testing-strategy.md`)

**Context.** Sections 48/49/74 make multi-dimensional testing a completion
gate. "Tests pass" must mean something verifiable.

**Decision.** The suite runs against real PostgreSQL with RLS active and
includes: unit (pure logic), integration (service+DB), API (httpx ASGI),
authorization (per-permission, per-role matrices), tenant isolation (adversarial
cross-tenant attacks), security (token tampering/expiry/revocation, upload
attacks, injection payloads, rate limits), ML (metrics computation correctness,
deterministic seeds, honest reporting), and AI safety (prompt injection, tool
authorization, tenant leakage through tools, structured-output validation,
hallucination guards). Tests are grouped by marker so any group runs standalone.

**Consequences.** A failing gate blocks a phase declaration. Cost: slower CI
than a mocked suite — accepted, because isolation bugs are the failure mode that
actually ends companies.

**Rejected.** Mocked repositories (would not catch a real tenant-scoping bug);
testing only the happy path.

---

## ADR-0013 — Honest status labels in API and UI

**Status:** accepted

**Context.** The platform mixes measured, estimated, predicted and simulated
values, and sections 62/64 forbid presenting one as another.

**Decision.** A closed `provenance` vocabulary is carried from database to API
response to UI badge. Simulated/mock components (fakeredis, synthetic weather,
simulated fleet positions, synthetic-corpus model metrics) are surfaced in
`/health`, in API payload metadata, and as visible UI labels. The dashboard
shows the data source of every KPI.

**Consequences.** Reviewers can always tell what is real; demos stay honest.

**Rejected.** Implicit "it's all real" presentation — forbidden, and it is the
fastest way to lose a reviewer's trust.
