# EcoMind-AI — Testing Strategy

**Status:** Phase 0 baseline
**Principle:** a test that cannot fail for the right reason is worse than no
test. Every suite below asserts on real behaviour against real PostgreSQL.

---

## 1. Test pyramid and execution model

```
        ┌───────────────────────────────┐
        │ E2E (Playwright)              │  ~10 critical journeys, RBAC per role
        ├───────────────────────────────┤
        │ API / integration (httpx ASGI)│  the widest band: real DB, real auth
        ├───────────────────────────────┤
        │ Service / repository          │  business rules, tenant scoping, SQL
        ├───────────────────────────────┤
        │ Unit (pure logic)             │  scoring, metrics, state machines,
        └───────────────────────────────┘  validation, formatters
```

**Database:** real PostgreSQL 16 per ADR-0002. Each `pytest-xdist` worker gets
its own database (`ecomind_test_<worker>`) created from a template with
migrations already applied, so parallel runs are isolated and fast.
RLS is active, and the application test connection uses the non-owner role.

**Determinism:** time is frozen with a controllable clock fixture; simulators
take explicit seeds; random identifiers are seeded; tests never depend on wall
clock ordering. Flaky-by-design tests (sleep-based) are not permitted.

---

## 2. Backend suites

| Suite | Location | Contents |
|---|---|---|
| Unit | `tests/unit/` | priority scoring weights and factor maths, overflow-risk blending, diversion-rate formulas per definition, carbon arithmetic with `Decimal`, z-score/IQR edge cases, state-machine transition tables, date/timezone rolling, pagination math, CSV cell validation |
| Repository | `tests/repositories/` | tenant predicate always applied, soft-delete filtering, unique-constraint mapping to `409 DUPLICATE_RESOURCE`, `ON CONFLICT` idempotency, `NUMERIC` exactness round-trips |
| Service | `tests/services/` | collection lifecycle; capacity enforcement (BR-06); load composition sums (BR-08); recovery ≤ load (BR-09); facility capability (BR-10); emission-factor resolution incl. the `UNKNOWN` path (BR-11); recommendation evidence requirement (BR-16) |
| API | `tests/api/` | status codes, error envelope shape, pagination/sorting/filtering contracts, ETag/If-Match conflict, idempotency keys, 202 + job flows, validation errors field-by-field |
| Authorization | `tests/security/test_authorization_matrix.py` | role × endpoint matrix exactly as documented in `rbac.md` §4 |
| Tenant isolation | `tests/security/test_tenant_isolation.py` | adversarial cross-tenant attacks on every resource class |
| Security | `tests/security/` | tokens, injection, uploads, rate limits, headers, CORS, state machines, secret leakage |
| Telemetry | `tests/telemetry/` | ingestion validation and rejection accounting, dedup idempotency, offline detection, latest-state derivation, sensor-health transitions, high-volume batch insert performance smoke |
| Optimization | `tests/optimization/` | solver respects capacity and time windows; unassigned stops reported with reasons; `is_optimal` honesty; determinism with fixed parameters; infeasible input handled without crash; run persistence is append-only |
| Forecasting | `tests/ml/test_forecasting.py` | pipeline runs end to end, baseline computed, intervals present or explicitly `null`, backtest metrics correct on synthetic fixtures, `INSUFFICIENT_DATA` for short histories, no training-on-test leakage |
| Anomaly | `tests/ml/test_anomaly.py` | injected anomalies detected, clean series quiet at threshold, parameters recorded, false-positive marking works |
| Classification | `tests/ml/test_classification.py` | backend protocol conformance, preprocessing correctness, top-k shape, low-confidence routing to review, metric computation against hand-computed fixtures including zero-division, model-registry promotion guard (BR-14) |
| Environmental | `tests/environment/` | carbon estimate uses the factor snapshot, `UNKNOWN` without a matching factor, diversion definition variants produce different, correctly-labelled values |
| Jobs | `tests/jobs/` | idempotency (run twice → no duplicates), retry on failure, `job_runs` bookkeeping, `SKIPPED_DUPLICATE` semantics |
| AI safety | `tests/ai/` | grounding (no evidence → no claim), tool permission checks, tenant leakage via tools, prompt injection payloads from data fields, structured output validation, deterministic local provider |
| Architecture | `tests/architecture/` | import-graph rules (no cycles, no production→simulation imports), every route declares a permission, no ORM entity in a response model, no raw SQL string construction |

---

## 3. Frontend suites

| Suite | Tool | Contents |
|---|---|---|
| Unit | Vitest | formatters, provenance label mapping, permission helpers, date/timezone conversion, CSV export escaping |
| Component | RTL | `DataTable` (loading/empty/error/pagination/sort), `KpiCard` (provenance + insufficient-data rendering), `StatusBadge` (icon + text, not colour alone), `AsyncBoundary` branches, `ConfirmDialog` keyboard accessibility, `MapView` accessible list fallback |
| Integration | RTL + MSW | bin creation with server-side validation errors surfaced, telemetry chart with empty state, task completion including exception reason path, optimization wizard incl. job polling and failure, assistant evidence panel rendering tool traces, error envelope rendering with request id |
| Accessibility | axe-core | no critical violations on dashboard, bin detail, optimization console, assistant |
| E2E | Playwright | see §4 |

---

## 4. End-to-end journeys (acceptance)

Each journey runs against a seeded database with the API and frontend started:

1. **Login & session** — login, refresh, logout, silent-refresh on expiry, account lockout after repeated failures.
2. **Dashboard** — KPIs render from real seeded data; provenance badges present; insufficient-data path shown when a tenant has no telemetry.
3. **Create bin** — validation errors (bad coordinates, duplicate code), success, appears in the registry and on the map.
4. **View telemetry** — chart and cursor-paginated table populate; stale-telemetry indicator appears for a bin whose last reading is old.
5. **Create collection task** — from a request and from the priority list; task appears in the queue.
6. **Optimize route** — wizard → job → result, comparison table vs baseline, unassigned stops listed with reasons.
7. **Apply & dispatch** — apply creates DRAFT routes; dispatch sends the driver notification; capacity validation blocks an oversized assignment.
8. **Driver flow** — driver logs in, sees only their route, completes a stop with quantity, reports one stop as failed with a reason, completes the route.
9. **Analytics** — generated, collected, diversion, environment views match seeded figures within documented rounding.
10. **Report** — generate, view structured result, export CSV.
11. **Assistant** — ask a supported question, receive a grounded answer with evidence, ask an unsupported question, receive `UNKNOWN` with a reason.
12. **RBAC** — for every seeded role, forbidden nav is absent, direct URL → `/no-access`, and the corresponding API call returns `403`.

---

## 5. Coverage and quality gates

| Gate | Threshold | Rationale |
|---|---|---|
| Backend line coverage (overall) | ≥ 80 % | Meaningful without becoming a vanity metric |
| Coverage of `authorization`, `tenancy`, `security` modules | ≥ 95 % | The failure modes that matter most |
| Coverage of `optimization`, `analytics`, `environment` | ≥ 85 % | Core correctness |
| All security suites | 100 % pass | Non-negotiable |
| All tenant-isolation suites | 100 % pass | Non-negotiable |
| `ruff` | clean | Lint + security rules |
| `mypy` | clean on `app/` | Type discipline |
| Frontend unit/component | pass, with axe critical violations = 0 | Accessibility is a requirement |
| Dead code / TODO scan | no TODO in production paths | Section 20 |

Coverage is a floor, not a goal: a phase is not declared complete on coverage
percentage alone but on the requirement-specific tests in §2 passing.

---

## 6. Test data strategy

* **Seed profiles:** `dev` (rich, multi-tenant, ~90 days of telemetry for two
  tenants, one tenant deliberately sparse), `test` (minimal deterministic
  fixtures), `demo` (the fullest scenario set for screenshots/walkthroughs).
* **Consistency by construction:** the generator enforces the invariants of
  section 46 — a vehicle's assigned route never exceeds its capacity; a bin
  marked empty has telemetry consistent with that; alerts correspond to actual
  threshold crossings; collection counts match events.
* **Factories** build valid entities with explicit override points and
  are tenant-aware; tests must state the tenant they operate in.
* **No shared mutable state between tests:** each test gets a transaction-scoped
  session rolled back on completion, or a fresh database for isolation tests that
  must exercise committed RLS behaviour.

---

## 7. Failure-injection tests (section 67)

| Injected failure | Expected behaviour |
|---|---|
| Database unreachable | `/ready` returns degraded with the dependency named; API returns `503 DEPENDENCY_UNAVAILABLE`; no partial writes; error logged once with the request id |
| Cache unavailable | Requests still succeed (cache is an optimisation, never a dependency); a warning is logged; no stale-auth path is used |
| Model artifact missing | Forecast/classification returns a clear failure; **no** silent fallback to another model without recording the substitution |
| Routing provider timeout | Optimization falls back to the local haversine provider **and records `travel_time_source`** so the result is honestly labelled |
| Notification provider failure | The business transaction still commits; delivery is retried with backoff and eventually dead-letters with visibility in `/jobs` |
| Solver time limit reached | Run completes with `status=TIMEOUT`, `is_optimal=false`, partial solution returned with unassigned stops and reasons |
| Malformed device payload | Batch accepted partially with a rejected-readings report; the batch record shows the counts; nothing is silently dropped |
| Job crash mid-run | Retry does not duplicate rows (natural-key idempotency asserted) |
| Clock skew in telemetry | Readings beyond tolerance are rejected and counted; the device's skew is visible in the batch record |

---

## 8. Running the suites

```bash
make test                 # backend suite (real PostgreSQL)
make test-security        # security + isolation + authorization matrices
make test-ml              # forecasting, anomaly, classification, metrics
make test-frontend        # vitest unit + component
make test-e2e             # playwright journeys
make quality              # ruff + mypy + dead-code/TODO scan
make audit                # the full local gate used at each phase boundary
```

`make audit` is the phase-gate command: it runs lint, types, all tests, the
architecture rules and the secret scan, and prints a pass/fail summary that is
copied verbatim into the phase report.
