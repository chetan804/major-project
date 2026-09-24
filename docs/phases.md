# EcoMind-AI — Implementation Phases

**Status:** Phase 0 baseline (approved direction) · **Phase gates:** mandatory per section 60

Each phase ends with a **gate report** containing: completed features; files
created/modified; database changes; API endpoints added; tests added; tests
passed; known limitations; remaining risks; next-phase prerequisites. A phase is
never declared complete while a critical test fails (section 60/78).

---

## Phase 0 — Requirements and architecture ✅ (this deliverable)

| Deliverable | Where |
|---|---|
| Environment capability inventory (with evidence) | `docs/environment.md` |
| Architecture + module boundaries + dependency rules | `docs/architecture/architecture.md` |
| Decision records | `docs/architecture/decisions.md` |
| Domain model: aggregates, invariants, state machines, business rules, metric definitions | `docs/architecture/domain-model.md` |
| Database ERD plan (72 tables, constraints, indexes, RLS list) | `docs/database/erd.md` |
| API plan + error contract | `docs/api/rest-api.md`, `docs/api/error-catalogue.md` |
| RBAC: permission catalogue + role matrix + test plan | `docs/security/rbac.md` |
| Security model and threat table | `docs/security/security-model.md` |
| Frontend information architecture | `docs/frontend/information-architecture.md` |
| AI/ML architecture and safety model | `docs/ai/ai-architecture.md` |
| Testing strategy and gates | `docs/testing/testing-strategy.md` |
| Risk register and assumptions | `docs/risks-and-assumptions.md` |
| Requirements traceability skeleton | `docs/requirements-traceability.md` |
| Environment scaffolding: `.env.example`, `.gitignore`, requirement sets, bootstrap | repo root |

**Gate 0 exit criteria:** architecture coherent; no unresolved question whose
answer would force rework of the database schema or the module boundaries.
*Status: met — the two open items in `risks-and-assumptions.md` §4 are scope
questions with documented default decisions, not architectural blockers.*

---

## Phase 1 — Repository and infrastructure

**Build:** directory skeleton per section 57; `pyproject.toml` (ruff, mypy,
pytest config, markers); Makefile; `scripts/bootstrap.sh`, `scripts/pg_server.py`,
`scripts/check_secrets.py`; Docker Compose (postgres, redis, api, worker,
frontend, nginx) and Dockerfiles authored for production-like deployment;
nginx config; CI workflow (lint → types → tests → frontend build → security scan);
config module with typed settings and startup validation; structured logging,
request-id middleware, error handler, `/health`, `/ready`, `/metrics`;
ALembic initialised with an empty baseline migration.

**Gate:** `make quality` clean; `/health` and `/ready` return correct payloads
with a real DB; app starts; CI config sane.

---

## Phase 2 — Authentication, tenancy, RBAC, audit

**Build:** tenant + user + role + permission + session + api_key tables and
migrations; permission catalogue and seeded roles (the `rbac.md` §4 matrix);
Argon2id hashing; login/logout/refresh rotation with reuse detection; password
reset and email-verification flows (provider adapter); session revocation;
authorization dependencies (route + service level) with the startup self-check;
tenant context derivation; `TenantScopedRepository`; RLS policies; audit log
service and middleware; rate limiting; security headers; CORS; secret redaction.

**Tests:** authorization matrix (all roles × endpoints), tenant isolation
(adversarial), token lifecycle, lockout, injection, mass assignment, secret
leakage, RLS-as-non-owner.

**Gate:** 100 % pass on security and isolation suites; matrix test proves the
documented role table; no endpoint without a declared permission.

---

## Phase 3 — Core waste domain

**Build:** zones, service areas, addresses, waste taxonomy (11 seeded categories
+ materials + mappings), bin types, bins, vehicles + types + capacity history,
drivers, facilities + capabilities + operating hours, collection requests,
schedules and tasks; CRUD APIs with validation; soft delete; optimistic
concurrency; CSV import/export for bins, vehicles, facilities.

**Gate:** CRUD + validation + authorization + tenant isolation tests pass; seed
profiles create internally consistent multi-tenant data (section 46).

---

## Phase 4 — IoT, telemetry, bin monitoring

**Build:** bin sensors and sensor health; telemetry ingestion endpoint with
API-key device auth, per-reading validation, dedup, partial acceptance reporting
and `ingestion_batches`; `bin_telemetry_latest` read model; latest-state
derivation; offline detection; threshold alerts with dedup keys; alert
acknowledge/resolve; telemetry aggregates endpoint; **IoT simulator** (seeded,
time-compressed, produces realistic fill curves, sensor dropouts, battery decay
and fault injections, labelled `SIMULATOR` everywhere).

**Gate:** telemetry validation/dedup/offline tests pass; simulator produces data
that drives real dashboards; alert lifecycle proven.

---

## Phase 5 — Collection operations

**Build:** full task lifecycle state machine with events and evidence;
assignment to vehicle/driver with availability and capacity validation; driver
workflow endpoints (own-route view, start/arrive/complete/fail, offline batch
sync idempotent on `client_uuid`); route creation and stop sequencing; dispatch;
overdue/missed detection job; driver-facing minimum-payload APIs.

**Gate:** lifecycle, capacity (BR-06), concurrency and driver-scope tests pass;
illegal transitions rejected with 409.

---

## Phase 6 — Optimization and comparison

**Build:** OR-Tools CVRPTW model (capacity, time windows, priorities, multiple
vehicles, depot, max duration, optional overtime); optimization runs as a job
with persisted input snapshot, constraints, solver status, `is_optimal`,
objective, duration and unassigned-stop reasons; apply-creates-DRAFT-routes;
route comparison against previous/manual/naive baseline with per-metric
provenance; comparison history.

**Gate:** solver respects all constraints; determinism test with fixed
parameters; infeasible and timeout paths handled; comparisons labelled
estimated.

---

## Phase 7 — Analytics and dashboards

**Build:** metric definition registry (the single source of the formulas in
`domain-model.md` §6); aggregation services with database-side grouping (no
whole-table loads); endpoints of `rest-api.md` §2.12; caching with tenant-safe
keys and explicit invalidation; executive dashboard, operations live board,
analytics pages, map layer service with bbox loading; KPI provenance plumbing.

**Gate:** analytics figures reconcile against seeded data in tests; N+1 and
unbounded-query checks pass; dashboards render loading/empty/error states.

---

## Phase 8 — Forecasting, anomaly detection, classification

**Build:** model registry tables and services (promotion guard, rollback);
dataset tracking with `is_synthetic`; forecasting pipeline (baseline + smoothing
+ GBT) with backtest-derived uncertainty and honest `INSUFFICIENT_DATA`;
anomaly detection (z-score/IQR/moving baseline, optional Isolation Forest) with
triage endpoints; classification pipeline (upload → validate → preprocess →
classify → confidence → review queue → feedback) with the classical backend,
**trained and evaluated** on a documented synthetic corpus; evaluation pipeline
producing metrics into `model_metrics`; generated model cards.

**Gate:** metric computation verified against hand-computed fixtures; published
metrics include the synthetic-corpus caveat; promotion without metrics refused;
low-confidence routing proven.

---

## Phase 9 — AI decision support assistant

**Build:** tool registry with typed schemas, permission binding and row limits;
deterministic local provider; optional OpenAI-compatible provider behind the same
interface; grounded response builder producing `statements[]` with evidence,
`tools_used[]`, `limitations[]`; conversations and message history persisted;
prompt-injection containment; assistant UI with the evidence panel and statement
type labels; recommendation engine (rule-based over metrics) with lifecycle and
feedback.

**Gate:** AI safety suite passes (grounding, tool authorization, tenant leakage,
injection, structured output); no answer without evidence; no write tool exists.

---

## Phase 10 — Traceability, facilities, recovery, environmental intelligence

**Build:** waste loads with chain of custody and composition; transfers; facility
intake and processing outcomes (recovery/composting/treatment/disposal);
traceability endpoint ("where did this waste go?"); emission factor library with
versioning and tenant overrides; carbon estimation with factor snapshots and an
explicit `UNKNOWN` path; environmental metric rollups including configurable
diversion definitions; sustainability dashboard and flow visualisation.

**Gate:** BR-08/09/10/11 tests pass; chain-of-custody reconstruction verified;
carbon figures carry factor provenance; diversion definition changes are audited
and labelled.

---

## Phase 11 — Reporting, notifications, integrations

**Build:** notification engine (severity, dedup, preferences, channels, delivery
attempts, adapters for email/webhook/console); report definitions and runs with
structured payloads, CSV/JSON export and rendering separated; scheduled reports;
webhooks with HMAC signing, retries and dead-letter; integration registry;
domain event outbox and dispatcher; job runner (inline + Celery) with
observability.

**Gate:** notification dedup and delivery-retry tests pass; report payloads
reconcile with analytics; webhook idempotency proven.

---

## Phase 12 — Hardening and final audit

**Perform:** security audit (OWASP-aligned review of every control in
`security-model.md`); performance audit (query plans, index verification, N+1
sweep, pagination enforcement, memory ceilings on aggregation paths);
accessibility audit (axe + keyboard walkthroughs on primary screens); test
coverage review against the gates; database review (constraints, indexes,
retention, migration reversibility); API review (contract consistency, error
codes, versioning); UX review (empty/loading/error states, dead-link sweep,
provenance labelling); documentation completeness; final verification checklist
of section 74; the 20-category system audit of section 72 with PASS/FAIL/PARTIAL
and evidence; completed requirements traceability matrix.

**Gate:** every item in section 74 verified with evidence; failures reported
honestly rather than hidden.

---

## Standing rules across all phases

1. One coherent phase at a time; do not start the next phase with a failing gate.
2. Any architectural change follows the section-75 procedure: explain, identify
   affected modules, propose the smallest safe correction, update documentation
   and tests, then implement — never silently.
3. `docs/project-state.md` is updated at the end of every session (section 76).
4. Every new endpoint updates: implementation, permission declaration, matrix
   test, API doc, traceability row.
5. Every new table updates: migration, ERD plan + Appendix A, RLS policy list if
   tenant-owned, and retention classification.
