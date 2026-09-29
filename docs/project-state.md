# EcoMind-AI — Project State

**This file is the continuity source for future development sessions.**
Update it at the end of every working session (section 76).

**Last updated:** 2026-09-27 · **Session:** 4 (Phase 2, in progress)

---

## 1. Current position

| Field | Value |
|---|---|
| Current phase | **Phase 2 — Authentication, tenancy, RBAC, audit (IN PROGRESS)** |
| Next action | users / roles / tenants routers, `app/scripts/seed.py`, then Phase 3 (zones, bins, taxonomy endpoints) |
| Repository branch | `arena/01a0e3c9-major-project` |
| Baseline commit | `12c4b66` (Phase 0+1 merge); this branch adds 3 commits on top |
| Architecture status | Coherent and complete at design level; no known blocking open question |
| Gate status | lint, format, mypy, secret scan and migration drift all clean; **425 passed, 3 skipped** |
| Open PR | [#2 — Phase 2 foundation](https://github.com/chetan804/major-project/pull/2) |

---

## 2. Completed modules

**Design (Phase 0):** all 28 bounded contexts are specified with aggregates,
invariants, state machines, business rules, metric definitions, permissions,
endpoints, tables, tests and risks.

**Code implemented and verified (Phase 1):**

| Area | Delivered |
|---|---|
| Application core | `app/main.py` (factory, lifespan, middleware order), `core/{config,errors,context,logging,metrics,cache,responses,time,middleware}.py` |
| Database | `app/db/{types,base,session,rls}.py` — column type aliases, declarative base with mixins, engine and session lifecycle, **row-level security generator** |
| API | `app/api/{deps,errors,health}.py` — dependency layer, exception handlers, `/health`, `/ready`, `/metrics` |
| Migrations | Alembic wired to the settings-derived URL; `0001_baseline` verified reversible |
| Scripts | `scripts/{pg_server,bootstrap,check_secrets,verify_environment}.py\|sh` |
| Tooling | `Makefile` (`make gate`), `.github/workflows/ci.yml` |

**Code implemented and verified (Phase 2, so far):**

| Area | Delivered |
|---|---|
| Models | 12 modules covering every aggregate in the domain model — **84 tables** (`identity`, `geography`, `taxonomy`, `bins`, `collections`, `fleet`, `routing`, `facilities`, `loads`, `environment`, `intelligence`, `platform`) |
| Migrations | `43f430493613` — the 84 tables, **RLS with `FORCE` on all 73 tenant-scoped tables**, the platform reference data, and the `v_processing_outcomes` view. Round-trips cleanly; `alembic check` reports no drift |
| Authorization | `authorization/{permissions,role_matrix,context,checks,resolution,tokens}.py` — 99 permission codes, 10 seeded roles with 307 grants **derived from `rbac.md` §4**, the actor value object, service-layer checks, and JWT + refresh-token handling |
| Repositories | `repositories/{base,identity}.py` — tenant-scoped base with pagination, allow-listed sorting and 404-not-403 behaviour, plus the identity repositories |
| Services | `services/auth.py` — sign-in, invitation registration, refresh rotation with replay detection, session revocation, password change and reset |
| API | `api/schemas/{common,identity}.py` and `api/v1/auth.py` — **12 authenticated operations**, 4 of them public by written decision |
| Tests | 425 tests across `unit`, `db`, `api`, `security`, `architecture` — all green |

Scaffolding present from Phase 0:

| File | Purpose |
|---|---|
| `.gitignore` | excludes venv, node_modules, `.runtime/` dev DB, storage, secrets |
| `.env.example` | full environment contract, no real secrets |
| `backend/requirements/{base,worker,ml,vision,dev}.txt` | dependency sets with stated rationale |
| `scripts/bootstrap.sh` | idempotent venv + deps + `.env` + PostgreSQL + migrations + seed |
| `scripts/pg_server.py` | manages the local real-PostgreSQL cluster; **written and verified** (start/stop/status/url/sync-url/psql/ensure) |
| `docs/**` | the Phase 0 deliverables listed in `docs/phases.md` |

---

## 3. Environment state (verified, evidence in `docs/environment.md`)

| Component | State |
|---|---|
| Python 3.11.2 venv | created at `.venv`; **all dependencies installed and import-verified**: fastapi 0.141.1, sqlalchemy 2.0.54, alembic 1.20.0, pydantic 2.13.5, asyncpg 0.31.0, ortools 9.15.6755, scikit-learn 1.9.1, pandas 2.3.3, numpy 2.4.6, opencv 5.0.0.93, pgserver 0.1.4, fakeredis 2.38.0, celery 5.6.3, PyJWT 2.15.0, argon2-cffi 25.1.0 |
| PostgreSQL | real 16.2 via `pgserver`; cluster provisioned at `.runtime/pgdata` (database `ecomind`, unix socket). **Verified:** CHECK constraints enforced, `gen_random_uuid()` and exact `NUMERIC` (123.4560) correct, **SQLAlchemy 2.x async + asyncpg connect successfully over the unix socket**, daemon survives process exit and a new process re-attaches to the same postmaster, and the `stop → status → start` lifecycle preserves data. Managed by the verified `scripts/pg_server.py`. |
| Redis | absent; `fakeredis` adapter planned and labelled |
| Docker | absent; Compose/Dockerfiles will be authored but not build-tested here (disclosed) |
| PostGIS | unavailable; dialect-aware geo layer designed (ADR-0005) |
| Frontend toolchain | Node 22.22.3 / npm 10.9.8 available; project not yet scaffolded |

---

## 4. Database state

| Field | Value |
|---|---|
| Migrations applied | `0001_baseline` + `43f430493613` (single head, reversible) |
| Tables created | **84**, of which **73 are tenant-scoped** and carry an RLS policy with `FORCE ROW LEVEL SECURITY` |
| Tables global by decision | 11, each with a written justification in `app/db/rls.py::GLOBAL_TABLES` (`tenants`, `permissions`, `waste_categories`, `waste_materials`, `emission_factors`, `unit_conversions`, `ai_models`, `ai_model_versions`, `report_definitions`, `notification_templates`, `integrations`, `data_retention_policies`) |
| Reference data seeded | 99 permissions, 10 roles, 307 role-permission grants, 11 waste categories, 23 materials, 7 emission factors, 4 model versions, 5 report definitions, 10 notification templates, 5 integrations, 7 retention policies |
| RLS coverage | `rls_coverage_report()` returns `unclassified: []` — 73 tenant-scoped / 11 global |
| Known limitations | no `btree_gist` → assignment-overlap guard via partial unique index + service check; telemetry partitioning documented but not enabled |

---

## 5. API state

| Field | Value |
|---|---|
| Implemented endpoints | **12 under `/api/v1/auth`** — login, refresh, password reset (request + confirm), me (GET/PATCH), password change, logout, logout-all, sessions (list + revoke), and invitation-based user creation |
| Public by written decision | 4 — `POST /auth/login`, `POST /auth/refresh`, `POST /auth/password-reset`, `POST /auth/password-reset/confirm` (each with a reason recorded in `tests/architecture/test_route_inventory.py::PUBLIC_ROUTES`) |
| Planned endpoints | ~150 across 15 groups (see `api/rest-api.md`) |
| OpenAPI | generated by FastAPI at `/openapi.json`; contract tests planned |
| Error contract | closed enum implemented in `core/errors.py` and asserted by `tests/test_error_contract.py` |
| Route classification gate | **live**: every mounted operation is either public-by-reason or protected; the test fails the build otherwise |

## 6. Frontend state

Scaffolding planned (React 18 + TS + Vite + Tailwind + TanStack Query + Leaflet
+ Recharts). Route map, navigation structure, component inventory, state
strategy, accessibility approach and test plan are designed
(`frontend/information-architecture.md`). No code yet.

## 7. AI/ML state

Architecture complete (registry, forecasting, anomaly detection, classification
with pluggable backends, assistant with tool grounding, recommendation engine,
safety controls). The registry itself now exists as data — 4 models with one
version each, all seeded as **`CANDIDATE`** — and the seed deliberately claims no
performance for any of them. A version becomes `ACTIVE` only through an evaluation
run that records real metrics against a named dataset (ADR-0008), which is the step
`app/scripts/seed.py` still has to perform.

No models trained, no metrics published, **no accuracy claims made anywhere**.

## 8. Tests

`make test` → **425 passed, 3 skipped**, 0 failed (~16 s).

| Marker | Files | What it pins |
|---|---|---|
| `unit` | `test_config`, `test_time`, `test_cache`, `test_logging` | settings validation matrix, aware-UTC rules and tenant-day bounds, cache key scoping and failure containment, log redaction |
| `api` | `test_health`, `test_error_contract`, `test_request_context` | probe semantics, exact error-envelope contract, contextvar propagation across a pure-ASGI stack |
| `security` | `test_security_headers`, **`test_authorization_matrix`** | headers on success *and* error, CORS allow/reject; **the seeded roles against `rbac.md` §4, cell by cell, plus the deliberate omissions** |
| `db` | `test_database`, `test_types`, `test_migrations`, `test_rls_coverage` | constraints enforced by PostgreSQL, exact `NUMERIC`, migration reversibility and drift, **RLS proven enforced** |
| `architecture` | `test_import_rules`, `test_route_inventory`, `test_secret_scanner` | layer direction, route classification gate (now reading declared permissions *and* authentication), secret-scan detection and its negative cases |

The authorization matrix test is the one to know about: it parses the markdown
table in `docs/security/rbac.md` §4 and compares it against the resolved
permission sets in code. A hand-written matrix had drifted from the specification
in twenty-one places; the sets are now derived from a table of grant marks, and
this test is what keeps the two from disagreeing again.

Verification performed in Phase 0 (environment capability probes) is recorded with
commands in `docs/environment.md`.

**Tests that would have passed vacuously have been removed or repaired** — a guard
that checks nothing is worse than no guard, because its presence is trusted. The
route-inventory traversal, the layer-map skip and the float/NUMERIC drift assertion
were each rewritten after they were found to be checking the wrong thing. Details
in `docs/phases.md` (Phase 1 report).

## 9. Known issues

1. **`scripts/bootstrap.sh` cannot complete end-to-end yet.** Its migration step
   works; its final step calls `python -m app.scripts.seed --profile dev`, and
   `backend/app/scripts/seed.py` does not exist yet. The migration already seeds the
   platform-wide reference data idempotently, so a fresh database is usable — what
   is missing is the *development* tenant with demo bins, telemetry and the model
   evaluations. This is the single blocking item for `make bootstrap`.
2. **Container artefacts are still not written.** Dockerfiles, Compose and nginx were
   planned for Phase 1 and remain deferred rather than committed unverified: this
   environment has no Docker daemon, so a container configuration could be authored
   and *statistically reviewed* but never built, started or health-checked. Shipping
   an unverifiable artefact under a "phase complete" report would be exactly the
   overclaim the master prompt forbids. The CI workflow is written but also
   unexecuted for the same reason (no network access to GitHub Actions from the
   sandbox) — it is marked as such in the workflow file itself.
3. **The frontend is not scaffolded yet.** Deferred to the frontend phase rather
   than created as an empty shell now, so that no route exists without a screen
   behind it (section 19).
4. **Only authentication has a router.** 12 of ~150 planned endpoints exist. The
   model layer, migrations, authorization and repositories for the remaining
   domains are in place, so each subsequent router is a thin layer over tested
   foundations — but the API surface is 8% built.
5. **Cosmetic third-party noise at interpreter exit.** `pgserver` logs
   `ValueError: I/O operation on closed file` from its `atexit` cleanup after the
   test process has already flushed. It appears *after* the pytest summary line and
   is unrelated to any test result — no test fails and the exit code is 0. Noted so
   a future session does not spend time chasing it; a fix belongs upstream.
6. **PostGIS remains unavailable** (ADR-0005). The geospatial fallback is documented
   and map features must state which path is in use.
7. **Redis is absent** (ADR-0002); the `fakeredis` adapter is used and must be
   labelled as such wherever it serves traffic.
8. Two Phase 0 scope questions (session depth priority, frontend breadth) still have
   documented defaults in `risks-and-assumptions.md` §4 and remain available for
   confirmation.

### Findings worth carrying forward

**A PostgreSQL superuser bypasses row-level security even with
`FORCE ROW LEVEL SECURITY` set.** The test suite connects as `postgres`, so a
policy test on that connection returns every tenant's rows and can only pass if
the policy is broken. The harness therefore provisions a dedicated non-superuser
login role. The same property is a production requirement: the application must
connect as an ordinary role, or the third isolation layer is inert. Recorded in
`docs/security/security-model.md`.

**A bare callable inside `Annotated` is a request field, not a dependency.**
`Annotated[Actor, some_dependency]` is parsed by FastAPI as a Pydantic *field*,
so the actor would be read from the request body and the route would appear to
have no authentication at all. `tests/architecture/test_route_inventory.py`
failed on exactly that shape while the auth router was being written. Dependencies
must be wrapped in `Depends(...)` explicitly — see `app/api/deps.py`.

## 10. Next recommended action

1. **`backend/app/scripts/seed.py` with `--profile`** — the only thing standing
   between the current state and a working `scripts/bootstrap.sh`. It must create a
   development tenant with demo bins, sensors and SIMULATOR-labelled telemetry, and
   run the model evaluations that promote a `CANDIDATE` version to `ACTIVE` against
   a named dataset.
2. **The users, roles and tenants routers** — `GET/POST /users`, role assignment,
   `GET/PATCH /tenants`, session administration. Each is a thin layer over the
   repositories and `AuthService` that already exist, and each must declare its
   permissions on the route.
3. **Adversarial tenant-isolation and authorization-matrix tests** — the Phase 2
   gate requires cross-tenant access to return 404 (not 403) and every role ×
   endpoint combination to be exercised.
4. **Then Phase 3** — zones, service areas, waste taxonomy, bins and their
   endpoints, which is the first domain with a real UI behind it.
5. Container artefacts and the frontend scaffold remain deferred as described in
   §9 above, and both must be marked verified or unverified explicitly when they
   land.

## 11. Standing constraints for the next session

* Do not weaken tenant isolation for convenience (ADR-0003).
* Do not add a hard PostGIS, Docker, or Redis dependency (ADR-0002/0005).
* Do not publish any model metric without its dataset and evaluation type
  (section 49).
* Do not present estimated/predicted/simulated values without a provenance
  label (ADR-0013).
* Any architectural change follows the section-75 procedure and updates
  `decisions.md` before code.
