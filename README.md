# EcoMind-AI

**AI-powered smart waste management & environmental intelligence platform.**

EcoMind-AI is designed to convert waste-management data into operational decisions:
ingesting smart-bin telemetry, forecasting waste generation, classifying waste from
images, planning and optimising collection routes under real capacity and
time-window constraints, tracking material from collection through processing to
recovery or disposal, estimating carbon impact from versioned emission factors,
and answering operational questions through an AI assistant that is bound to
permission-checked tools rather than free invention.

Multi-tenant, role-based, API-first, built for municipalities, private haulers,
campuses, commercial and industrial facilities.

---

## Project status

| Phase | Scope | State |
|---|---|---|
| **0** | Requirements, architecture, domain model, ERD, API/RBAC/AI design | ✅ **Complete** |
| 1 | Repository & infrastructure scaffolding | Backend delivered; frontend/container work deferred |
| **2** | **Authentication, tenancy, RBAC, audit** | **Complete — API/security gate passed; production prerequisites documented** |
| 3 | Core waste domain (bins, vehicles, drivers, facilities, taxonomy) | Next |
| 4 | IoT & telemetry (ingestion, sensors, alerts, simulator) | Planned |
| 5 | Collection operations & driver workflow | Planned |
| 6 | Route optimisation & comparison | Planned |
| 7 | Analytics & dashboards | Planned |
| 8 | Forecasting, anomaly detection, waste classification | Planned |
| 9 | AI decision-support assistant | Planned |
| 10 | Traceability, facilities, recovery, environmental intelligence | Planned |
| 11 | Reporting, notifications, integrations | Planned |
| 12 | Hardening & final audit | Planned |

Detailed phase deliverables and gate criteria: [`docs/phases.md`](docs/phases.md).
See [`docs/project-state.md`](docs/project-state.md) for live continuity state.

> **Honesty note.** This platform distinguishes *measured*, *estimated*,
> *predicted* and *simulated* data everywhere it appears — in the database, in
> API responses and in the UI. Where real infrastructure (IoT gateways, fleet
> telematics, PostGIS, a hosted LLM, a labelled waste-image corpus) is not
> available, the repository ships a clearly-labelled adapter or simulator rather
> than fabricated data. Documents state what has been verified and what has not.

---

## Quickstart

The backend foundation, authentication, user/role administration, current-tenant
settings, a development-admin seed, recovery/verification mail delivery and
authentication rate limits, audit browsing, administrative sessions and scoped
API-key lifecycle management are implemented. The frontend, general job runner,
simulator and operational demo data are not available yet.

```bash
# Install dependencies, generate .env, start PostgreSQL, migrate and seed.
./scripts/bootstrap.sh

# Initial admin login details: .runtime/dev-account.json (mode 0600).
# Never commit or share this file. Re-running bootstrap preserves changed access.

# Start FastAPI on 0.0.0.0:8000; API docs at /docs.
# Explicit local cache adapter: no Redis server required.
REDIS_ADAPTER=fakeredis make run

# In another terminal: dispatch queued recovery/verification mail (one pass).
# Local mail: .runtime/auth-mail/<tenant UUID>/<message UUID>.eml (private).
make auth-mail

# Lint, types, secrets, migration drift, all tests.
make gate
```

Requires Python 3.11+. Development uses real PostgreSQL 16 through `pgserver`,
not SQLite. A runtime production DB role must not have superuser or `BYPASSRLS`
privileges. The auth integration suite verifies behavior using a restricted role.

**Phase 2 complete — verified 2026-09-29:** `make gate` passes — **1638 tests passed, 6 skipped**.
See the [Phase 2 gate report](docs/reports/phase-2-gate.md) for evidence and remaining
production prerequisites. Phase 3 (core waste domain) is next. Startup now refuses
unclassified routes; OpenAPI advertises actual bearer and error contracts.
Recovery is locally end-to-end verified; external SMTP delivery and real Redis
have not been tested here. Production requires shared Redis 7+ counters and
configured STARTTLS mail; development adapters are explicitly labelled. See the
[recovery runbook](docs/api/account-recovery.md) for endpoints and worker setup.
Tenant [audit/session administration](docs/api/security-administration.md) is now
available with permission checks, audited reads and refresh-safe revocation.
[API-key lifecycle](docs/api/api-keys.md) now supports one-time issuance, finite
expiry, rotation and revocation. Machine ingestion endpoints remain planned.
[Platform tenant administration](docs/api/platform-tenants.md) now includes guarded
provisioning, suspension and activation, plus offline first-operator bootstrap.
Platform mutations now require [session-bound password confirmation](docs/api/platform-step-up.md).
[Opt-in platform-action MFA](docs/api/platform-mfa.md) adds TOTP, one-time recovery
codes and guarded factor replacement. Enrolled operators need two-factor confirmation
for registry writes; ordinary login and unenrolled password confirmation are unchanged.
[Operator lifecycle](docs/api/platform-operators.md) now supports MFA-protected invitations,
suspension/reactivation and one-way required-MFA policy, with a last-operator guard.
Global/login-wide MFA, all-factor-loss recovery and break-glass remain planned. See
[`docs/project-state.md`](docs/project-state.md) for remaining work.

---

## Architecture at a glance

```
Browser SPA ──► reverse proxy ──► FastAPI (modular monolith)
                                      │
        ┌─────────────────────────────┼──────────────────────────────┐
        │                             │                              │
   Identity/Tenancy            Core Operations                Intelligence
   authn · rbac · audit        bins · telemetry · collections  forecasting · anomaly
                               routes · fleet · facilities     classification · optimisation
                               loads · recovery                analytics · assistant
        │                             │                              │
        └─────────────► PostgreSQL 16 ◄┴► Redis ◄─ workers ─► object storage
                        (+ RLS)
```

* **Modular monolith** with 28 bounded contexts, enforced by an import-graph
  test — not a distributed system pretending to be one
  ([ADR-0001](docs/architecture/decisions.md)).
* **Tenant isolation in three layers:** repository scoping, PostgreSQL
  row-level security, and an adversarial cross-tenant test suite
  ([ADR-0003](docs/architecture/decisions.md)).
* **Determinism where it matters:** route optimisation is OR-Tools CVRPTW and
  bin priority is a transparent weighted score. An LLM is never used for
  numerical optimisation, authentication, authorisation or validation
  ([ADR-0007](docs/architecture/decisions.md), [ADR-0008](docs/architecture/decisions.md)).
* **Append-only intelligence artefacts** — optimisation runs, forecasts, model
  versions, classifications and audit records are never overwritten, which is
  what makes comparison, provenance and rollback possible
  ([ADR-0010](docs/architecture/decisions.md)).

---

## Documentation index

| Document | Contents |
|---|---|
| [`docs/environment.md`](docs/environment.md) | Verified sandbox capabilities with reproduction commands, and the three findings that shaped the design |
| [`docs/architecture/architecture.md`](docs/architecture/architecture.md) | System context, module decomposition, dependency rules, request lifecycle, scaling path |
| [`docs/architecture/decisions.md`](docs/architecture/decisions.md) | 15 ADRs with rejected alternatives |
| [`docs/architecture/domain-model.md`](docs/architecture/domain-model.md) | Aggregates, invariants, state machines, 20 business rules, metric formulas, explainable scoring |
| [`docs/database/erd.md`](docs/database/erd.md) | 72-table physical design: columns, constraints, indexes, RLS plan, retention |
| [`docs/api/rest-api.md`](docs/api/rest-api.md) | ~150 endpoints, conventions, long-running job flows, assistant response contract |
| [`docs/api/error-catalogue.md`](docs/api/error-catalogue.md) | Closed error-code enumeration and `details` discipline |
| [`docs/security/rbac.md`](docs/security/rbac.md) | Permission catalogue, 11 roles, full role × permission matrix, authorization test matrix |
| [`docs/security/security-model.md`](docs/security/security-model.md) | Threat model, authn/authz, tenant isolation, upload security, logging and privacy |
| [`docs/frontend/information-architecture.md`](docs/frontend/information-architecture.md) | Route map, permission-adaptive navigation, screen composition, component system |
| [`docs/ai/ai-architecture.md`](docs/ai/ai-architecture.md) | Where AI is and is not used, forecasting, anomaly detection, classification, assistant safety |
| [`docs/testing/testing-strategy.md`](docs/testing/testing-strategy.md) | Test pyramid, suites, coverage gates, end-to-end journeys, failure injection |
| [`docs/phases.md`](docs/phases.md) | Phase-by-phase deliverables and gate criteria |
| [`docs/requirements-traceability.md`](docs/requirements-traceability.md) | 69 requirements → subsystem → impl → API → DB → tests → docs |
| [`docs/risks-and-assumptions.md`](docs/risks-and-assumptions.md) | Risk register, environmental assumptions, open questions with default decisions |
| [`docs/project-state.md`](docs/project-state.md) | Continuity state for the next development session |

---

## Repository layout

```
backend/
  app/
    api/v1/         HTTP routers (no business logic)
    core/           config, errors, security, tenancy, logging, cache, events
    db/             engine, session, mixins, base
    models/         SQLAlchemy entities (one module per bounded context)
    schemas/        Pydantic request/response contracts
    repositories/   tenant-scoped data access
    services/       business logic
    authorization/  permission catalogue, role matrix, guards
    analytics/      metric definitions and aggregations
    ai/             forecasting, anomaly, classification, assistant, recommendations
    telemetry/      ingestion, validation, dedup, latest-state
    environment/    emission factors, carbon estimation
    integrations/   provider adapters + local implementations
    simulation/     deterministic IoT / fleet / burst simulator
    workers/        job registry, jobs, runner
  migrations/       Alembic
  tests/            unit · api · services · security · ml · ai · jobs · architecture
frontend/           React + TypeScript + Vite SPA
ml/                 training, evaluation, datasets, model cards
simulator/          scenario definitions
infrastructure/     docker, nginx, deployment
docs/               architecture, database, api, security, ai, testing, deployment
scripts/            bootstrap, pg_server, check_secrets
```

---

## Safety and integrity commitments

These are implementation requirements. Enforcement is being added phase by phase;
the current verified coverage is recorded in `docs/project-state.md`:

1. No fake success responses; no mock endpoints; no hardcoded dashboard numbers.
2. Every important metric is traceable to records, a model version, or a sourced
   emission factor.
3. Missing data produces an explicit `INSUFFICIENT_DATA` result, never a `0`.
4. AI recommendations always carry evidence; they never execute destructive
   actions without explicit human confirmation.
5. Low-confidence waste classifications are queued for human review and never
   drive hazardous-waste handling.
6. No model accuracy is published without its dataset, evaluation type and an
   honest statement about what that dataset proves.
7. No secrets in source; configuration comes from the environment.

---

## Licence

Academic project — see the repository owner for terms.
