# EcoMind-AI

**AI-powered smart waste management & environmental intelligence platform.**

EcoMind-AI converts waste-management data into operational decisions: it
ingests smart-bin telemetry, forecasts waste generation, classifies waste from
images, plans and optimises collection routes under real capacity and
time-window constraints, tracks material from collection through processing to
recovery or disposal, estimates carbon impact from versioned emission factors,
and answers operational questions through an AI assistant that is bound to
permission-checked tools rather than free invention.

Multi-tenant, role-based, API-first, built for municipalities, private haulers,
campuses, commercial and industrial facilities.

---

## Project status

| Phase | Scope | State |
|---|---|---|
| **0** | Requirements, architecture, domain model, ERD, API/RBAC/AI design | ✅ **Complete** |
| 1 | Repository & infrastructure scaffolding | ⏳ Next |
| 2 | Authentication, tenancy, RBAC, audit | Planned |
| 3 | Core waste domain (bins, vehicles, drivers, facilities, taxonomy) | Planned |
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

```bash
# 1. Bootstrap: virtualenv, dependencies, .env, real PostgreSQL, migrations, seed
./scripts/bootstrap.sh

# 2. Start the services
make api      # FastAPI  → http://localhost:8000  (OpenAPI docs at /docs)
make web      # Vite SPA → http://localhost:5173
make worker   # background jobs (forecasts, aggregations, notifications)

# 3. Drive the platform with simulated IoT data
make simulate

# 4. Verify
make audit    # lint + types + all tests + architecture rules + secret scan
```

Development runs against a **real PostgreSQL 16** server (bundled binaries via
`pgserver`) so that constraints, `NUMERIC` precision, row-level security and
window functions behave exactly as in production. No SQLite substitute is used
anywhere — see [ADR-0002](docs/architecture/decisions.md).

Requires Python 3.11+ and Node 20+. Docker is optional: `docker compose up`
brings up the same stack with PostgreSQL, Redis, MinIO and nginx.

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
| [`docs/architecture/decisions.md`](docs/architecture/decisions.md) | 13 ADRs with rejected alternatives |
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

These are enforced in code, in the schema, and in tests — not just documented:

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
