# EcoMind-AI — Risks, Assumptions and Open Questions

**Status:** Phase 0 baseline · **Owner:** lead architect
**Rule:** an unstated assumption is a future bug. Everything the design depends
on that is not verifiable from the repository is listed here.

---

## 1. Architectural risks

| # | Risk | Likelihood | Impact | Mitigation (already designed) | Residual |
|---|---|---|---|---|---|
| R1 | A single missed tenant predicate leaks data | Medium | Critical | Three layers (repository, RLS, adversarial tests); 404-on-foreign; security audit events | Low — but never zero, hence the test suite is a permanent gate |
| R2 | RLS requires a non-owner DB role in production; a misconfigured deployment silently loses the second layer | Medium | High | `/ready` reports the RLS state; a startup check logs `SECURITY_WARNING` when the app role owns tenant tables | Low if the check is honoured in deployment review |
| R3 | Optimization job cost on a 2-vCPU host | High | Medium | Bounded solver time, job queue, `is_optimal` honesty, measured duration recorded per run | Medium — documented as an environment limitation |
| R4 | Telemetry volume outgrows the read model | Low (short term) | High | Append-only design, composite indexes, BRIN, partitioning strategy documented, retention policy, `latest` read model | Medium — partitioning not enabled here (disclosed) |
| R5 | Analytics aggregations become slow as data grows | Medium | Medium | Database-side aggregation, period rollups, caching with explicit invalidation, indexes matched to documented query patterns | Medium — no load test possible at scale in this environment |
| R6 | Model quality claims could be over-read | Medium | High | Synthetic corpus labelled as such everywhere; `is_synthetic` on datasets; promotion requires metrics; model cards carry the caveat | Low — enforced by schema, not by discipline |
| R7 | Prompt injection through recorded operational text (bin notes, complaints, CSV cells) | Medium | High | Untrusted content confined to data slots; schema-validated tool arguments; read-only tool set; injection test suite | Low-Medium |
| R8 | Route optimizer produces plans that ignore real road networks | High (dev) | Medium | Travel times from a routing-provider adapter; the local haversine adapter is **labelled** as estimated; a real provider is a configuration change | Medium in dev, Low in production with a real provider |
| R9 | Emission factors mislead if a tenant assumes they are authoritative | Medium | High | Factors are versioned rows with source, geography, methodology and effective dates; estimates carry factor provenance; comparisons require matching definitions | Low |
| R10 | Scope breadth dilutes depth | High | Medium | Phases (docs/phases.md) sequence depth-first through the operational core; each phase gate demands working, tested functionality rather than stubs | Medium — an explicit trade-off, see §4 |
| R11 | Frontend/backend contract drift | Medium | Medium | OpenAPI as the source of truth, generated TypeScript types, contract tests, single permission catalogue shared conceptually | Low |
| R12 | Simulated components mistaken for real ones | Medium | High | Every simulated value carries `SIMULATED`/`is_simulated`, surfaced in `/health`, in API metadata and as UI badges | Low |
| R13 | Test suite becomes a slow monolith | Medium | Medium | Per-worker databases, markers, parallel execution, targeted `make` targets | Low |
| R14 | Offline driver sync produces duplicates | Medium | Medium | `client_uuid` unique per tenant + idempotent event insert + sync-state reconciliation | Low |

---

## 2. Verified environment assumptions (evidence in `docs/environment.md`)

| Assumption | Status | Consequence if wrong |
|---|---|---|
| Real PostgreSQL 16.2 available via `pgserver`, persists across processes | **Verified** | Would need a container or SQLite — the latter explicitly rejected (ADR-0002) |
| No PostGIS extension available | **Verified** | The dialect-aware geo layer (ADR-0005) keeps behaviour identical |
| No Docker in the sandbox | **Verified** | Compose/Dockerfiles are authored and statically reviewed, **not** build-tested here (disclosed) |
| No Redis daemon | **Verified** | fakeredis adapter, labelled; production uses Redis |
| PyPI/npm reachable; apt blocked | **Verified** | Dependencies install; OS packages cannot |
| OR-Tools 9.15 installs and imports | **Verified** | If unavailable, optimization would need an in-house heuristic — significantly weaker results |
| No GPU; 2 vCPU / 3.8 GB | **Verified** | Deep learning is out of scope here (ADR-0008) |

---

## 3. Product/scope assumptions

| # | Assumption | Rationale |
|---|---|---|
| A1 | The platform is operator-facing (municipality/hauler/campus/facility), with no citizen mobile app. Citizen input enters as a collection request. | The specification names operators, drivers, analysts and admins as users; no citizen app is described. |
| A2 | One tenant = one operational organisation; a user may belong to several tenants and act in one at a time. | Required for contractor/staff multi-org scenarios without weakening isolation. |
| A3 | Collection "day" is evaluated in the tenant's timezone; storage is UTC everywhere. | Section 55 requires it; service windows are local-time concepts. |
| A4 | Weights are the primary measured quantity (weighbridge or onboard scale); volume is a secondary estimate. | Waste operations are weight-governed for capacity and carbon. |
| A5 | Diversion rate defaults to `RECOVERY_BASED` and is tenant-configurable; the active definition is always displayed. | Section 20 requires explicit, non-mixed definitions. |
| A6 | Hazardous waste may be classified by CV but never *acted upon* without human confirmation. | Safety and section 12. |
| A7 | Reports are generated as structured data first; PDF/XLSX rendering is a separate, later concern. | Section 43; also keeps the pipeline server-side and testable. |
| A8 | English (`en-IN`) ships first; Hindi is scaffolded. User-facing strings live in resource files from day one. | Section 54 without over-investing in translations now. |
| A9 | Single-region deployment; no data-residency partitioning in this build. | No requirement stated; per-tenant routing is documented as an extension point. |
| A10 | Email/SMS/push use adapters; the console adapter is the development implementation. | No provider credentials in scope; sections 45/62 permit adapters for unavailable infrastructure. |

---

## 4. Open questions — with the decisions taken by default

Per section 77, these are recorded **with a default decision already made**, so
that proceeding is safe and answers only redirect effort rather than block it.

### Q1 — Session scope / depth priority
The full 12-phase specification is a multi-month effort for a team. This session
implements depth-first through the operational core (Phases 1→7), then the AI
layer (8→9), then traceability/environment (10) and reporting (11), with a
hardening pass (12) covering what is built.
**Default decision:** build the complete vertical slice — real DB, real
migrations, real auth/RBAC, real telemetry, real optimization, real analytics,
real ML pipelines with honest labels — rather than shallow stubs across all
subsystems. Anything not reached is reported explicitly at the gate with its
Phase 0 design already in place.
**Your input matters if:** you need a particular subsystem finished first (e.g.
the AI assistant demo, or the full frontend) — that reorders phases, it does not
change the architecture.

### Q2 — Frontend breadth
**Default decision:** implement the frontend for the core operational journeys
(auth, dashboard, bins + telemetry, collection tasks, route optimization,
analytics, assistant, admin/RBAC) with the reusable component system, rather
than 40 pages of low-value screens. Administrative pages that are not reached
still resolve to real, permission-gated pages — no dead routes (section 19).

### Q3 — Tenancy of a real production deployment
Not needed for this build. Recorded so it is a decision rather than an accident:
the platform runs single-database multi-tenant with RLS; a per-tenant database
model is a documented extension point, not implemented.

---

## 5. Explicit non-goals (restated for auditability)

1. Microservices or Kubernetes orchestration.
2. A deep-learning vision model in `ACTIVE` state without a real labelled corpus.
3. Real-time vehicle telemetry from physical hardware (the ingestion API is real;
   the data source in development is the labelled simulator).
4. Financial/billing workflows.
5. Citizen-facing mobile applications.
6. Antivirus/EDR integration (interface stubbed, integration not implemented).
7. Multi-region deployment, data residency partitioning.
8. Any claim of measured environmental savings attributable to this software
   (section 64 forbids it absent real measurement).
