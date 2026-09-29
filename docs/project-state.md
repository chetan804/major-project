# EcoMind-AI — Project State

**This file is the continuity source for future development sessions.**
Update it at the end of every working session (section 76).

**Last updated:** 2026-09-29 · **Session:** 14 (Phase 2 completion and pull request)

---

## 1. Current position

| Field | Value |
|---|---|
| Current phase | **Phase 2 COMPLETE — Authentication, tenancy, RBAC, audit; Phase 3 next** |
| Next action | Phase 3 core waste-domain APIs; retain the completed security gate and closed break-glass boundary |
| Repository branch | `arena/01a0eaec-major-project` |
| Baseline commit | `d34fda2` (merged Phase 2 foundation) |
| Architecture status | Coherent and complete at design level; no known blocking open question |
| Gate status | lint, format, mypy, secret scan and migration drift all clean; **1638 passed, 6 skipped** |
| Open PR | [#4 — Complete Phase 2](https://github.com/chetan804/major-project/pull/4), from this branch into `main`; hosted checks are authoritative on the PR |

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

**Code implemented and verified (Phase 2 — complete to its written gate):**

| Area | Delivered |
|---|---|
| Models | 13 modules covering the domain and auth delivery — **85 tables** (`identity`, `geography`, `taxonomy`, `bins`, `collections`, `fleet`, `routing`, `facilities`, `loads`, `environment`, `intelligence`, `platform`, `auth_mail`) |
| Migrations | `43f430493613` + `0a396e61910c` + `ca9642749b58` + `600bc6193a23` + `1eb8da7c2793` + `c4195297efc7` + `e1c3617bfb4c` — **85 tables, FORCE RLS on all 74 tenant-scoped tables**, reference data and processing view. Encrypted outbox, verification hashes, security indexes and machine actor attribution; full round-trip and drift checks pass |
| Authorization | `authorization/{permissions,role_matrix,context,checks,resolution,tokens,totp}.py` — 101 permission codes, 10 seeded roles with 322 grants **derived from `rbac.md` §4**, the actor value object, service-layer checks, and JWT + refresh-token handling |
| Repositories | `repositories/{base,identity}.py` — tenant-scoped base with pagination, allow-listed sorting and 404-not-403 behaviour, plus the identity repositories |
| Services | `services/auth.py` — sign-in, invitation registration, refresh rotation with replay detection, session revocation, password change and reset |
| API | `api/v1/{auth,users,roles,tenants,security_administration,api_keys,platform_tenants,platform_step_up,platform_mfa,platform_operators}.py` — **60 operations**, 6 public by written decision; explicit response and request contracts |
| Auth hardening | RLS-bound authentication, matching signed identity claims, durable failure counters/audit, append-only refresh rotation, replay-family revocation, user-row serialization, guarded invitations and reset revocation (ADR-0014) |
| Administration | `services/identity.py` — permission-checked/audited user CRUD, role editor/assignments, current tenant metadata; serialized last-admin protection (ADR-0015) |
| Dev seed | `scripts/seed.py --profile dev` — one tenant/admin and nine tenant roles; private initial credentials; repeatable without resetting access |
| Recovery/verification | `auth_delivery.py`, `integrations/auth_mail.py`, `workers/auth_mail.py` — encrypted transactional outbox, local MIME/STARTTLS adapters, bounded dispatch, expiring single-use codes (ADR-0016) |
| Rate limits | IP and normalized identity budgets; HMAC keys; Redis atomic counters or bounded local memory; failure denies auth and affects readiness |
| Security administration | Tenant audit list/detail with signed cursor paging and read audit; session list/family/bulk revocation; bounded metadata privacy and append-only repository protections (ADR-0017) |
| API keys | Human-only metadata/create/rotate/revoke + device scope catalogue; tenant-bound machine auth service, finite expiry and separate audit principal reference (ADR-0018). Device HTTP ingestion remains planned |
| Platform control plane | Six platform registry endpoints, offline first-operator bootstrap, atomic invited-admin provisioning, suspension/activation and live scope separation (ADR-0019). Break-glass remains closed |
| Platform reauthentication | POST/DELETE password confirmation, mandatory five-minute per-session gate for registry writes, shared lockout, rate budgets and audit (ADR-0020). Password-only for legacy unenrolled operators without mandatory policy; enrolled operators also require ADR-0021 verification |
| Platform action MFA | Opt-in TOTP, independently encrypted bound seeds, single-use recovery codes, transactional replacement/rotation and factor-bound proof. No active-factor disable or password-only recovery (ADR-0021) |
| Operator lifecycle | Six own-realm routes, dedicated platform permissions, strong MFA on every write, fixed-role verified invitation, last-operator guard, suspension/reactivation and one-way required-MFA policy (ADR-0022). No all-factor-loss recovery or role editor |
| Startup / API contract | Production mounted-route policy guard, explicit public/self-service exceptions, 460 role/operation gate cases, 54 anonymous-denial cases and bearer/error OpenAPI contracts (ADR-0023) |
| Tests | 1638 tests across `unit`, `db`, `api`, `security`, `architecture` — all green |

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
| Redis | absent; optional cache uses labelled `fakeredis`; security counters use labelled bounded memory locally. Redis transaction contract tested with fakeredis, not a real Redis server |
| Docker | absent; Compose/Dockerfiles will be authored but not build-tested here (disclosed) |
| PostGIS | unavailable; dialect-aware geo layer designed (ADR-0005) |
| Frontend toolchain | Node 22.22.3 / npm 10.9.8 available; project not yet scaffolded |

---

## 4. Database state

| Field | Value |
|---|---|
| Migrations applied | `0001_baseline` + `43f430493613` + `0a396e61910c` + `ca9642749b58` + `600bc6193a23` + `1eb8da7c2793` + `c4195297efc7` + `e1c3617bfb4c` (single head; round-trip verified) |
| Tables created | **85**, of which **74 are tenant-scoped** and carry an RLS policy with `FORCE ROW LEVEL SECURITY` |
| Tables global by decision | 11, each with a written justification in `app/db/rls.py::GLOBAL_TABLES` (see `GLOBAL_TABLES`; migration bookkeeping is counted separately) |
| Reference data seeded | 101 permissions, 10 roles, 322 role-permission grants, 11 waste categories, 23 materials, 7 emission factors, 4 model versions, 5 report definitions, 10 notification templates, 5 integrations, 7 retention policies |
| RLS coverage | `rls_coverage_report()` returns `unclassified: []` — 74 tenant-scoped / 11 global |
| Known limitations | no `btree_gist` → assignment-overlap guard via partial unique index + service check; telemetry partitioning documented but not enabled |

---

## 5. API state

| Field | Value |
|---|---|
| Implemented endpoints | **60** — 14 auth, 16 user/role/permission/current-tenant, 5 audit/session, 6 key-management, 6 platform-registry, 2 platform-confirmation, 5 own-factor MFA, 6 operator-lifecycle operations |
| Public by written decision | 6 — `POST /auth/login`, `POST /auth/refresh`, `POST /auth/password-reset`, `POST /auth/password-reset/confirm`, `POST /auth/email/verify-request`, `POST /auth/email/verify-confirm` (each with a reason recorded in `api/route_policy.py` and independently tested) |
| Planned endpoints | ~150 across 15 groups (see `api/rest-api.md`) |
| OpenAPI | generated by FastAPI at `/openapi.json`; mounted-route, bearer, closed-input and error-envelope contract tests implemented |
| Error contract | closed enum implemented in `core/errors.py` and asserted by `tests/test_error_contract.py` |
| Route classification gate | **live**: production startup refuses unclassified routes before opening resources; all 60 operations are explicitly public, authenticated self-service or permission-protected |

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
run that records real metrics against a named dataset (ADR-0008), which requires future evaluation tooling. The development identity seed deliberately
leaves every model candidate untouched.

No models trained, no metrics published, **no accuracy claims made anywhere**.

## 8. Tests

`make test` → **1638 passed, 6 skipped**, 0 failed (~358 s).

| Marker | Files | What it pins |
|---|---|---|
| `unit` | `test_config`, `test_time`, `test_cache`, `test_logging` | settings validation matrix, aware-UTC rules and tenant-day bounds, cache key scoping and failure containment, log redaction |
| `api` | `test_health`, `test_error_contract`, `test_request_context` | probe semantics, exact error-envelope contract, contextvar propagation across a pure-ASGI stack |
| `security` | `test_security_headers`, **`test_authorization_matrix`** | headers on success *and* error, CORS allow/reject; **the seeded roles against `rbac.md` §4, cell by cell, plus the deliberate omissions**; `test_auth_lifecycle` adds 36 HTTP/service tests under real non-superuser RLS |
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

1. **Identity bootstrap now completes end-to-end.** `./scripts/bootstrap.sh` and
   a subsequent `make seed` were verified. Initial credentials are in the ignored
   `.runtime/dev-account.json` with mode 0600. Operational demo bins, telemetry and
   ML evaluations are still not seeded, and models remain candidates. Never use
   this development seed in staging/production (the CLI refuses both).
2. **Container artefacts are still not written.** Dockerfiles, Compose and nginx were
   planned for Phase 1 and remain deferred rather than committed unverified: this
   environment has no Docker daemon, so a container configuration could be authored
   and *statistically reviewed* but never built, started or health-checked. Shipping
   an unverifiable artefact under a "phase complete" report would be exactly the
   overclaim the master prompt forbids. Hosted CI is separate from Docker validation. GitHub checks can be inspected;
   the current PR reports the hosted result. No container verification is claimed.
3. **The frontend is not scaffolded yet.** Deferred to the frontend phase rather
   than created as an empty shell now, so that no route exists without a screen
   behind it (section 19).
4. **Auth and tenant administration now have routers.** 60 operations are mounted.
   Audit browsing and administrative session control are implemented. Remaining
   domain/device workflows, global/login-wide MFA, break-glass and operator recovery
   still need implementation/tests. Tenant registry and API-key lifecycle are now
   implemented; device HTTP ingestion is not.
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

9. **Recovery delivery and auth rate limits are implemented, not deployment-proven.**
   Local mailbox requests/dispatch/confirmation are verified. External SMTP and
   real Redis remain untested; delivery needs a repeated worker schedule, secret
   management and monitoring. Mail is at-least-once. Terminal outbox/local mail
   retention is not automated. See `api/account-recovery.md` for operational limits.
   Invitations create no session; email proof can activate INVITED users without
   adding any role grants. Platform provisioning/operator invitations queue verification atomically;
   ordinary tenant invitations retain the documented request-verification flow.
10. **Refresh-token compatibility:** legacy unprefixed tokens require a fresh
    login. The new routing hint is not an authorization claim (ADR-0014). JSON
    token transport remains current; cookie transport is still planned.
11. **No runtime session-history retention job exists yet.** Never delete consumed
    refresh hashes while their family can still have a live descendant.

### Session 5 verification and changes (historical)

* Restored dependencies and local configuration with
  `SKIP_MIGRATIONS=1 ./scripts/bootstrap.sh`, then `make migrate`.
* `make gate`: lint/format, mypy, secret scan, no migration drift, and
  **461 passed / 3 skipped**. No new schema migration was needed.
* Added **36** tests in `backend/tests/security/test_auth_lifecycle.py`; HTTP
  requests use a restricted PostgreSQL role with RLS active, not mocked actors.
* Fixed audit writes passing a nonexistent `changes` ORM column; change details
  now live in the existing JSON metadata. Login/reset audit actors and tenant
  scopes are correct.
* Failed sign-ins and replay revocations survive error responses, while an
  injected internal failure proves ordinary writes roll back.
* Rotation retains historical hashes and predecessor links. User-row locks
  serialize simultaneous refresh, ancestor replay, password changes and logout.
* Password whitespace is preserved exactly, inactive/deleted users and tenants
  are rejected, and bearer claims must match the live session's user and tenant.
* README quickstart now describes runnable backend targets rather than planned
  frontend/worker commands. No UI, demo-account seed, or additional admin router
  was added in this session.
* Existing `pgserver` shutdown logging noise and the `XDG_RUNTIME_DIR` fallback
  warning remain non-failing. GitHub Actions was not run in this session.

### Session 6 verification and changes

* Added 16 operations: users list/detail/invite/update/soft-delete, role
  assignment/revocation, own permissions, role list/detail/create/update/permission
  replacement, tenant permission catalogue, and current tenant GET/PATCH.
* Service and router checks, foreign-ID 404s, privilege ceilings, reserved
  platform/device grants, current-session/account rechecks, and audit records
  protect administration. Changing account status revokes sessions/reset tokens.
* The last recovery administrator cannot be suspended, deleted, stripped of
  required permissions, or left with only an expiring grant. Tenant-row locking
  makes this invariant safe under concurrent administrative requests (ADR-0015).
* `seed.py` creates only a development tenant, admin and nine human role bundles.
  It does not reset changed passwords, reactivate disabled users, restore removed
  grants, or invent credentials when an existing account's local file is missing.
* Fixed bootstrap DB URL propagation and Alembic handling of percent-encoded URLs.
  Full bootstrap succeeded; rerunning the seed reported no changes. A smoke
  test using the actual local seed credentials signed in, read `/auth/me`,
  `/users`, `/roles`, `/permissions`, `/tenants/current` (all 200), then signed
  out. OpenAPI confirms 28 versioned operations. No credentials were logged.
* Shared non-superuser HTTP fixture moved to `tests/security/conftest.py`.
  Added **57 administration tests**, **8 seed tests** and **1 encoded-URL migration
  regression**, in addition to expanded architecture checks. The route matrix
  exercises all nine tenant roles against all new operations.
* `make gate`: **544 passed, 4 skipped**, lint/format/mypy/secret scan clean,
  no migration drift. Newly created files were also explicitly secret-scanned.
  No schema revision was required. GitHub Actions was not run.
* Runtime PostgreSQL remains a local development cluster. Production must use
  a non-superuser application role; tests exercise actual RLS on that role.

### Session 7 verification and changes

* Added public `/auth/email/verify-request` and `/auth/email/verify-confirm`.
  Reset/verification requests return identical queued-if-eligible responses for
  known/unknown/ineligible accounts, or uniform configuration/rate failures.
* Added independent Fernet-encrypted `auth_mail_outbox` with forced tenant RLS,
  one-hour credentials, transactional enqueue/supersession, SKIP LOCKED dispatch,
  exponential retries, stale-code checks and terminal payload erasure. Worker
  logs only aggregate counts; transport exceptions and mail bodies are not logged.
* Implemented private local `.eml` mail and mandatory verified STARTTLS transport.
  `make auth-mail` processes one bounded batch per tenant; it must be scheduled
  repeatedly. External acceptance is at-least-once, not exactly-once or a promise
  of inbox delivery. No frontend confirmation links are invented.
* Auth rate limits use atomic Redis counters separately from the fail-open cache,
  or a bounded simulated memory counter locally. Counter failures deny auth;
  `/ready` checks actual Redis counter capability. Production rejects disabled
  or non-Redis limits. Trusted-proxy configuration is an operator responsibility.
* New revision `0a396e61910c` adds the outbox and User verification hash/expiry.
  Fixed the previous migration to retain its original 73-table RLS list: deriving
  historical DDL from today's ORM broke clean installs when a future table arrived.
* Bootstrap now generates/preserves an independent encryption key and protects
  `.env` with 0600 permissions. Actual local smoke: HTTP request -> CLI worker ->
  private MIME code -> successful verification, rejected replay, login/me/logout,
  healthy readiness and an OpenAPI inventory of 30 versioned operations. The local
  seed admin was explicitly verified by that smoke; the seed itself never marks
  an account verified or resets existing credentials.
* Added **42 focused tests** across delivery/limiter security and unit suites.
  Full gate: **603 passed / 5 skipped**, lint/format/mypy and migration drift clean;
  fresh-schema upgrade, downgrade/re-upgrade and offline SQL checks pass. Tracked
  and newly created source files were separately secret-scanned.
* SMTP policy tested using a test double, Redis transactions using fakeredis;
  no external SMTP send, real Redis server, GitHub Actions, commit or PR execution.
  Existing pgserver shutdown/XDG warnings remain non-failing.

### Session 8 verification and changes

* Added five permission-declared routes: audit stream/detail, tenant session
  list, device-family revocation and user-wide session revocation. There are
  now 35 versioned operations; public/authenticated classification is unchanged.
* Audit pages use descending timestamp/integer-ID keysets, exact/time filters,
  one-hour tenant/filter-bound HMAC cursors and no total count. Successful reads
  commit their audit record before responding; responses never expose credential
  hashes. This is a live traversal, not an immutable export snapshot.
* New audit writes are bounded/redacted and correlate request IDs/available
  actor-name snapshots. Legacy data is redacted only at read time. Blocked the
  inherited generic update/soft-delete methods: lack of updated_at/deleted_at
  had not actually made the repository append-only. Runtime-role tests now grant
  audit SELECT/INSERT only and prove raw SQL UPDATE/DELETE fail.
* Revocation locks target User, covers refreshed descendants and retains token
  history; bulk includes all devices and self. It does not disable password login.
  Operations managers cannot revoke more privileged administrators without the
  elevation permission. No seeded role permissions changed.
* Changed the shared tenant mutex to NO KEY UPDATE for FK compatibility.
  **Session 9 evidence correction:** sessions/audits have no tenant FK. The original
  refresh-based regression did not prove that FK edge; it now forces the recovery
  outbox INSERT while User is locked. Separate refresh and mutual-admin tests
  cover session revocation and stale-caller authorization.
* Revision `ca9642749b58` changes only query indexes; no row data is deleted. The
  ordinary index build can block writes and needs deployment scheduling. Fresh
  upgrade, complete downgrade/re-upgrade, offline SQL and drift checks pass.
* Added **44 security tests and 14 unit cases**, including all nine tenant roles,
  custom auditor, cross-tenant denials, privacy, rollback and concurrency. Full
  gate: **676 passed / 5 skipped**, lint/format, mypy (69 source files), tracked
  and new-source secret scans and migration drift clean.
* Actual local seed smoke exercised all five routes, immediate bearer invalidation,
  subsequent valid login, readiness and the 35-operation OpenAPI inventory. Local
  admin sessions used by the smoke were revoked; the password/account are unchanged.
* API-key lifecycle, platform/break-glass, frontend, export/retention and general
  endpoint throttles are not part of this slice. No external SMTP/real Redis,
  production-scale load test, GitHub Actions, commit or PR execution is claimed.

### Session 9 verification and changes

* Added six human bearer-authenticated management routes: scope catalogue, key
  list/detail, create, rotate and revoke. There are 41 versioned operations, still
  six deliberately public auth operations. Machine HTTP endpoints are not mounted.
* Delegation is an explicit device-only allowlist (`bins.telemetry.ingest`), not
  arbitrary human grants. `apikeys.write` intentionally permits device provisioning;
  even admins cannot issue identity/platform scopes. Rotation may not expand scopes.
  No seeded role changes. Keys are tenant-owned, independent of creator liveness.
* Keys have a public random prefix plus 256-bit secret, SHA-256-only storage,
  90-day default/365-day maximum issuance, one-time post-commit disclosure and
  no-store responses. Rotation immediately revokes the predecessor; repeated old-ID
  rotation conflicts. Exact-key revoke is idempotent; it does not revoke descendants.
* Hardened the existing authentication helper: explicit tenant argument, forced-RLS
  binding, enabled tenant/finite expiry/allowlist checks, Tenant SHARE -> key UPDATE
  serialization, no roles/JWT, transactional last-use and machine audit. In-flight
  work may finish before revocation; consumers must keep transactions short.
* Added the nullable `actor_api_key_id` audit FK so a machine UUID is not written
  into the User FK. Audit API supports that filter/reference. Secret/key-hash/inline
  key redaction extended; cross-tenant audit actor/repository mismatches are denied.
* Migration `600bc6193a23` adds attribution and key paging/one-child rotation
  indexes. Downgrade archives actor UUIDs in reserved metadata; re-upgrade restores
  matching same-tenant references. A two-tenant, data-bearing regression proves it.
  RLS remains forced while migration data steps iterate explicit tenant contexts.
* Corrected the earlier FK concurrency explanation/test to use AuthMail, which
  actually has a tenant FK; TenantKeyMixin sessions/audit rows do not. The lock
  implementation remains NO KEY UPDATE; the revised regression now tests that edge.
* Fixed an existing flaky session-audit test helper: explicit event ID ordering
  replaces an unordered SQL read before asserting sequential revocation counts.
* Added **64 key security cases, 4 unit cases and 1 migration-data regression**;
  full gate **757 passed / 5 skipped**, mypy 73 source files, lint/format/secrets and
  migration drift clean. New/untracked source also secret-scanned separately.
* Local seed smoke exercised all six management routes, real service authentication,
  machine attribution, immediate rotation/revoke denial and a 41-operation OpenAPI
  inventory. Smoke keys and session were revoked; plaintext keys were never written
  to files or logs. No real device, production throughput, frontend, external SMTP/
  real Redis integration, GitHub Actions, commit or PR execution is claimed.

### Session 10 verification and changes

* Added six `/platform/tenants` operations: registry list/detail, create, metadata
  patch, suspend and activate. Total **47** versioned operations; the same six auth
  routes remain public. All new routes require live human platform identity and
  `platform.tenants.read/write`, with service rechecks after the platform mutex.
* Offline interactive first-operator bootstrap creates no default password or file;
  rejects non-TTY/echo fallback and any existing platform account (even deleted or
  disabled), and atomically records SYSTEM bootstrap evidence. It is not a repair
  or second-operator enrollment command and is not run by normal bootstrap/startup.
* Provisioning is atomic: ACTIVE registry row, nine tenant role bundles, one
  INVITED TENANT_ADMIN, unshared random password hash, encrypted verification mail
  and tenant/platform audit. The administrator verifies email, then sets their own
  password via the existing reset flow. No credential is returned to the operator.
* Platform/tenant permissions are filtered by scope at resolution, including
  misconfigured stored assignments. Platform users still cannot browse customer
  data or use `X-Tenant-ID` as an impersonation switch. Break-glass remains closed.
* Suspend invalidates human sessions and recovery/verification credentials while
  retaining history. Activation never restores those sessions/codes. Device keys
  are paused by tenant status and can work again after activation if still valid.
  Cancelled/deleted/reserved platform targets cannot be reactivated through this API.
* Fixed stale tenant snapshots in login/recovery after user-lock waits. Both invite
  aliases now acquire the tenant/caller administration mutex and recheck live grants
  and sessions. Forced-interleaving regressions cover in-flight login invalidation,
  queued login denial after suspension and neutral recovery with no queued mail.
* Platform audit uses the real operator and target registry UUID in platform scope.
  Reads are audited before disclosure; failures roll back writes. Bounded target
  RLS contexts are restored on success or rolled back on failure; no policy bypass.
* Added **76 platform security cases and 14 unit cases**. Full gate **858 passed /
  6 skipped**, mypy 77 source files, lint/format, migration drift and tracked/new-file
  secret scans clean. Skips are architecture exclusions for simulation-capable
  scripts/workers, not missing RLS/security coverage. New-file totals are cumulative.
* Onboarding regression proves actual private MIME delivery for verification and
  password reset, HTTP confirmation, and a successful new administrator login.
  Tests run with a non-superuser/non-BYPASSRLS role. No external SMTP, real Redis,
  production load, frontend, Actions, commit or PR execution is claimed.
* No schema migration: head remains `600bc6193a23`, 85 tables and 74 forced tenant
  policies. Runtime DB roles need the appropriate registry DML/row-lock privileges.
  Break-glass, MFA/step-up, operator management/recovery and platform audit reader
  remain deferred. See `docs/api/platform-tenants.md` and ADR-0019.

### Session 11 verification and changes

* Added POST/DELETE `/platform/auth/step-up`: explicit current-password confirmation
  and early clearing for a live human platform writer. **Password reauthentication
  only, not MFA**. No new token, grant, tenant selector or public auth surface.
* Four platform registry mutations now require confirmation from the same live
  session within five minutes, bounded by session expiry. Registry reads do not.
  Future/pre-session timestamps are rejected. Login and refresh replacements start
  unconfirmed; password change/reset clears every proof, including kept sessions.
* Extracted common platform identity/permission locking into `platform_access.py`.
  Session lookup reloads after locks, so a retained ORM object cannot reuse cleared
  proof. Existing platform fixtures confirm through the real new endpoint before
  writes rather than disabling the gate or editing the timestamp directly.
* Wrong passwords clear current proof, increment shared persistent lockout counters
  and commit DENIED audit via the established authentication-denial transaction
  contract. Success/clear are audited; failed audit/commit rolls back changes and
  discloses no successful lease. POST is covered by pre-body IP and authenticated
  account budgets; limiter outages fail closed. Password whitespace/repr is tested.
* Revision **`1eb8da7c2793`** adds nullable `sessions.platform_reauthenticated_at`;
  no existing session is grandfathered in. A data-bearing downgrade/re-upgrade test
  proves proof is discarded while audit evidence remains. Still 85 tables/74 forced
  policies. Old application versions lack this gate: restrict platform mutations
  during mixed-version deployment and use compatible app/schema rollback pairs.
* Added **37 security cases, 11 unit cases and one migration-data regression**.
  Full gate **919 passed / 6 skipped**, mypy 81 source files, lint/format, migration
  drift and tracked/new-file secret scans clean. 49 versioned operations, same six
  public auth operations. Security checks use real restricted-role PostgreSQL.
* Six skips remain simulation-capable module architecture exclusions. No frontend,
  external SMTP/real Redis, production-scale load, MFA hardware/authenticator,
  break-glass access, GitHub Actions, commit or PR execution is claimed.
* Runbook: `docs/api/platform-step-up.md`; design: ADR-0020. Next: second-factor
  enrollment/verification and recovery design, then explicit bounded break-glass
  and platform operator lifecycle/audit access. Do not treat a password timestamp
  as second-factor assurance or grant a cross-tenant data bypass.

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

### Session 12 verification and changes

* Implemented ADR-0021: **opt-in platform-action TOTP**, not mandatory enrollment or
  login-wide MFA. Existing unenrolled password confirmation remains unchanged.
  Enrolled writers need password plus TOTP or a one-time recovery code for all four
  registry mutation services. Proof is fresh, session-bound and current-factor-bound.
* Added five human platform-writer MFA routes (status, enrollment start/confirm/cancel,
  recovery rotation); **54 versioned operations**, same six public auth operations.
  No disable, password-only recovery, customer-data bypass or break-glass endpoint.
* RFC 6238 HMAC-SHA1, 160-bit seeds, six digits, 30 seconds, one-step skew and monotonic
  consumed counters under User lock. Independent Fernet encryption binds purpose,
  tenant, user and factor. Key-reuse comparisons include equivalent base64 encodings.
  Bootstrap privately provisions a separate dev MFA key, preserving configured keys.
* Pending enrollment is session-bound and expires within ten minutes. Replacement
  requires current strong proof; old factor remains until activation commits.
  Activation consumes its counter, clears all proofs and discloses ten 192-bit
  recovery codes once. Codes are hash-only and single-use across sessions/concurrency.
  Rotation needs strong proof plus password and atomically replaces hashes/clears proofs.
* Password reset/change cancels pending enrollment and clears proofs but retains the
  active factor/codes. Refresh/new login inherits neither proof nor pending authority.
  Credential POSTs share step-up IP/account budgets and durable lockout. Invalid
  credentials clear proof and commit denial audit; failed persistence rolls everything
  back. Long password checks recheck live-session/lease bounds before promotion.
* Added privacy coverage for representations, encrypted storage and logs/audit.
  Failure-injection tests found an outer error-middleware cache-header gap; unexpected
  errors now carry `no-store` too, including failed issuance/rotation commits.
* Migration **`c4195297efc7`**, parent `1eb8da7c2793`, adds six User and two Session
  fields, keeping **85 tables / 74 forced policies**. Locked downgrade guard refuses
  any remaining active/pending/counter/recovery/session proof state, preserving data.
  Old applications still bypass MFA: restrict platform writes/enrollment during rollout
  and rollback, and never clear factors to force a downgrade.
* Full final gate: **1018 passed / 6 skipped**, mypy 85 source files, lint/format,
  migration drift and tracked/new-file secret scans clean. Tests use real restricted-role
  PostgreSQL and standard RFC vectors. Evidence: `.runtime/session12-final-gate.log`.
* Runbook: `docs/api/platform-mfa.md`. Actual authenticator-app/hardware interoperability,
  external SMTP/real Redis, production load, frontend, mandatory enrollment, all-factor
  loss recovery and break-glass remain unverified or unimplemented as applicable.

### Session 13 verification and changes

* Added ADR-0022 before implementation. Six reserved-realm operator routes list/read,
  invite, suspend/reactivate and require action MFA. Dedicated PLATFORM-scoped
  `platform.operators.read/write`; **60 operations**, same six public auth operations.
  Every lifecycle write requires current password+MFA, including for legacy operators.
* Fixed-role SUPER_ADMIN invitations require the complete reviewed platform grant set
  and exact role catalogue. Atomic user/grant/audit/encrypted verification delivery,
  unshared 128-character random initial password, independent mailbox verification
  and password reset. Inviter never receives a usable credential. Duplicate/reserved
  email conflicts; no arbitrary role/tenant/credential selector.
* New `users.platform_mfa_required` defaults false for compatibility. HTTP invitations
  set true; one-way `require-mfa` tightens legacy policy and immediately clears all
  proofs. Required but unenrolled accounts can log in, read and enroll, not mutate
  the registry using password-only confirmation. Login-wide MFA is not claimed.
* Suspension retains active factor/recovery codes/policy, but revokes all sessions,
  proofs, pending enrollment and reset/verification codes. Reactivation returns
  ACTIVE only after mailbox verification, otherwise INVITED. No credential/session
  restoration, unlock, deletion, factor removal or all-factor-loss repair.
* Realm mutex serializes a conservative last-permanent-MFA-manager invariant, with
  live caller rechecks and bound/decryptable factor checks. Concurrent cross- and
  self-suspensions cannot remove both managers. Temporary grants, expired/locked/
  disabled/unenrolled accounts do not count. Device custody/continued human availability
  are not proved by this invariant and still require operational governance.
* Audited bounded metadata reads, closed private request/response contracts,
  pre-body IP/shared-account budgets and failed-counter denial. Real HTTP mail,
  password, MFA, required-policy and lifecycle flows under restricted PostgreSQL.
  Failure injection proves audit/commit/delivery rollback; strong-reference regression
  verifies a cached User cannot resurrect old password-only policy.
* Migration **`e1c3617bfb4c`**, parent `c4195297efc7`; **85 tables / 74 forced policies**,
  **101 permissions / 322 baseline grants**. The applied DB/code inventory corrected
  an inherited stale grant-count note; this migration adds two grants, not fifteen.
  Downgrade refuses any true policy.
  Alembic commits per revision: tests now model partial downgrade progress when an
  older MFA guard refuses. Inspect actual head and restore compatible schema before
  serving current code. Never erase required policy just to force a rollback.
* Final gate **1080 passed / 6 skipped**; lint/format 128 files, mypy 88 source files,
  migration drift and tracked/new-file secret scans clean. Evidence:
  `.runtime/session13-final-gate.log`. OpenAPI: 60 operations, no break-glass.
* Runbook `docs/api/platform-operators.md`. No physical authenticator interoperability,
  external SMTP/real Redis, production load, frontend, role editor, authorized platform
  audit HTTP viewer, independently verified emergency recovery, commit/PR or break-glass
  implementation is claimed. First bootstrap is still not an access repair tool.

### Session 14 — Phase 2 completion

* Audited the written Phase 2 build/test/gate, closed the missing production startup
  self-check, and recorded ADR-0023 rather than expanding optional privileged features
  indefinitely. **Phase 2 is complete; Phase 3 is next.** The formal gate report is
  `docs/reports/phase-2-gate.md`; it distinguishes API completion from production readiness.
* Added `api/route_policy.py`: actual mounted/hidden/nested dependency inspection;
  unknown/missing permission, duplicate parameter-equivalent path and unsupported
  transport rejection. Runs before DB/cache/counter initialization. Six public auth
  and eight authenticated self-service exceptions have explicit reasons.
* Added 460 baseline role x mounted permission-gate cases, 54 real-route anonymous
  rejection cases, adversarial startup/lifespan tests and OpenAPI contracts. The
  dependency matrix is not represented as business/MFA/RLS success; separate real
  restricted-role integration tests retain those checks.
* OpenAPI now publishes bearer security, required permissions and the actual error
  envelope (400 request validation, 422 domain rules). Runtime auth/error handling
  remains unchanged. API description no longer implies future domain APIs are live.
* Added explicit SQL-shaped query/login/mutation probes and fixed secret scanning
  to inspect actual index blobs as well as working copies (with staged-only leak tests).
* Final local gate **1638 passed / 6 skipped**; lint/format 134 files, mypy 90 source
  files, migration drift and tracked/staged secret scan clean. No new migration or
  endpoint in this closure: head `e1c3617bfb4c`, 60 operations, 85 tables/74 policies,
  101 permissions/322 baseline grants. Evidence `.runtime/phase2-final-gate.log`.
* Committed the accumulated delivery as `09505d2`, pushed the session branch and
  opened PR **#4** against `main`. Hosted CI is tracked on the PR separately from
  the local gate. Hosted lint/type/secret and PostgreSQL test jobs passed on
  `dcc7323` ([run 36609556120](https://github.com/chetan804/major-project/actions/runs/36609556120)).
  GitGuardian separately classified two literal HMAC test identity tuples as generic
  authentication secrets; they were never service credentials. The follow-up generates
  those identity fixtures at runtime without weakening the assertions or suppressing
  detectors. The PR checks show the result for the latest revision.
* Updated phase status, requirements traceability, gate evidence and PR scope. No
  production SMTP/Redis/load, frontend, container or emergency-access claim. Pending
  privileged features remain unavailable and do not block the original Phase 2 gate.

## 10. Next recommended action

1. **Phase 3 core waste domain:** zones/service areas, taxonomy and bins first, with
   closed contracts, declared capabilities, service/RLS isolation and real workflows.
   Preserve the complete Phase 2 gate; schema presence alone is not API delivery.
2. **Production prerequisites:** real shared Redis/SMTP, deployment roles/ingress,
   worker scheduling, retained replay/audit evidence, key custody and bounded load/
   transaction tests. Deferred Phase 1 container artifacts remain explicit work.
3. **Separate privileged-access follow-up:** controlled platform audit reader,
   independently verified operator recovery, global MFA rollout and reviewed role
   editing before any narrow consented/revocable break-glass. No generic tenant
   selector, RLS bypass or first-operator bootstrap repair shortcut.
4. Frontend and cookie transport remain later scope; do not claim either implemented.

## 11. Standing constraints for the next session

* Do not weaken tenant isolation for convenience (ADR-0003).
* Do not add a hard PostGIS, Docker, or Redis dependency (ADR-0002/0005).
* Do not publish any model metric without its dataset and evaluation type
  (section 49).
* Do not present estimated/predicted/simulated values without a provenance
  label (ADR-0013).
* Any architectural change follows the section-75 procedure and updates
  `decisions.md` before code.
