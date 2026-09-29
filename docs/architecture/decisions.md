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

---

## ADR-0014 — Authentication routing under RLS and durable denial events

**Status:** accepted · 2026-09-29

**Context.** Phase 2 review found that public auth queries ran before tenant
context was set, refresh lookup was bound to the platform tenant, rotation
replaced the only copy of the consumed hash, and request rollback erased failed
attempts and replay revocation. Superuser-only tests would conceal the RLS
failures. No schema change is necessary: `sessions` already has `family_id` and
`previous_session_id`.

**Decision.**

* Login/reset bind the tenant resolved from the supplied slug before accessing
  scoped rows. Bearer authentication binds the verified `tid` before any user or
  session lookup, and explicitly matches `tid`, `sub`, and `sid` to live records.
* Refresh credentials use `rt1.<tenant-uuid>.<384-bit-random-secret>`. Clients
  treat the whole value as opaque. The public UUID is an **untrusted routing
  hint**, never an authorization grant. After binding RLS, the full credential's
  SHA-256 hash must match a session in that tenant. There is no global session
  query, privileged function, or RLS bypass.
* Each rotation revokes the old row and inserts a new row with the same family
  and a predecessor link. Historical hashes are retained for replay detection.
  A consumed token revokes every live descendant; other devices are unaffected.
* Credential/session mutations serialize on the owning user row. This prevents
  lost failure counters, forked refresh chains, and ancestor-replay races.
  Logging out a device revokes its family, including any concurrent rotation.
* Only `AuthenticationStateChangedError` asks the request unit of work to commit
  security-denial state before returning an error. Ordinary errors roll back.
  This signal must never be raised after a partial business mutation; direct
  service callers must honor the same transaction contract.

**Consequences.** Previously issued refresh tokens without the routing format
are rejected; clients must sign in again. Reusing a token after a lost response
is indistinguishable from theft: clients must serialize refresh and reauthenticate
on reuse. Cleanup must preserve consumed hashes for the lifetime of their live
family (a retention job is not implemented yet). Returning refresh tokens in
JSON remains the current API; the planned secure-cookie transport is not built.

**Rejected.** Adding a mandatory `tenant_slug` to the refresh body (unnecessary
client contract change); looking up opaque hashes globally under elevated DB
privileges (weakens isolation); overwriting hashes (loses evidence); committing
every exception (could persist partial writes); locking only the presented
session (does not serialize an ancestor replay with a descendant rotation).

**Evidence.** `backend/tests/security/test_auth_lifecycle.py`: real HTTP requests
using a PostgreSQL role without superuser or BYPASSRLS privileges, including
concurrent refresh/replay, cross-tenant routing, durable denial writes, reset
consumption, and rollback on an injected internal failure.

---

## ADR-0015 — Tenant administration serialization and safe local provisioning

**Status:** accepted · 2026-09-29

**Context.** User, role and tenant administration must not let concurrent
requests remove all administrators, grant platform capabilities to a tenant, or
reuse permissions revoked while a request was waiting. A development seed is
also needed, but repeatable provisioning must not become a password-reset or
access-restoration backdoor.

**Decision.** Administrative writes acquire the tenant row lock before user
locks and re-resolve the caller's active account, session and grants after
acquiring it. Each service checks its own permission in addition to the router.
This tenant-wide mutex covers user deactivation/deletion, role grants, expiry
changes and edits to role permissions. Authentication only locks users and does
not acquire the tenant lock, avoiding inverse lock ordering.

A recoverable tenant retains at least one active, nondeleted user whose
**non-expiring grants collectively** contain `users.read`, `users.write`,
`roles.read`, `roles.write`, `roles.assign` and `roles.assign.elevate`. The
last-administrator guard counts that effective set, not role names or an
isolated elevation bit. Existing timed grants are honored for ordinary access,
but cannot be the sole recovery path. Removing the last recovery administrator
returns `BR-IDENTITY-LAST-ADMIN` and rolls the whole transaction back.

Granting permissions the actor lacks requires `roles.assign.elevate`. The same
ceiling applies to role editing and administration of more privileged users.
Platform, telemetry-ingest and model-promotion permissions cannot be introduced
through the tenant role editor even with elevation authority. Empty custom
roles remain visible as memberships but confer no permissions.

The development seed is a CLI-only operation restricted to `development`/`test`.
It creates one deterministic tenant/admin and copies the nine human tenant role
bundles, excluding the platform role. A transaction advisory lock serializes
initial provisioning. Subsequent runs do not repair, reset or overwrite existing
accounts, roles or grants. Initial generated login details live in an ignored,
owner-only file; losing that file does not cause a rerun to invent a replacement
password. The seed does not create operational/ML demo data or mark email as
verified.

**Consequences.** Administration within one tenant is serialized, favoring
correctness over write throughput for a low-volume workflow. Operational data
writes are unaffected. Tenant metadata is updated through explicit allowlisted
fields; changing plan, status, slug or tenant identity remains platform work.
Invitations retain the old `/auth/users` endpoint as a compatibility alias of
`/users/invite`; delivery remains unavailable until the notification flow lands.

**Rejected.** A role-name/level hierarchy (custom roles invalidate it); checking
administrator counts without locking (two requests can both pass); counting
expiring grants as the only recovery account; silently recreating admin grants
on seed reruns; publishing demo credentials in source or console output.

**Evidence.** `test_identity_admin.py` exercises each new route with all nine
tenant roles, adversarial foreign IDs, live grant changes and concurrent admin
removal under non-superuser PostgreSQL RLS. `test_dev_seed.py` verifies role
contents, usable login, repeatability, concurrency, environment restrictions,
credential file permissions and preservation of manually changed access.

---

## ADR-0016 — Transactional recovery delivery and fail-closed security counters

**Status:** accepted · **Date:** 2026-09-29

**Context.** Reset confirmation existed but the request route could not deliver
credentials. Invited users also needed a public proof-of-email flow without
signing in first. The optional cache intentionally fails open; it cannot safely
implement security budgets. Sending mail synchronously risks orphaned credentials,
request latency, secret logging and account-disclosing provider failures.

**Decision.** Issue high-entropy, one-hour, single-use credentials under the User
row lock. Persist only their hash on User. Store the recipient, tenant slug and
usable code encrypted with an independent Fernet key in a forced-RLS outbox,
committed atomically with hash replacement and issuance audit. Supersede pending
same-purpose messages. Public reset/verification requests disclose no credential
or eligibility: a configured, unthrottled request gets the same neutral 202.
Misconfiguration and security-store failures are checked before account lookup.
This is response neutrality, not a constant-time lookup guarantee.

A separately invoked worker enumerates tenants in pages and uses per-tenant
`FOR UPDATE SKIP LOCKED` batches. It checks expiry, current credential hash,
user/tenant eligibility and recipient before sending; failures retry with bounded
exponential backoff. Terminal states erase ciphertext. Audit records contain
status/attempts/error categories, not payloads, addresses or exception strings.
The worker does **not** acquire a User lock after taking Outbox locks: issuance
uses User -> Outbox order. Concurrent invalidation can therefore deliver a stale
but unusable code; confirmation remains authoritative and locks User for one-use
consumption. There is no exactly-once external-send claim.

Development `console` means private MIME files, explicitly labelled simulated,
not mail bodies printed to stdout. SMTP requires certificate-verified STARTTLS
with no insecure downgrade. Staging/production cannot use the local mailbox.
Local files replace a stable message filename; SMTP retries keep Message-ID.
A crash after SMTP accepts mail but before the transaction commits can duplicate
it. API-first messages carry the actual confirm path rather than nonexistent UI
URLs. Email proof activates INVITED accounts but adds no roles or sessions.

IP budgets run before body parsing. Normalized tenant/email or hashed opaque
credential budgets run before identity lookup; key identifiers are HMACs under
the signing secret. Redis 7+ INCR/EXPIRE NX/TTL is executed as one transaction;
expiry is fixed, not extended on each hit. Outages fail closed with 503 and
Retry-After; exceeded limits return 429 and remaining-window Retry-After. The
readiness probe exercises the actual atomic counter operation. Memory counters
are bounded and only a simulated single-process development alternative;
production requires enabled real-Redis enforcement. Raw forwarding headers are
not trusted; ingress trust configuration belongs to deployment. Auth responses
are marked no-store.

**Consequences.** API and worker must share the encryption key; the database
alone does not reveal usable queued codes. Deployments must schedule delivery,
monitor failures/backlog, protect SMTP and Redis, configure trusted proxies and
manage retention. Drain before key rotation or downgrade: there is no multi-key
keyring, and unreadable payloads are failed/erased. SMTP acceptance and local
mailbox tests do not prove external deliverability or ownership in production.
The runbook is `../api/account-recovery.md`.

**Rejected.** Returning codes in public responses; plaintext durable queues;
logging local mail to stdout; sending externally before database commit;
claiming exactly-once email; using a fail-open cache for throttling; unbounded
memory counters; trusting arbitrary X-Forwarded-For; requiring bearer auth from
an invited user to request verification; dynamic ORM discovery for historical
migration DDL (it tried to secure a future table before creating it).

**Evidence.** Forty-two focused unit/security tests exercise private MIME and
restricted-role PostgreSQL HTTP flows, ciphertext and log privacy, RLS isolation,
rollback, supersession/expiry, retries, concurrent workers/confirmations, purpose
binding, budget exhaustion/expiry, failure closure and header handling. Redis
command concurrency is tested with fakeredis, SMTP TLS policy with a double;
real external integrations remain unverified. The standalone local mail worker
was also exercised from request through successful confirmation/replay rejection.

---

## ADR-0017 — Audited security browsing and refresh-safe administrator sign-out

**Status:** accepted · **Date:** 2026-09-29

**Context.** Tenant operators need audit evidence and the ability to sign out
compromised devices without borrowing another user's self-service endpoints.
Read access exposes personal security metadata and therefore needs its own
permissions, read receipts and output contract. Offset audit pagination drifts
when reads themselves append audit events. Concurrent refresh must not defeat
revocation, and inherited repository helpers do not imply append-only history.

**Decision.** Add tenant-scoped `audit.read` stream/detail operations and
`sessions.read`/`sessions.revoke` administration operations with explicit DTOs.
Keep `/auth/sessions` self-owned. Service authorization repeats after acquiring
the existing tenant administration mutex; target-user privilege ceilings remain
permission based. More privileged targets require `roles.assign.elevate`.
Successful security reads append an audit receipt and commit before responding;
if recording fails, data is not returned. No mutation/export audit endpoint exists.

Audit paging is descending `(created_at, id)` keyset paging, capped at 100 rows,
without a total-count query. HMAC cursors are purpose-separated from JWT signing,
tenant/filter bound and valid for a fixed one-hour traversal. Every page still
requires live authorization; cursors confer none. This is live pagination, not a
long-lived MVCC snapshot. The current read receipt is appended after selection.

Audit metadata is bounded and credential-redacted on repository writes and on
legacy-row reads; reads never rewrite history. New records use request correlation
and available actor-name snapshots; old missing labels stay missing. Generic
repository update/delete methods now explicitly refuse audit mutation. Production
runtime roles must be non-owners with audit SELECT/INSERT only: application
methods do not protect against a table owner or separate archival role. Redaction
cannot identify arbitrary unlabelled secrets; producers must curate metadata.

Administrative sign-out serializes with refresh on the target User row and
revokes the entire family, even if the supplied ID is a consumed ancestor.
Bulk sign-out includes every device and the caller when targeting themselves.
Non-revoked expired rows are included in the affected-row count. Rows/hashes remain
for replay detection. A later password login is permitted; suspension is a
separate administrative operation. Revocation and audit are one transaction.

**Lock correction to ADR-0015.** The tenant mutex is **FOR NO KEY UPDATE**, not
FOR UPDATE. Administrators still serialize against one another. Recovery-outbox
inserts take FK KEY SHARE on Tenant while holding User; a FOR UPDATE mutex would
create Tenant -> User -> FK Tenant. NO KEY UPDATE permits that check.
**Evidence correction, Session 9:** sessions/audit logs have no tenant FK, so the
original refresh-based test did not exercise this FK edge. It now forces actual
recovery-outbox insertion while an administrator holds the tenant mutex. Separate
mutual-admin and concurrent-refresh tests continue to cover session revocation.

**Consequences.** Security reads serialize with tenant administration for clear
live-authorization semantics; this favors correctness over throughput. Index-only
revision `ca9642749b58` supports the exact query ordering and is reversible without
row loss. Ordinary index DDL can block writes; deployments must schedule it.
Read receipts increase audit volume; retention, ingress abuse budgets, exports,
platform access and production-scale performance work remain outstanding.

**Rejected.** Reusing self-service routes for foreign users; trusting token-time
permissions after waiting; revoking only the pre-refresh row; deleting session
history; returning raw ORM/JSON metadata; silently returning data when audit writes
fail; treating absence of timestamp columns as audit immutability; claiming a
cursor traversal is an immutable export; a tenant FOR UPDATE mutex that conflicts
with implicit foreign-key locks.

**Evidence.** `test_security_administration.py` has 44 restricted-role security
cases (including the nine-role matrix, custom auditor, cross-tenant checks,
rollback, privacy and forced lock interleavings); `test_audit_safety.py` adds 14
cursor/redaction cases. All five routes were also exercised on the local seed,
including self-revocation, immediate bearer rejection and a fresh password login.

---

## ADR-0018 — Explicit device-key delegation, finite secrets and machine evidence

**Status:** accepted · **Date:** 2026-09-29

**Context.** The API-key table/authentication stub existed, but no safe issuance,
rotation or revocation surface did. The stub assumed pre-bound tenancy, ignored
tenant status and would identify a machine UUID as a User in audit storage.
Human role grants cannot simply become durable integration scopes: that would
create an alternative route around human identity/platform controls.

**Decision.** Add six human-only, bearer-authenticated tenant management routes,
protected by existing `apikeys.read`/`apikeys.write` permissions and live service
rechecks under the administration mutex. Scope delegation is an explicit allowlist:
only `bins.telemetry.ingest` in this build. `apikeys.write` is deliberate authority
to provision that device capability, although the human cannot directly ingest.
A provisioning-account compromise can therefore mint device credentials; this is
not hidden behind a blanket claim that no human-session compromise can do so.
No identity/platform/own-user grants or human roles are inherited by a key.

Keys use a random public lookup prefix and independent 256-bit secret; only SHA-256
of the full opaque key is stored. Creation/rotation disclose plaintext once, after
commit, with no-store headers. Other endpoints expose metadata only. Default life
is 90 days, maximum 365; no new non-expiring credentials. Rotation creates a new
row, preserves expiry by default, may narrow but not expand scopes, and immediately
revokes the predecessor in the same audited transaction. A unique non-null
rotation-source index prevents forks; expired/revoked predecessors cannot rotate.
Revocation is exact-key, not family-wide. Lost response recovery requires rotating
the current replacement or revoking/recreating, never revealing a stored secret.

Keys belong to tenants, not continuing creator sessions/grants. They remain valid
when an issuing user is disabled unless explicitly revoked. Offboarding must
inventory device credentials; a later human login does not revive a revoked key.

Machine authentication requires an explicit tenant, binds RLS before prefix lookup,
checks enabled tenant, complete hash, finite expiry, revocation and allowed scopes,
and returns only machine capabilities. Tenant SHARE -> key UPDATE locks serialize
with administration's Tenant NO KEY UPDATE -> User -> key order. Authorized
in-flight business transactions may complete before revoke returns; subsequent
uses fail. The consumer commits/rolls back domain work, last-use and authentication
audit together. No public key-verification or fake telemetry endpoint is introduced.
Device endpoints and their ingress/per-key budgets remain future work.

Audit attribution gets a nullable `actor_api_key_id` FK; machine events have no
User FK, carry the real key principal and snapshot its name. The shared Actor value
object still uses `user_id` as its principal slot, so consumers must discriminate
`auth_type`. The repository maps that slot to the appropriate audit column and
refuses explicit actor/repository tenant mismatches. New key/hash/inline credential
patterns are redacted; arbitrary unlabelled secrets must never be metadata.

**Consequences.** Rotation needs coordinated immediate cutover; there is no grace
period or secret recovery. Short bounded transactions are required for revocation
latency. Unique-index creation can fail on manually provisioned duplicate rotation
sources, intentionally requiring review rather than deleting evidence. Revision
`600bc6193a23` archives machine attribution in reserved audit JSON before downgrade;
re-upgrade restores references to matching surviving same-tenant keys. This data
step preserves evidence without disabling forced RLS, and requires a controlled
migration role and deployment window. Device integration/throughput, quota,
retention and frontend work remain unverified/unimplemented.

**Evidence correction to ADR-0017.** The prior refresh test did not actually touch
a Tenant FK: Session/AuditLog use TenantKeyMixin. The forced interleaving now uses
AuthMail issuance, which does have that FK. The NO KEY UPDATE implementation is
unchanged; the executable evidence now matches its explanation.

**Rejected.** Arbitrary role-to-key scope copying; management by machine keys;
non-expiring defaults; global prefix authentication; plaintext persistence or
logging; retrying old-ID rotation as secret retrieval; revocation that erases
history; misattributing a key UUID as a User; dropping machine evidence on rollback;
claiming a planned device endpoint or production throughput was verified.

**Evidence.** 64 restricted-role security cases cover all nine tenant roles,
custom provisioning, metadata privacy, RLS, rotation/concurrency, audit/commit
rollback, collisions, expiry and transaction-bound machine use. Four unit cases
pin format, delegation and redaction; a two-tenant migration regression preserves
attribution across downgrade/re-upgrade. A local seed smoke exercises all six
management routes and the real authentication service, leaving its keys revoked.

---

## ADR-0019 — Platform control plane without implicit tenant impersonation

**Status:** accepted · **Date:** 2026-09-29

Add six human-session operations under `/platform/tenants`: list, detail, create,
metadata PATCH, suspend and activate. Registry permissions are not tenant data
permissions. Require the reserved platform scope, an actual human session, the
platform-operator flag and live `platform.tenants.read/write` grants at both API
and service boundaries. Resolve only scope-appropriate permissions even if stored
role assignments are misconfigured. No `X-Tenant-ID` override or break-glass bypass.

Provisioning atomically creates an ACTIVE tenant, nine tenant role bundles and an
INVITED administrator with an unknown random password, then queues encrypted
email verification. No credential is returned. The administrator verifies email,
then uses the existing reset flow to choose a password. Mail configuration/audit
failure rolls everything back. Platform operators cannot reset or replace an
existing tenant's administrator. Slugs and tenant identity are immutable; patches
are restricted to name/timezone/locale. Every mutation requires an operator reason.

Suspend/activate are explicit operations, not arbitrary status patches. CANCELLED
and deleted tenants cannot be revived here; the reserved platform tenant cannot
be targeted. Suspension locks Platform tenant -> platform caller -> target tenant
(NO KEY UPDATE) -> target users in UUID order, revokes session history rows without
deleting them, and invalidates pending verification/reset credentials. Machine
Tenant SHARE locks serialize with suspension. Keys themselves are not revoked:
activation permits still-valid device credentials again, but never resurrects old
human sessions. Authentication must refresh tenant eligibility after user-lock
waits, not trust identity-map snapshots. In-flight authorized work can finish
before suspension completes; no claim of cancelling every concurrent read.

Provisioning/invalidation temporarily binds target RLS for tightly bounded writes,
then restores platform scope (or rolls back the transaction on failure inside the
target scope). Both existing invitation aliases now use live tenant/caller
administration guards to serialize with suspension and grant removal.
Platform lifecycle/read evidence is recorded in the
platform audit partition, with the real operator and target registry UUID; no
cross-tenant audit reader is introduced. A separate, offline interactive bootstrap
command creates the first platform operator only, refusing all repeat/repair
attempts (including disabled or deleted existing users). No auto-seeded operator,
password CLI argument, default password or public enrollment endpoint.

Break-glass, MFA/step-up, platform-user management/recovery, cancellation/purge,
plan billing and cross-tenant audit inspection remain deferred. This is a control
plane, not production-complete privileged-access management. Deployment requires
controlled bootstrap DB access, TLS, ingress restrictions and a real mail worker.
No schema migration is needed for these operations.

---

## ADR-0020 — Session-bound password reauthentication before platform mutations

**Status:** accepted · **Date:** 2026-09-29

Add explicit password reauthentication for platform tenant mutations. This is
**not MFA**, phishing resistance or break-glass authorization. It limits what a
stolen, otherwise live bearer can do without the operator's password. TOTP/WebAuthn,
operator recovery and cross-tenant emergency access remain separate work.

`POST /platform/auth/step-up` confirms the current password for a live human
platform session with `platform.tenants.write`; `DELETE` clears that confirmation.
Store a nullable verification timestamp on the session, never a new bearer token
or client-trusted claim. The lease is five minutes, capped by session expiry,
rejects future/pre-session timestamps and is checked after live actor locks before
all four registry mutations. Registry reads do not require this confirmation.
Existing sessions and ordinary password logins start unconfirmed. Refresh creates
an unconfirmed replacement, and successful password changes clear every session's
confirmation (including the kept session). Revocation, status and grants still win.

Confirmation/clearing uses the same Platform Tenant -> User lock order as registry
administration. Reload the session after locking so an old identity-map snapshot
cannot resurrect cleared confirmation. Password failures clear current proof,
share the persistent account failure/lockout counter, and commit a DENIED audit
with the existing completed-authentication-denial transaction policy. Audit errors
roll back everything. Successful confirmation resets the failure count and commits
its proof and event before returning only method/expiry metadata. Clearing is
idempotent, audited, and does not log out the bearer.

The POST has pre-body IP and authenticated-user budgets through the existing
fail-closed limiter; DB lockout also protects direct service calls. No secret in
queries, response representations, audit or logs. No feature flag disables the
write gate. Denial is 403 with a bounded remediation hint, not a tenant-context
switch. A request already authorized may finish after the window expires; bounded
transactions and timeouts remain deployment requirements.

The nullable schema addition gives no existing session a grant; downgrade drops
only ephemeral confirmation state, leaving its audit evidence intact. **Rolling
back application code also removes the gate**: isolate the platform control plane
during rollback, do not describe an older application as enforcing this policy.

---

## ADR-0021 — Opt-in TOTP for platform actions, with no password-only downgrade

**Status:** accepted · **Date:** 2026-09-29

Add opt-in platform action MFA, not mandatory login MFA or break-glass. Unenrolled
operators keep ADR-0020's password gate. Once enrolled, registry mutations require
recent password-plus-TOTP (or single-use recovery-code) confirmation tied to the
current factor UUID. Ordinary login/registry reads remain password-session based.
No feature flag, password reset or lost-device endpoint removes an active factor.

TOTP uses the cryptography library's RFC 6238 implementation: 160-bit CSPRNG seed,
SHA-1, six digits, 30 seconds, +/- one step. Under the existing platform/User mutex,
accept only counters newer than the last consumed counter, across all sessions.
A separate Fernet key encrypts seeds with bound user/tenant/factor identity. No raw
seed persists; malformed ciphertext/key configuration fails closed. This is
phishable shared-secret MFA, not hardware attestation or phishing resistance.

Enrollment/replacement starts with a fresh password. Replacement additionally
requires the current strong session confirmation. A pending seed is disclosed once,
expires after ten minutes and is tied to its initiating live session. Confirmation
requires password and a code from that seed, then atomically replaces the active
factor, consumes its counter, cancels pending state, clears all session proofs and
issues ten random 192-bit recovery codes, stored only as hashes. Confirmation does
not itself authorize a registry mutation; use a subsequent code/recovery code.
The old factor remains usable until replacement commits. Refresh cannot transfer
pending enrollment; password changes/reset clear pending state and proofs but retain
active MFA. No disable API or email/password-only factor recovery is introduced.

A recovery code is a one-time second factor, always paired with the password; it
can establish the short session proof used to replace a lost authenticator.
Recovery-code regeneration needs fresh password plus current strong proof, replaces
all hashes atomically and discloses new codes once. Lost issuance responses are not
retrievable; use the enrolled authenticator/remaining recovery codes to rotate.

Enrollment state/status/cancel and recovery-code rotation are human platform-writer
operations; credential POSTs share fail-closed IP/account budgets and durable user
lockout. Invalid credentials clear proof and commit DENIED audit with the existing
auth-denial transaction policy. Audit failures roll back mutations and consumption.
Both representations and logging redact seeds, provisioning URIs and recovery codes.
No authenticator secret is sent to an external QR/image service.

Schema downgrade must not silently remove second-factor enforcement: refuse it
while any MFA seed, pending enrollment or factor/recovery state remains. Old app
versions do not enforce MFA even with new columns present; block platform mutations
during mixed-version rollout/rollback. Key backup/rotation, loss of all factors,
mandatory enrollment rollout and independently verified operator recovery remain
controlled operational work, never an automatic password-only repair shortcut.

---

## ADR-0022 — MFA-protected platform operator lifecycle, without factor recovery bypass

**Status:** accepted · **Date:** 2026-09-29

Add dedicated PLATFORM-scoped `platform.operators.read/write` permissions, granted
only to the shared SUPER_ADMIN baseline. Six own-realm operations list/detail,
invite, suspend, reactivate and require MFA. No customer-user access, arbitrary
role grants, deletion, unlock, email edit, factor disable or all-factor-loss recovery.
Every mutation requires live permissions and recent current-factor password+MFA
confirmation, even for legacy operators whose registry policy remains opt-in.

HTTP invitations create a fixed SUPER_ADMIN operator in platform scope, INVITED,
with an unshared random password and transactional verification delivery. The caller
must hold the entire reviewed platform grant set; the shared role must match it.
After mailbox verification the invitee independently resets the password, signs in,
and enrolls MFA. No usable credential is disclosed to the inviter. Duplicate emails
conflict, including reserved soft-deleted identities. First-operator offline bootstrap
continues to refuse any existing operator; it is not an account repair tool.

Persist `users.platform_mfa_required` (default false for compatibility); HTTP-invited
operators receive true. An explicit, audited endpoint may set it true for existing
operators but cannot unset it. Platform registry mutation proof must include the
current MFA factor when the flag is true, including before enrollment. Enrollment,
login, self-service password recovery and reads remain accessible without a strong
proof. This is action policy, not login-wide or mandatory global MFA. Own MFA status
reports the policy so clients can distinguish required enrollment from opt-in.

Lifecycle mutations take the platform realm NO KEY UPDATE mutex, then caller User,
then target User and remaining platform Users ordered by ID under the same mutex. Suspension must leave at least
one other active, nondeleted, nonlocked operator with permanent grants for lifecycle
write and step-up, and a decryptable, bound enrolled factor. This is a conservative
administrative safety invariant, not proof that a human/device/key backup is available.
Expiry/lockout/external database edits can still reduce availability; dual-controlled
operational recovery remains separate. Concurrent suspensions must serialize and
re-resolve caller grants/status before counting survivors.

Suspension invalidates all target sessions/proofs, pending enrollment and reset/
verification codes, but retains active MFA, recovery hashes and mandatory-MFA policy.
It can also withdraw a pending invitation. Reactivation of SUSPENDED users returns
ACTIVE only if email was verified, otherwise INVITED; it never restores sessions,
proofs or codes, unlocks temporary lockout, or removes MFA. DISABLED/deleted/LOCKED
states cannot be repaired here. Requiring MFA clears all target proofs immediately.

All reads/writes are audited within the response transaction; failed audit/commit
rolls back all state and delivery. Closed schemas return only bounded operator
metadata; never hashes, seed, codes, pending credentials or bearer material. Every
response, including errors, is no-store. Read pagination is bounded. Mutations have
pre-body IP and authenticated-account budgets; reasons are mandatory and privacy-filtered.

The permission/flag migration must not silently remove mandatory action MFA:
downgrade refuses while any required flag remains. New grants are removed under RLS
on safe downgrade; audit evidence is retained. Mixed-version rollout/rollback must
block platform writes, since old applications ignore both lifecycle and MFA policy.
No claim of mandatory global enrollment or independently verified emergency recovery.


ADR-0022 rollback clarification: Alembic uses per-revision transactions. If a lower
MFA guard refuses a multi-revision downgrade, prior completed revisions stay down.
Inspect the actual head and re-upgrade before serving the current application.

---

## ADR-0023 — Phase 2 deny-by-default startup gate and explicit phase closure

**Status:** accepted · **Date:** 2026-09-29

Phase 2's written exit gate requires a startup self-check, not only test-time route
classification. Add a production API-layer policy inventory executed during lifespan
before database/cache/counter resources initialize. Inspect effective mounted routes,
including hidden routes, nested include prefixes and include-time dependencies. Reject
unknown permissions, duplicate method/path registrations (including parameter-name
aliases, not arbitrary regex-overlap analysis), unclassified routes,
permission declarations lacking real authentication, and unsupported ASGI mounts or
WebSockets instead of silently excluding them. Route registration after startup is not
supported; new transports need a reviewed policy before introduction.

Public exceptions are the six credential-exchange/recovery operations plus the existing
probe/docs surfaces, with explicit reasons. Self-service exceptions are the eight
caller-scoped auth/session/grant operations; each still needs real actor authentication.
No other route may replace permission authorization with merely having a bearer.
The configured API prefix is applied to exceptions. HEAD inherited from a GET route
uses that GET policy; standalone HEAD/OPTIONS routes require classification. CORS
middleware preflight is not an application data endpoint.

Keep marker-backed permission declarations and real authentication dependency identity
checks, rather than trusting endpoint attributes or OpenAPI visibility. Unit adversarial
startup tests and an all-ten-baseline-roles × mounted-protected-operations dependency
matrix supplement the existing real PostgreSQL HTTP/service/RLS tests. Dependency
matrix success means the permission gate allows evaluation to continue, not that MFA,
resource state or service-level tenant rules are bypassed.

Close Phase 2 against the build/test/gate requirements in docs/phases.md once all
pass, with a traceable gate report and PR. Do not expand that gate indefinitely with
optional privileged-control-plane features. Cross-tenant break-glass, all-factor-loss
recovery, operator role editing and platform audit HTTP browsing remain explicitly
unimplemented and unavailable. Global/login-wide MFA, external SMTP/real Redis/load
verification, frontend and deferred Phase 1 container artifacts are not claimed as
part of this completion. They remain visible follow-up/deployment risks. Phase 3
begins with core domain workflows, not by silently opening privileged bypasses.


ADR-0023 contract clarification: publish bearer authentication and required-permission
metadata from that same inspected surface. Publish the existing standard error
envelope, including 400 request validation and 422 business rules, instead of
FastAPI's unused default HTTPValidationError shape. Runtime authentication and error
handling remain unchanged; the contract now matches their tested behavior.
