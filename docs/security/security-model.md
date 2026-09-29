# EcoMind-AI — Security Model

**Status:** Phase 0 design baseline with Phase 2 implementation notes · **Baseline guidance:** OWASP ASVS L2 / Top 10
**Related:** `rbac.md`, `../architecture/decisions.md` (ADR-0003, ADR-0004), `../api/rest-api.md` §1.2, `../../.env.example`

---

## Implementation status (2026-09-29)

**Phase 2 API/security gate complete.** See `../reports/phase-2-gate.md` for exact
scope, full-suite evidence and deployment limitations. Role/route matrix and
OpenAPI checks now supplement these service/DB integration suites.

The sections below describe the target security model; planned tests and
controls are not evidence of implementation. The currently verified auth suite
is `backend/tests/security/test_auth_lifecycle.py` (36 tests against PostgreSQL
with a non-superuser runtime role). See ADR-0014 for refresh-token routing,
serialization and transaction decisions.

Implemented: tenant-bound login/reset and bearer queries; exact session/user/
tenant claim matching; inactive-account rejection; persisted lockout counters;
retained refresh history and family revocation on reuse; concurrent-refresh
safety; session ownership; password change and single-use reset confirmation;
permission-checked invitations without issuing sessions. Audit change details
are stored in the existing `metadata` JSON column.

Recovery delivery and public email verification now use a forced-RLS encrypted
outbox, private local mailbox or verified STARTTLS, and one-use expiring codes.
IP budgets precede body parsing; HMAC-keyed account/token budgets precede lookup.
Security counters fail closed (503), unlike the optional cache; budget exhaustion
returns 429 with Retry-After. Production requires shared Redis 7+; development
memory counters are bounded and labelled simulated. See ADR-0016 and the
[recovery runbook](../api/account-recovery.md). Forty-two focused tests in
`test_auth_delivery.py`, `test_auth_rate_limits.py`, `test_auth_mail.py`, and
`test_rate_limits.py` cover this slice. Local delivery is end-to-end verified;
external SMTP and a real Redis server remain unverified here.

Not implemented: refresh cookies/origin checks, session/outbox-history retention,
JWT issuer/audience/not-before claims, and general API/edge rate limiting. Current
tokens are returned as JSON and refresh is submitted in JSON. Recovery request
bodies/status are neutral for eligible/ineligible accounts; this is not a claim
of constant-time account lookup. Auth responses prohibit caching.
Tenant administration is now implemented and covered by 57 additional tests in
`test_identity_admin.py`, including all nine tenant roles against all new routes.
Writes serialize on the tenant and recheck grants after locking; last-admin
recovery permissions and role privilege ceilings are enforced (ADR-0015).
The dev seed is CLI-only, environment-restricted and never restores modified
access. The production app must connect without superuser/BYPASSRLS privileges.

Tenant audit browsing and administrative sessions are implemented (ADR-0017):
explicit DTOs, audited successful reads, signed bounded cursors, family/bulk
revocation, privilege ceilings and live authorization rechecks. The new suite has
44 real-RLS security tests plus 14 cursor/redaction unit cases. Audit repository
mutation paths are explicitly blocked; the restricted-role suite also rejects
raw UPDATE/DELETE. Production must grant audit SELECT/INSERT only to a non-owner
runtime role. Redaction is bounded defense in depth, not a detector for arbitrary
unlabelled secrets. The tenant mutex uses NO KEY UPDATE to avoid foreign-key lock
inversion with User-locked refresh transactions. Platform audit, exports/retention and frontend remain planned; see `../api/security-administration.md`.

API-key lifecycle is now implemented (ADR-0018): six human-authenticated,
permission-declared management operations, finite expiry, hashed storage,
one-time committed disclosure, non-expanding rotation and explicit revocation.
The device scope allowlist excludes human/platform administration. Authentication
is tenant-bound under RLS and rejects inactive tenants/keys and unsafe scopes;
it returns no JWT or human grants. Machine audit attribution uses a separate
key FK rather than pretending the key UUID is a User. Migration rollback archives
that attribution before removing its column. There are 64 dedicated lifecycle
security cases, 4 unit cases and a data-bearing migration round-trip regression.
Machine HTTP ingestion, per-key HTTP budgets and production throughput are not
implemented/verified here. See `../api/api-keys.md`.

Correction to the earlier lock evidence: sessions/audit logs have no Tenant FK;
the forced FK regression now uses the recovery outbox, which does. The NO KEY
UPDATE mutex remains unchanged. Separate tests cover refresh versus revocation.

Platform tenant registry administration is implemented separately (ADR-0019), with
six guarded routes and offline, non-repairing first-operator bootstrap. Registry
provisioning, user/role setup, encrypted invitation delivery and audit are atomic.
Suspension takes the tenant/user mutexes, invalidates human sessions/recovery codes
and gates machine use by tenant state; activation does not revive human sessions.
Login/recovery now reload tenant eligibility after user-lock waits. Invitation
aliases now use live administration guards. Scope-filtered permission resolution
also rejects misconfigured cross-scope role grants. See `../api/platform-tenants.md`.
There is no break-glass bypass, tenant impersonation or platform audit API yet.
Opt-in platform-action TOTP is implemented; login-wide MFA is not.

Platform tenant mutations now also require explicit session-bound password
confirmation (ADR-0020), with five-minute expiry, live grant checks, IP/account
budgets, shared lockout and transactional success/denial audits. Confirmation is not
inherited on refresh, and password changes clear it on kept sessions as well.
`1eb8da7c2793` adds a nullable timestamp; no existing session gains authority.
See `../api/platform-step-up.md`. Password-only confirmation remains the unenrolled
flow. ADR-0021 adds opt-in TOTP/recovery verification for enrolled platform writers;
see `../api/platform-mfa.md`. ADR-0022 adds MFA-protected operator lifecycle, required
policy for HTTP invitees, and one-way policy enforcement for legacy operators.
Break-glass and all-factor-loss recovery remain deferred; see `../api/platform-operators.md`.

## 1. Threat model summary

| # | Threat | Control | Verified by |
|---|---|---|---|
| T1 | Cross-tenant data access (IDOR/BOLA) | Server-derived tenant context; `TenantScopedRepository`; PostgreSQL RLS; 404-on-foreign; security audit events | `backend/tests/db/test_rls_coverage.py` (RLS enforcement, proven per tenant) |
| T2 | Privilege escalation | Permission-string checks; `roles.assign.elevate` gating; permission-set provenance; no client-supplied scopes | `tests/security/test_privilege_escalation.py` |
| T3 | Credential theft / session hijack | Argon2id; 15-min access tokens; rotating refresh tokens with reuse detection + family revocation; session revocation; lockout | `backend/tests/security/test_auth_lifecycle.py` |
| T4 | SQL injection | SQLAlchemy parameterised queries only; no string-built SQL; allow-listed sort columns | `tests/security/test_injection.py` |
| T5 | Mass assignment | `extra="forbid"` on all input schemas; explicit field allow-lists in services | `tests/api/test_mass_assignment.py` |
| T6 | Malicious file upload | Magic-byte sniffing, size/dimension limits, decode test, server-generated storage names, path-traversal guard, quarantine state | `tests/security/test_file_upload.py` |
| T7 | XSS | React escaping; no `dangerouslySetInnerHTML`; strict response content types; CSP header | Frontend lint rule + header tests |
| T8 | CSRF | Bearer tokens in memory for API calls; refresh token in `HttpOnly; Secure; SameSite=Strict` cookie with origin check on the refresh endpoint | `tests/security/test_csrf_source_check.py` |
| T9 | Rate-limit abuse / DoS | Per-identity and per-IP limits, stricter on auth/assistant/export/upload; request body size caps; bounded solver and query limits | `tests/security/test_rate_limits.py` |
| T10 | Prompt injection / tool abuse | Untrusted content confined to data slots; schema-validated tool arguments; tool permission checks; read-only tool set; output schema validation | `tests/ai/test_prompt_injection.py` |
| T11 | Secret leakage | Config from environment only; `.env` git-ignored; log redaction processor; errors never echo config; no secrets in audit metadata | `tests/test_no_secret_leakage.py` + `scripts/check_secrets.py` |
| T12 | Data exfiltration via export | `data.export`/`analytics.export` permissions, rate limits, export audit events, response size caps | `tests/security/test_export_controls.py` |
| T13 | Illegal state transitions | Explicit transition tables in services; DB CHECKs; 409 on violation | `tests/services/test_state_machines.py` |
| T14 | Tampered telemetry | API-key device auth; tenant-bound device ids; per-reading range validation and rejection accounting; dedup key | `tests/telemetry/test_ingestion_validation.py` |
| T15 | Unsafe AI recommendations | Evidence required; no destructive tool; explicit user confirmation; audit of execution | `tests/ai/test_recommendation_integrity.py` |

Explicit non-goals of this build (disclosed): DDoS mitigation at the edge,
WAF management, hardware security modules, and third-party penetration testing.

---

## 2. Authentication

* **Password hashing:** Argon2id via `argon2-cffi`, parameters from configuration
  (`ARGON2_TIME_COST`, `ARGON2_MEMORY_COST_KIB`, `ARGON2_PARALLELISM`). Password
  policy: minimum length 12, blocklist of common passwords, no composition rules
  that encourage predictable patterns. Hash format is self-describing, so
  parameters can be increased later and hashes upgraded on next login.
* **Access tokens:** JWT HS256, 15-minute lifetime, claims `sub`, `sid`, `tid`,
  `iat`, `nbf`, `exp`, `jti`, `iss`, `aud`. A `sid` referencing a revoked or
  rotated session is rejected even if the JWT is otherwise valid — signature
  validity is necessary, not sufficient.
* **Refresh tokens (implemented):** `rt1.<tenant-uuid>.<384-bit-random-secret>`,
  opaque to clients. The UUID is only an untrusted routing hint; the complete
  SHA-256 hash must match within that tenant under RLS. Rotation inserts a new
  row and retains the consumed hash, linked by `family_id` and predecessor id.
  Reuse revokes the entire family and records an audit event. A lost-response
  retry also triggers this fail-closed behavior; clients must serialize refresh.
  Legacy unprefixed tokens are rejected and require sign-in.
* **Login protections:** constant-time comparison, generic error message (no
  user enumeration), progressive lockout (`failed_login_attempts`, `locked_until`),
  `last_login_at`/`last_login_ip` recorded, and an audit entry per attempt
  including failures.
* **Account states:** `INVITED`, `ACTIVE`, `SUSPENDED`, `LOCKED`, `DISABLED`.
  Only `ACTIVE` authenticates; suspension revokes all sessions immediately.
* **Email verification & password reset:** token-based architecture with
  single-use expiring tokens; providers behind the notification adapter, so the
  flows are exercisable in development with the console adapter.
* **MFA:** opt-in platform-action TOTP/recovery is implemented (ADR-0021), using
  independently encrypted seeds, single-use recovery hashes and factor-bound session
  proofs. Mandatory enrollment, login-wide MFA and WebAuthn remain planned; ordinary
  tenant-user login is not second-factor protected.
* **API keys (devices/integrations):** `prefix.secret` format, only the hash
  stored, scoped, expiring, revocable, and usage-tracked. Device keys are
  distinct from user credentials and are granted no human permissions.

---

## 3. Authorization

Detail in `rbac.md`. Security-relevant summary:

* Deny by default; the production startup check inspects actual mounted dependencies,
  including hidden routes. Known permission declarations plus live actor authentication
  are required, except explicitly reasoned public and authenticated self-service
  operations (ADR-0023). No arbitrary bearer-only route is accepted.
* Permission checks are enforced in the route dependency **and** in sensitive
  service methods (defence against internal call paths bypassing the route).
* `SUPER_ADMIN` holds only `scope=PLATFORM` permissions that cannot be granted
  to tenant roles. Tenant data requires an explicit, time-boxed, fully audited
  break-glass activation.
* Cross-tenant probes return `404` (never `403`) and are recorded as security
  events, so enumeration yields no signal and repeated probing is visible.

---

## 4. Tenant isolation (three layers — ADR-0003)

1. **Query layer:** all tenant-owned access flows through
   `TenantScopedRepository`, which injects the tenant predicate from the request
   context. No "unscoped" helper exists in the codebase; a repository method
   that needs cross-tenant access must be named `*_platform` and is only
   reachable with a platform permission.
2. **Database layer:** RLS enabled and forced on every tenant table, with both
   `USING` and `WITH CHECK` clauses:

   ```sql
   USING      (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
   WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
   ```

   `USING` filters rows that are read; `WITH CHECK` filters rows that are written.
   Omitting either opens a real hole — without `WITH CHECK` a tenant can *insert* a
   row owned by another tenant, and the forged row is invisible to the writer, so
   nothing looks wrong until the other tenant's data is reconciled. `NULLIF` folds
   an unset or blank setting to `NULL`, and a comparison against `NULL` is never
   true, so an unconfigured connection sees **zero rows rather than all rows**: the
   policy fails closed. The session variable is transaction-local
   (`set_config(..., true)`), so it cannot survive a commit and leak into the next
   request that reuses the pooled connection.

   The DDL is generated from one place (`app/db/rls.py`), never hand-written per
   migration, and `tables_without_rls()` asks the live database what is actually
   true at deploy time rather than trusting that migrations ran.

### Deployment requirement: the application must not connect as a superuser

**Measured on PostgreSQL 16 in this repository's own test cluster: a superuser
bypasses row-level security even with `FORCE ROW LEVEL SECURITY` set.** The same is
true of any role holding `BYPASSRLS`.

| Connecting as | `SELECT` on a forced-RLS table with two tenants' rows |
|---|---|
| `postgres` (superuser) | returns **both** tenants' rows |
| an ordinary role, tenant A bound | returns tenant A's rows only |

Two consequences, both mandatory:

* **Production:** the application's database role must be an ordinary role — not a
  superuser, and without `BYPASSRLS`. A deployment that gets this wrong silently
  disables the entire third isolation layer while every test and policy still looks
  correct. This is checked by `app.db.rls.tables_without_rls()` and must be part of
  the deployment checklist.
* **Testing:** the suite connects as `postgres` to create and migrate the database,
  so a policy test run on that connection can only pass when the policy is *broken*.
  `tests/conftest.py` therefore provisions a dedicated non-superuser login role
  (`ecomind_rls_test`) and binds it into the engine URL. Binding it into the URL
  rather than issuing `SET ROLE` matters: a `SET ROLE` is session state, and
  SQLAlchemy returns the connection to the pool on the first `rollback()`, so the
  superuser would be silently restored part-way through a test.

   `FORCE ROW LEVEL SECURITY` is still required as well, because the table *owner*
   bypasses RLS without it and the migration role typically owns the tables it
   creates.
3. **Test layer:** an adversarial suite that authenticates as tenant A and
   attempts read/update/delete/list/export, file access, telemetry access and
   analytics queries against tenant B's identifiers, asserting 404/empty and the
   presence of a security audit event.

The identity of the *model* in the assistant is bound to the same context; a
cross-tenant tool request is not expressible in the tool schema.

---

## 5. Input validation and output safety

* Pydantic v2 models with `extra="forbid"` for every request body; query
  parameters typed explicitly; a dedicated allow-list for sort/filter fields.
* `NUMERIC` bounds, coordinate ranges, percentage ranges, enum membership and
  cross-field rules (e.g. `end > start`, composition sums) validated before any
  write, and independently enforced by database `CHECK` constraints where a
  business rule must be unbreakable (BR-02, BR-08).
* Responses are always Pydantic schemas. ORM entities are never serialised
  directly (section 8), which structurally prevents leaking `password_hash`,
  internal notes, or tenant ids the client should not see.
* Error responses use the fixed envelope and never include stack traces, SQL,
  file paths, dependency versions or internal hostnames.
* Unicode normalisation and control-character stripping on all free-text fields;
  length caps everywhere; `null` bytes rejected.

---

## 6. File upload security (section 38)

1. Size limit enforced while streaming (`STORAGE_MAX_UPLOAD_MB`), not after
   buffering the whole body.
2. **Content-type detection by magic bytes** (`pillow`/`python-magic`-style
   sniffing) with the client-supplied MIME treated as untrusted metadata only
   and recorded for audit.
3. Extension is checked against the detected type; mismatch → `415`.
4. Images must decode successfully and be within allowed dimensions; EXIF is
   stripped on re-encode, and EXIF-embedded scripts/URLs are never surfaced.
5. CSV imports are parsed with a strict dialect, row limits, and per-cell
   validation; formula-injection prefixes (`=`, `+`, `-`, `@`) are neutralised
   on export.
6. Storage names are server-generated UUIDs; the original filename is stored as
   data for display only. The storage adapter refuses any resolved path outside
   the configured root (path-traversal defence), and a `CHECK` forbids path
   separators in `stored_filename`.
7. Uploaded files start in `scan_status=PENDING`; the download endpoint refuses
   `REJECTED` files. (Real antivirus integration is an adapter stub with a
   documented interface — stated as a limitation, not faked.)
8. Files are tenant-scoped and ownership-checked on every read; a foreign file
   id returns `404`.

---

## 7. Transport, headers, browser protections

* TLS terminated at the reverse proxy in production; HSTS enabled by
  configuration (`HSTS_ENABLED`).
* Security headers on API and static responses: `X-Content-Type-Options:
  nosniff`, `X-Frame-Options: DENY` (or a permissive policy only where an
  embedding preview requires it, which is why it is configurable),
  `Referrer-Policy: strict-origin-when-cross-origin`, `Permissions-Policy`
  minimal, and a CSP appropriate to the SPA build.
* CORS: explicit origin allow-list from configuration; wildcard is rejected when
  credentials are enabled; preflight cached.
* Cookies: `HttpOnly`, `Secure`, `SameSite=Strict` for the refresh token;
  `__Host-` prefix; the refresh endpoint additionally validates `Origin`.
* Compression: no BREACH-sensitive secrets in compressed responses; CSRF tokens
  are not placed in compressed reflectable bodies.

---

## 8. Logging, audit and privacy

* Structured logs with a redaction processor that strips `password`, `token`,
  `secret`, `authorization`, `api_key`, `refresh_token` and configured PII
  patterns before emission.
* Audit log is append-only, access-controlled (`audit.read`), itself audited on
  read, and stores a **snapshot** actor label so history remains interpretable
  after a user is renamed or deleted.
* Audit metadata is a bounded, validated dict; no request bodies, no secrets,
  no file contents.
* Personal data is minimised: telephone numbers, emails and names are the only
  PII fields held; retention is configurable per data class
  (`data_retention_policies`) and enforced by a sweep job that archives before
  deleting.
* Right-to-erasure workflow: user deletion is a soft delete plus an
  anonymisation routine for audit/history references, documented in
  `docs/deployment/operations.md`.

---

## 9. Dependency and supply-chain hygiene

* Dependencies are pinned to reviewed ranges and frozen into
  `backend/requirements/lock.txt` for reproducible builds.
* `scripts/check_secrets.py` scans the tree for credential-shaped strings and
  runs in CI.
* `ruff` (lint + security-relevant rules) and `mypy` run in CI; a failing gate
  blocks the build.
* Deliberate framework choices with a security rationale: **PyJWT** over
  `python-jose` (maintained, no outstanding CVEs), **argon2-cffi** directly over
  `passlib` (passlib is unmaintained and incompatible with current bcrypt
  releases).

---

## 10. Security test suite (executable evidence)

| Test file | Asserts |
|---|---|
| `test_tenant_isolation.py` | 15+ adversarial cross-tenant attacks across every tenant-owned resource class |
| `test_authorization_matrix.py` | Every role × every endpoint matches the documented matrix |
| `test_authentication.py` | Tampered/expired/wrong-audience tokens rejected; revoked session rejected |
| `test_token_lifecycle.py` | Refresh rotation, reuse detection, family revocation, logout-all |
| `test_injection.py` | SQL/NoSQL/ORM payloads in every string field and filter/sort parameter |
| `test_mass_assignment.py` | Attempts to set `tenant_id`, `id`, `password_hash`, `status`, `role` are ignored/rejected |
| `test_file_upload.py` | Polyglot file, MIME/extension mismatch, oversized, zero-byte, path-traversal filename, non-image masquerading as image |
| `test_rate_limits.py` | Login, assistant, export, upload limits enforced with `Retry-After` |
| `test_security_headers.py` | Headers present and correct; CORS rejects disallowed origins |
| `test_state_machines.py` | Illegal transitions produce 409 and never partial writes |
| `test_decimal_precision.py` | Weights/volumes/carbon round-trip exactly through API and DB |
| `test_no_secret_leakage.py` | Error responses and logs contain no secret-shaped values |
