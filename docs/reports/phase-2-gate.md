# Phase 2 gate report — authentication, tenancy, RBAC and audit

**Decision: COMPLETE against the Phase 2 build/test/gate in `docs/phases.md`.**
**Date:** 2026-09-29. **Branch:** `arena/01a0eaec-major-project`.
**Baseline:** `d34fda2`; this report covers the accumulated Phase 2 work after that
foundation, not just the final startup-policy change. Phase 3 is next, not started.

Completion is a development/API security gate, **not production certification**.
The deployment dependencies and unimplemented privileged features below are explicit
limitations, not quietly enabled bypasses. ADRs 0014–0023 record the decisions.

## Exit-criteria evidence

| Phase 2 requirement | Implementation and executable evidence | Result |
|---|---|---|
| Identity schema, migrations and baseline roles | `models/identity.py`, `scripts/seed_catalogue.py`; migration/RLS suites and markdown role-matrix assertions | PASS |
| Argon2id, login/logout, refresh rotation/reuse, lockout | `services/auth.py`, authorization tokens, auth routes; `security/test_auth_lifecycle.py` | PASS |
| Password reset / email verification via provider adapter | Encrypted transactional outbox, local MIME/STARTTLS adapters and worker; `test_auth_delivery.py` runs local request→dispatch→confirmation | PASS (external SMTP not verified) |
| Session and API-key lifecycle | Own/admin revocation, metadata-only browsing, one-time key issuance/rotation/revocation; lifecycle integration suites | PASS (machine authentication is service-only) |
| Tenant context, scoped repositories, non-owner RLS | Signed claim/session/user alignment; `repositories/base.py`, forced policies; real restricted-role DB and adversarial HTTP/service tests | PASS |
| Backend route + service authorization, startup self-check | `api/route_policy.py` inspects actual mounted/hidden/included routes before resource initialization; service live-state checks remain independent | PASS |
| All baseline roles against the declared API gates | Markdown matrix plus **460 cases: 10 roles × 46 permission-protected operations**. Actual dependency callables run through FastAPI; service success is not inferred from gate success | PASS |
| Anonymous denial and reviewed exceptions | **54 authenticated operations** reject anonymous requests; six public credential/recovery operations and eight authenticated self-service exceptions have written reasons | PASS |
| Audit service/context and durable evidence | Append-only repository, transaction-bound mutation/read events, request correlation, privacy filters, signed-cursor tenant audit API and rollback tests | PASS |
| Rates, CORS, security headers, validation/redaction | Auth IP/account budgets, persistent lockout, fail-closed counters, closed schemas, injection/mass-assignment/privacy/header suites | PASS |
| Published API contract | **60 versioned operations**, bearer security and required-permission metadata, standard error envelope (400 validation; 422 domain rules), closed request models | PASS |

The route-permission matrix substitutes a final sentinel handler and supplied actor
only to test the declared gates. The separate restricted-role HTTP suites execute
real login, SQL transactions, live grants, tenant isolation, MFA and business-state
checks. Neither test category is represented as a substitute for the other.

## Delivered beyond the minimum auth foundation

* Tenant user/role administration and serialized last-administrator protection.
* Tenant audit browsing and refresh-safe administrator session controls.
* API-key metadata/issuance/rotation/revocation, finite expiry, independent machine
  attribution and tenant-bound machine authentication service (not HTTP ingestion).
* Platform registry provisioning/suspension/activation and offline first-operator
  bootstrap, with no implicit customer-data access.
* Five-minute session confirmation, optional/required platform-action TOTP and
  one-time recovery codes; encrypted identity-bound seeds and replay counters.
* MFA-protected operator invitation/suspension/reactivation and one-way required-MFA
  policy, with serialized last-permanent-MFA-manager safeguards.
* Startup refusal for unclassified/unknown/unauthenticated permission gates,
  duplicated parameter-equivalent routes and unsupported transports. Hidden routes
  and nested include-time dependencies are covered; runtime route registration
  after startup is unsupported.

## Files and API surface

The PR is the exact created/modified file manifest. Main areas:

| Area | Files/groups |
|---|---|
| Authentication and tenancy | `api/deps.py`, `api/v1/auth.py`, `authorization/{tokens,resolution}.py`, `repositories/identity.py`, `services/{auth,identity}.py` |
| Recovery, counters and privacy | `api/rate_limits.py`, `core/{rate_limits,audit_cursor,audit_privacy,logging,middleware}.py`, `services/auth_delivery.py`, `integrations/auth_mail.py`, `workers/auth_mail.py` |
| Administrative APIs | `api/v1/{users,roles,tenants,security_administration,api_keys,platform_tenants,platform_step_up,platform_mfa,platform_operators}.py` and closed schemas/services |
| Operator assurance | `authorization/totp.py`, `services/platform_access.py`, `scripts/bootstrap_operator.py`, encrypted MFA/policy/session fields |
| Final closure | `api/route_policy.py`, `api/schemas/errors.py`, `main.py`, startup-policy, mounted-permission-matrix, SQL-injection and OpenAPI contract tests |
| Persistence | Six incremental revisions after `43f430493613`; frozen original-revision RLS table list fixes clean installs without changing its original DDL |
| Developer/CI docs | Bootstrap/Makefile/config, API runbooks, ADRs, phase state, requirements traceability and this report |

The 60 operations comprise 14 auth, 16 user/role/permission/current-tenant,
5 audit/session administration, 6 API-key management, 6 platform registry,
2 confirmation, 5 MFA and 6 operator lifecycle operations. No break-glass route
or machine HTTP ingestion endpoint is mounted.

## Database and rollback

Head **`e1c3617bfb4c`**, with revisions:

1. `0a396e61910c`: encrypted auth-mail outbox and verification credentials.
2. `ca9642749b58`: audit cursor and session browsing indexes.
3. `600bc6193a23`: API-key rotation integrity and separate machine attribution.
4. `1eb8da7c2793`: per-session password confirmation.
5. `c4195297efc7`: bound MFA enrollment/proofs and one-time recovery state.
6. `e1c3617bfb4c`: operator permissions and required action-MFA policy.

**85 tables, 74 forced tenant policies, 101 permission definitions, 322 baseline
grants over 10 roles (nine tenant roles plus SUPER_ADMIN).** Other domain tables
are schema groundwork, not implemented domain workflows.

Clean-database round trips, drift and data-bearing downgrade guards are tested.
Downgrades refuse to erase active/pending MFA or required policy. Never clear these
fields to force rollback. Alembic commits per revision; a lower guard can stop a
multi-revision downgrade after an earlier one completes. Inspect the actual head,
restore compatible schema, and keep writes blocked during mixed-version rollout.
Older code does not enforce newer password/MFA/policy gates merely because columns
remain. See the platform runbooks for the precise custody/rollback rules.

## Final verification

* `make gate`: **1,638 passed, 6 skipped**, no failures (357.77 s); lint/format, mypy, secret
  scan and migration drift pass. Full local log: `.runtime/phase2-final-gate.log`
  (ignored runtime evidence, not committed data).
* Six skips are explicit architecture-layer exclusions for composition/simulation
  entry points, **not skipped security/isolation tests**. The environment warning
  is `XDG_RUNTIME_DIR` fallback; cosmetic pgserver atexit logging may follow success.
* Final scan covers **183 tracked files**, both actual index blobs and working copies,
  including the new files rather than only the previously tracked subset;
  `git diff --check` is clean. No local env, dev account, mailbox or database is in Git.
* Production-like limited DB roles are used by the integration tests. Local mail
  and memory/fakeredis adapters are labelled; external dependencies are not inferred.
* GitHub CI is reported separately by the PR checks. Local verification is not
  described as a successful hosted run before GitHub reports one.

## Limitations, risks and follow-up owners

| Not completed / not claimed | Boundary and follow-up |
|---|---|
| External SMTP and real shared Redis verification | Deployment gate: provision secrets, worker schedule, monitoring and shared counters; run actual integration/failure tests before production |
| Production DB/app role and ingress configuration | Use non-owner/non-superuser/non-BYPASSRLS app roles; restrict metrics, require TLS, bound request/transaction/lock times; dev bootstrap is not production provisioning |
| MFA key custody, global/login-wide MFA, physical authenticator interoperability | Preserve encrypted-seed key backups; actual hardware/app and recovery drills are not replaced by RFC vectors |
| Break-glass, all-factor-loss recovery, operator role editor, platform audit HTTP viewer | Remain unimplemented/unmounted. Need reviewed governance/consent, narrow authorization and independent recovery; no generic tenant selector or bootstrap repair shortcut |
| Mail/outbox and refresh evidence retention, production load | Operational/Phase 12 hardening; do not delete history needed for replay detection or recovery evidence |
| Frontend, cookie transport, domain workflows | Later phases; current transport is bearer/JSON, not a cookie/CSRF implementation |
| Containers/proxy artifacts deferred from Phase 1, PostGIS unavailable | Still visible prerequisites, not silently declared completed by this Phase 2 gate |

## Next phase prerequisites

Start Phase 3 with zones/service areas/waste taxonomy/bins and explicit contracts,
permission declarations, tenant isolation, validation and reproducible seed data.
Keep this complete Phase 2 gate green. Domain APIs do not inherit authority merely
because tables exist; each new operation must pass startup classification and
service/RLS checks. Do not open deferred privileged recovery as a dependency shortcut.
