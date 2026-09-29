# Platform password reauthentication

**Implemented 2026-09-29 (ADR-0020), extended by ADR-0021.** Platform tenant
mutations require explicit recent credential confirmation in addition to a live
bearer session and permission. The password-only flow below applies to **unenrolled**
operators without a required-action MFA policy; repeating a password alone is not MFA.
HTTP-invited operators and explicitly required legacy accounts must enroll before registry
writes. Operator lifecycle mutations always require MFA; see `platform-operators.md`. Enrolled operators must additionally
supply an authenticator or single-use recovery code. See [platform action MFA](platform-mfa.md)
for enrollment, second-factor verification and guarded rollback. Break-glass remains closed.

## Client flow

1. Sign in normally under `ecomind-platform`. Login alone does not confirm a session.
2. POST `/api/v1/platform/auth/step-up` with the same bearer and a JSON `password`
   field containing the operator's current password, preserving whitespace.
3. For an unenrolled operator, a committed success returns only `method: password` and `expires_at`. No token,
   secret, permission upgrade or tenant selector is returned.
4. Perform the intended platform mutation with that **same** bearer session.
5. DELETE `/api/v1/platform/auth/step-up` to end the confirmation early. It returns
   an audited, idempotent 204 without signing the bearer out.

Both routes require `platform.tenants.write`, reserved platform scope and a live
human operator session. Tenant users, API keys and SYSTEM actors cannot confirm.
A read-only platform role cannot confirm or mutate; registry reads remain available
without confirmation. There is no additional public auth route or bypass flag.

Send passwords only over TLS, never in a URL, shell history, application logs or
APM request-body capture. Input is closed and bounded to 1–128 characters, with no
whitespace trimming; its model representation hides the password. All responses,
including validation/authentication failures, use `Cache-Control: no-store`.

## Protected operations and window

Confirmation is mandatory in the service layer for all four registry mutations:

* POST `/platform/tenants`
* PATCH `/platform/tenants/{id}`
* POST `/platform/tenants/{id}/suspend`
* POST `/platform/tenants/{id}/activate`

Missing/stale confirmation returns 403 `PERMISSION_DENIED` with
`details.step_up_required: true`. Existing live account/session/grant checks still
apply and can deny a confirmed caller. The lease lasts **five minutes**, capped by
the session's own expiry; exactly-at-expiry is expired. Future or pre-session
verification timestamps are invalid. The access JWT must also remain valid.

The window belongs to **one session**, not the user, refresh family, device name
or a client-provided claim. A second login and every refreshed replacement start
unconfirmed. Refresh before confirmation if needed; clients should serialize auth
operations to avoid refreshing away a confirmation they just obtained. Successful
password change clears every session's confirmation, including the kept session;
password reset clears it and revokes sessions. Session revocation, operator disable,
lockout and live permission removal remain effective immediately on subsequent use.

This is a reusable short window, **not** single-operation approval or protection
against a bearer stolen while already confirmed. Clear it after sensitive work.
Freshness is checked after platform/caller locks, at operation authorization—not a
promise to abort already-authorized transactions at the expiry instant. Keep DB
transactions short and use deployment timeouts.

## Failures, limits and evidence

Wrong passwords return 401, clear the current session's confirmation and increment
the existing persistent account failure counter. They share login lockout policy
(five failures, fifteen-minute lockout) rather than creating an unlimited second
password-checking path. Success resets the failure count. Malformed inputs do not
invoke password verification. IP budgets apply before body parsing; a separate
`platform_step_up` account budget is keyed by authenticated tenant/user IDs, shared
across their sessions. These use existing auth-limit configuration and HMAC keys.
Limiter outages fail closed. Local memory is explicitly a development simulation;
a shared Redis deployment remains necessary for distributed HTTP budgets.

Audit events are `platform.step_up.confirm` (SUCCESS or DENIED) and
`platform.step_up.clear`, in the platform audit partition with the real operator
and session UUID. Metadata includes method/expiry or whether clear changed state;
no password, hash, bearer or raw request body is recorded. There is still no
platform audit HTTP viewer; inspection requires controlled operational access.

Confirmation and its success audit commit before a response is disclosed.
Completed wrong-credential denials commit their counter/proof changes and audit via
`AuthenticationStateChangedError`. Audit/commit failures expose no successful lease
and roll back the transaction. Callers using the service directly must preserve
that existing denial transaction contract, not swallow the exception or silently
roll it back. HTTP IP/account budgets live at the API boundary; DB account lockout
also protects direct service use.

Shared platform authorization takes Platform Tenant NO KEY UPDATE -> operator User
locks. Confirmation, clear and registry writes use this order. Session lookup
refreshes the ORM identity map after locking, so a cached timestamp cannot resurrect
a lease cleared by another transaction. No RLS policy or tenant context changes.

## Deployment and rollback

Migration **`1eb8da7c2793`**, following `600bc6193a23`, adds nullable
`sessions.platform_reauthenticated_at`. Existing rows become NULL: **no existing
session is grandfathered in**. No table or RLS-policy count changes (85/74).

Apply the additive migration before deploying the new application. Drain/restrict
platform mutations until every serving instance runs the gate; older instances
will not enforce it just because the new column exists. Deploy compatible
application/schema pairs. During rollback, drain the affected API before dropping
the column; current code expects it, while old code lacks this protection.

The later MFA migration must first pass its guarded downgrade (see `platform-mfa.md`).
Only then can this password migration drop ephemeral confirmation state, not audit history. Re-upgrade
leaves all sessions unconfirmed and does not reconstruct authority from old audit
events. A data-bearing regression proves this behavior. Ordinary ALTER TABLE needs
a lock and should be scheduled with operational timeouts.

## Verification and remaining work

Restricted-role PostgreSQL tests cover all four protected service methods, both
routes, malformed inputs, cross-session isolation, refresh/password changes,
lockout, audit/commit rollback, IP/account budgets and unavailable counters. A
strong-reference ORM regression exercises concurrent clearing rather than relying
on SQLAlchemy's weak identity-map cache. Unit tests pin exact time boundaries and
password whitespace/repr behavior; migration tests preserve evidence without
restoring authority. Existing platform tests now perform real password confirmation.

Opt-in TOTP/recovery protection is now implemented in ADR-0021. Mandatory/login-wide
MFA, WebAuthn, operator role editing/recovery, consent and revocable break-glass remain
separate work. Bounded operator lifecycle is now implemented in ADR-0022. No emergency
tenant-data endpoint or implicit SUPER_ADMIN access has been introduced. No external
SMTP, real Redis deployment, frontend or production-scale load is claimed here.
