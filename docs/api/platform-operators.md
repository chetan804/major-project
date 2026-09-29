# Platform operator administration

**Implemented 2026-09-29 (ADR-0022).** This is a reserved-platform-realm control
plane, not tenant-user administration, customer-data access or emergency recovery.
There is no role editor, operator delete, email change, unlock, factor removal or
all-factor-loss repair endpoint. First-operator bootstrap still refuses any existing
platform account; it must not be used to recover or add operators.

## Permissions, confirmation and routes

The new PLATFORM-scoped `platform.operators.read` and `.write` permissions are
seeded only into the shared SUPER_ADMIN baseline. Grants/status/session are resolved
live after the realm mutex. Tenant users, machine keys and SYSTEM actors cannot
use the service. These permissions do not grant any customer-data capability.

**Every mutation requires a current session-bound password+TOTP/recovery proof**, even
for legacy operators who may still use password-only confirmation for registry writes.
Enroll through [platform MFA](platform-mfa.md), then confirm with a later TOTP counter
or unused recovery code. The existing five-minute window and live-factor binding apply.
Reads require the read permission and a live human session, not a strong proof.

Paths below are relative to `/api/v1/platform/operators`:

| Method/path | Input | Result |
|---|---|---|
| GET (root) | `page` 1–10000, `page_size` 1–100 (default 25) | Audited metadata page |
| GET `/{user_id}` | UUID | Audited metadata detail |
| POST (root) | `email`, `full_name`, `reason` | 201: invited operator metadata |
| POST `/{user_id}/suspend` | `reason` | Suspended operator metadata |
| POST `/{user_id}/activate` | `reason` | ACTIVE if verified, otherwise INVITED |
| POST `/{user_id}/require-mfa` | `reason` | One-way action-MFA policy enabled |

Inputs are closed. Reasons require 10–1000 characters; names 1–200; emails must be
single ASCII addresses of at most 320 characters and are canonicalized to lowercase.
No tenant selector, initial password, role, policy-off switch or verification flag
is accepted. A customer user ID, deleted user or nonexistent ID returns 404.

Response fields are only `id`, `email`, `full_name`, `status`,
`platform_mfa_required`, `email_verified_at`, `last_login_at`, `locked_until`,
`created_at`, `updated_at`. Never return a password hash, seed, code, recovery hash,
pending credential or bearer. All responses, including validation/permission/rate/
persistence failures, are `Cache-Control: no-store`.

## Invite a successor without sharing credentials

1. The inviting operator enrolls MFA and obtains a strong proof. Invitation also
   requires the **complete reviewed platform permission set**. A delegated lifecycle
   manager with fewer grants cannot issue a more privileged SUPER_ADMIN role.
2. POST the new email/name/reason. The service checks the shared SUPER_ADMIN role
   against the reviewed catalogue, creates an INVITED operator with an **unshared
   random password hash**, assigns that fixed role, and queues encrypted mailbox
   verification. Duplicate emails conflict, including soft-deleted identities.
3. The recipient verifies their mailbox through the existing public verification
   endpoint using `tenant_slug: ecomind-platform`. This makes the account ACTIVE;
   it does not disclose or set a usable password.
4. The recipient independently requests/confirms a password reset, then signs in.
5. The recipient enrolls an authenticator, safely stores recovery codes, and obtains
   a fresh strong proof. Only then can they mutate the registry or administer operators.

HTTP invitations set `platform_mfa_required=true`. This flag blocks password-only
**registry** writes even before enrollment. It is not login-wide MFA: login,
self-service setup/recovery and authorized reads remain available. Step-up can still
return `method: password` for an unenrolled account, but that proof does not satisfy
mandatory action policy. Clients should read `/platform/auth/mfa`; if
`required_for_platform_actions=true` and `enabled=false`, enroll instead of repeatedly
confirming the password. Proof issuance is not a permission upgrade.

A successful response means the invitation transaction committed, not that external
SMTP delivered it. Local MIME delivery is tested; actual SMTP is not. A lost issuance
response can be reconciled through operator metadata; retrying the same email yields
409, not another operator or a replacement password. Recipients can request fresh
verification through the existing public flow.

## Suspension, reactivation and the last-operator guard

Suspension retains the active factor, unused recovery codes and action-MFA policy.
It revokes all target sessions, clears all proofs and pending enrollment, and
invalidates reset/verification credentials. It can withdraw a pending invitation.
Old queued credentials are unusable; the mail worker checks current eligibility.

A suspension must leave another active, nondeleted, nonlocked operator with:

* a decryptable, principal/factor-bound enrolled authenticator and consumed counter;
* **permanent**, live grants for `platform.operators.write` and
  `platform.tenants.write` (needed for step-up and own-factor setup).

Invited, unenrolled, disabled, temporarily locked, corrupt-factor and temporary-grant
accounts do not satisfy this guard. Failure is 422 `BUSINESS_RULE_VIOLATION` with
rule `BR-PLATFORM-LAST-OPERATOR`. Self-suspension is allowed only with a qualifying
successor. The realm mutex serializes both cross-suspensions and simultaneous
self-suspensions, with live caller rechecks: neither race can remove both managers.

This is an administrative safety check, **not evidence that another human has a
working device or retained recovery codes**. Later password failures, external SQL,
key loss or loss of all devices can still make the control plane unavailable.
Maintain independently controlled operator/device/key custody; no automatic recovery
shortcut is provided. Do not create unattended/default operator accounts.

Reactivation is restricted to SUSPENDED users. A verified email returns to ACTIVE;
an unverified email returns to INVITED and must be verified through the mailbox.
This also applies to an offline-bootstrapped operator whose email was never verified.
Reactivation never restores sessions, pending seeds, reset/verification tokens or
old proofs. It does not clear temporary lockout, remove MFA or repair DISABLED,
LOCKED or deleted accounts. Repeated activation of already ACTIVE/INVITED users is
an audited no-op; repeated suspension re-invalidates credentials safely.

## Tighten legacy action policy

Legacy accounts, including the existing offline bootstrap flow, retain their prior
opt-in registry policy. A strongly confirmed manager may POST `require-mfa` for
an existing ACTIVE/INVITED/SUSPENDED operator. It sets the persisted policy true and
clears **all** target proofs immediately, including the caller's if targeting self.
There is no inverse endpoint. It does not sign the target out or block enrollment.
Password change/reset, suspension/reactivation and refresh cannot unset the flag.

Already-enrolled operators continue to need their second factor regardless of this
flag. Operator administration always needs MFA regardless of this flag. Mandatory
global enrollment and login-wide MFA remain separate rollout decisions.

## Transactions, privacy and deployment

Lock order is realm NO KEY UPDATE → caller User → target User → remaining candidate
Users ordered by ID. All lifecycle requests share the realm mutex; ordinary auth
holds User, with compatible Tenant FK locks. A refresh completing before suspension
has its new session revoked; refresh after suspension is denied. Use bounded request,
transaction and lock timeouts operationally.

Successful reads/mutations and `platform.operator.list/read/invite/suspend/activate/
require_mfa` events commit before metadata is returned. Invitation includes the user,
role grant, verification credential and encrypted outbox row in that transaction.
Failure of audit, delivery enqueue or commit rolls everything back. Reasons are
privacy-filtered; do not include secrets in free text. No cross-tenant audit reader
is introduced. Authorization/validation failures use the normal error contract.

Lifecycle POSTs share pre-body IP and authenticated-account budgets. Counter failure
denies requests; no request body is needed to enforce the IP budget. All-target
session invalidation retains historical revocation timestamps and evidence.

Migration **`e1c3617bfb4c`**, after `c4195297efc7`, adds the non-null, false-default
`users.platform_mfa_required` column and two permission definitions/grants. The
catalogue is now **101 permissions / 322 baseline grants**; tables/policies remain
**85 / 74**. No account is created or silently opted in by migration.

Drain/restrict platform writes and enrollment while schema/application versions are
mixed: older applications ignore mandatory policy. Downgrade locks User state and
**refuses if any required flag remains**, even on invited/suspended/deleted accounts.
Never unset a policy just to make downgrade pass. A safe downgrade with no required
flags removes the two permission definitions/grants and empty policy; audit history
is retained. Re-upgrade grants only the reviewed shared SUPER_ADMIN baseline, not
previous custom grants.

**Alembic commits per revision.** A multi-revision downgrade may finish this revision
then fail at the older MFA guard. Inspect the actual schema version after failure;
do not assume the original head remains. Restore a compatible head before restarting
the API. Regression tests exercise this partial-progress behavior as well as the
required-policy refusal. Old application rollback is not safe merely because columns
or encrypted MFA seeds remain in the database.

## Evidence and remaining scope

Restricted-role PostgreSQL tests cover real mailbox onboarding, fresh MFA gates,
legacy-policy tightening, cached-user reload, concurrent suspensions, factor retention,
live grants, last-manager eligibility, cross-tenant denial, closed pagination/inputs,
rate failures and atomic rollback. Unit tests pin permission scope and proof policy;
migration tests preserve required policy and enforce rollback compatibility.

Role/account editing, operator deletion, all-factor-loss recovery, an authorized
platform audit viewer, mandatory global/login-wide MFA, consent and revocable
break-glass remain unimplemented. No frontend, physical authenticator test, external
SMTP/real Redis deployment, production load test, commit or PR is claimed here.
