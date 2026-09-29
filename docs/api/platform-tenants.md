# Platform tenant control plane

**Implemented 2026-09-29 (ADR-0019).** These operations manage the tenant registry,
not tenant business data. There is no implicit impersonation, header-selected
tenant context or implemented break-glass grant. A platform operator cannot browse
customer users, audit logs, API keys or sessions through tenant endpoints.

## Bootstrap the first operator

Migrations create the reserved `ecomind-platform` tenant and permission catalogue,
**not an operator account**. The development seed also creates no operator.
With controlled database access and a real interactive terminal:

```bash
# At the repository root; set DATABASE_URL securely for the intended database.
PYTHONPATH=backend .venv/bin/python -m app.scripts.bootstrap_operator \
  --email operator@example.org \
  --name "Platform Operator" \
  --reason "Approved first-operator bootstrap, change CHG-1234"
```

Use your actual operator mailbox. The command prompts twice with echo disabled;
it refuses noninteractive input or an echoing fallback. Do not put a password in
flags, shell history, environment variables or chat. No generated/default password
or credential file is created. An unknown random password is used only for tenant
onboarding below, never for the interactive operator bootstrap.

Bootstrap locks the platform row, refuses **any** existing platform user (including
disabled/deleted users), validates the seeded SUPER_ADMIN's resolved platform
capabilities and atomically creates the user, grant and SYSTEM audit event. It is
not an idempotent repair, password reset, second-operator enrollment or recovery
backdoor. If a success response is lost, inspect controlled database evidence;
do not assume a retry resets access. The command requires the correct database
and schema, and its database operator is a trusted administrative actor.

Sign in through the existing `/api/v1/auth/login` using
`tenant_slug: ecomind-platform`. The service uses ordinary live bearer sessions,
lockout and authentication budgets. Bootstrap does not assert mailbox verification.
There is no default platform password and no new public authentication route.
Active operators can use the existing self-service password flow; disabled-account
recovery remains future work. [Operator lifecycle](platform-operators.md) now adds
MFA-protected invitation/suspension/reactivation and a last-operator guard. Platform-action
MFA is implemented; see [`platform-mfa.md`](platform-mfa.md).

## Routes and contracts

Paths are relative to `/api/v1`. Successful responses are `no-store`/`no-cache`.
All six routes require a human platform session and scope-appropriate live grants.
All four mutations additionally require explicit password confirmation within the
last five minutes on that same session, with a second factor if enrolled or required by operator policy. See [`platform-step-up.md`](platform-step-up.md);
ordinary login does not satisfy the confirmation gate.

| Method | Path | Permission | Result |
|---|---|---|---|
| GET | `/platform/tenants` | `platform.tenants.read` | `{items, meta}` registry page |
| GET | `/platform/tenants/{id}` | `platform.tenants.read` | Tenant metadata |
| POST | `/platform/tenants` | `platform.tenants.write` | 201; atomic provisioning, tenant metadata only |
| PATCH | `/platform/tenants/{id}` | `platform.tenants.write` | Metadata update |
| POST | `/platform/tenants/{id}/suspend` | `platform.tenants.write` | Suspend and invalidate human access |
| POST | `/platform/tenants/{id}/activate` | `platform.tenants.write` | Set ACTIVE without restoring human sessions |

Every mutation needs a meaningful `reason` of 10–1000 characters. Include the
change/incident reference, not secrets. Listing accepts only `page` (1–10,000),
`page_size` (1–100, default 25) and optional `status` (ACTIVE/TRIAL/SUSPENDED/CANCELLED).
Order is descending `(created_at, id)`. Counts reflect live data; offset pagination
is not a stable snapshot. The reserved platform tenant and soft-deleted tenants
are excluded. Missing/deleted/reserved target IDs return 404. CANCELLED tenants
can be inspected but not modified or activated here (409).

Requests are closed: supplied IDs, tenant selectors, passwords, role grants, plan,
trial expiry, deletion flags and arbitrary status updates are rejected. Registry
responses contain only the existing TenantResponse metadata, never administrator
email, hashes, tokens, sessions or domain data. No seeded permissions were added.
A tenant role named SUPER_ADMIN still has no platform authority; permission
resolution filters grants by scope even if stored assignments are misconfigured.

### Provision a tenant

```json
{
  "name": "North District",
  "slug": "north-district",
  "type": "MUNICIPALITY",
  "timezone": "Europe/Amsterdam",
  "locale": "nl-NL",
  "admin_email": "admin@example.org",
  "admin_name": "District Administrator",
  "reason": "Approved onboarding, change CHG-1234"
}
```

Slug is immutable: 3–120 lowercase ASCII alphanumeric/hyphen characters, no leading,
trailing or consecutive hyphens; the `ecomind-` prefix is reserved. Duplicate
slugs, including soft-deleted reservations, return a sanitized 409 without repair.
Type must be a supported TenantType. Defaults are UTC, en-IN and the schema's
standard plan. Administrator addresses are normalized single ASCII mailboxes;
address syntax is checked, not external deliverability.

The transaction creates:

1. An **ACTIVE registry** row (not proof that onboarding is complete).
2. Nine editable tenant role bundles from the reviewed code catalogue—no platform
   role, operational demo data or fabricated metrics.
3. An INVITED administrator with a permanent TENANT_ADMIN grant and an unshared
   high-entropy password stored only as an Argon2 hash.
4. A single-use email verification hash and encrypted transactional outbox item.
5. Tenant-scoped verification evidence and platform-scoped provisioning evidence.

Nothing is disclosed until commit. Delivery configuration or audit failure rolls
back the entire operation, not just the invitation. Creation queues mail; **201
does not mean it was sent**. Run the existing auth-mail worker for the new tenant,
using the [recovery runbook](account-recovery.md). Local transport writes private
MIME files; real STARTTLS/SMTP remains an external deployment responsibility.

The administrator then:

1. Confirms the delivered code at `/auth/email/verify-confirm` with their tenant slug.
2. Requests `/auth/password-reset` and confirms its separately delivered code at
   `/auth/password-reset/confirm` to choose their own password.
3. Signs in with the tenant slug/email/new password.

If the verification code expires, use `/auth/email/verify-request` rather than
reprovisioning the tenant. The operator cannot retrieve or set this password,
replace an existing tenant's administrator or activate their user through these
platform endpoints. No frontend onboarding page is implemented yet.

### Metadata and lifecycle

PATCH accepts `reason` plus at least one of `name`, `timezone`, `locale`. Nulls,
empty names, unknown timezones and malformed locales are invalid. It cannot change
slug/type/plan/status or administrator identity. Metadata auditing records changed
field names, not an unrestricted request-body snapshot.

Send `{"reason": "Approved incident containment, INC-1234"}` to `/suspend`.
It sets SUSPENDED, revokes all previously unrevoked session rows (including expired
history rows) and clears pending reset/verification hashes and expiries. Rows and
consumed refresh hashes remain for replay evidence. Pending encrypted mail is not
synchronously erased: delivery rechecks user eligibility/hash and cancels stale
payloads; already delivered codes fail confirmation. Repeated suspension is safe
and audited. Login, JWT use and machine-key authentication reject suspended tenants.

`/activate` sets ACTIVE, including conversion from TRIAL; there is no billing or
trial-schedule automation implied. It never un-revokes human sessions or restores
old recovery codes. Humans must sign in again and request fresh codes if needed.
**Device keys are paused, not revoked by suspension**: after activation, any key
still valid by expiry/revocation/scope policy can work again. If keys are compromised,
keep the tenant suspended until an authorized incident procedure can revoke them;
this control plane deliberately has no cross-tenant key-management shortcut.

## Authorization, transactions and audit

Service checks repeat after locking, requiring platform scope, a human session,
operator flag, active account/session and live permission grants. Platform reads
also serialize and must successfully audit/commit before metadata is returned.
All audit failures roll back their associated mutations. Audit events use
`platform.tenant.{list,read,create,update,suspend,activate}` in the **platform** audit
partition, naming the real operator and target tenant UUID. Bootstrap is
`platform.operator.bootstrap`, SYSTEM-attributed, with the created user as resource.
There is no new cross-tenant/platform audit HTTP viewer; use controlled operational
inspection until that separately authorized reader is delivered.

Lock order is Platform Tenant NO KEY UPDATE -> operator User -> target Tenant
NO KEY UPDATE -> target Users in UUID order. Login/refresh/recovery hold User;
FK KEY SHARE is compatible with tenant NO KEY UPDATE. Suspension waits for
in-flight user authentication and then invalidates its sessions. Waiters reload
tenant eligibility after acquiring User rather than using pre-suspension snapshots.
Both invitation aliases now use the tenant administration mutex and live caller
rechecks, so a stale invitation cannot bypass suspension or grant removal.
Machine authentication holds Tenant SHARE -> key UPDATE, so suspension also waits
for those transactions. Already-authorized reads/in-flight work are not forcibly
cancelled; keep transactions short and use database/gateway timeouts.

Provisioning and credential invalidation bind a target RLS context for bounded
writes only. Success restores platform context; exceptions inside that scope roll
back the whole transaction. No RLS policy is weakened or disabled. The registry
itself is a global table protected by application authorization, not tenant RLS.
Production runtime roles must be non-superuser/non-BYPASSRLS, with SELECT/INSERT-only
audit access and only the necessary DML grants. Row locking requires UPDATE rights.
The offline bootstrap DB principal remains an explicitly trusted operator.

## Verified boundaries and remaining work

The restricted-role suite covers all nine tenant roles, anonymous access, forged/
stale service actors, grant scope pollution, input bounds, audit/commit/mail rollback,
RLS restoration, concurrent slug collision, suspension/activation and forced auth/
recovery interleavings. Onboarding exercises actual private MIME delivery for both
verification and reset and then a successful administrator login. No SMTP provider,
production load or real Redis deployment was tested. No schema change is needed;
the registry slice itself needed no migration. The subsequent password confirmation
migration is `e1c3617bfb4c` (still 85 tables, 74 forced tenant policies).

**Break-glass remains closed**: no grant model, tenant selection bypass, impersonation
or cross-tenant audit reader is introduced. Mandatory/login-wide MFA, consent, time-limited
capabilities, read auditing, revocation and operator recovery need their own
implementation and tests. Do not market this as production-complete privileged
access management. Apply TLS, operator network restrictions and ingress budgets;
these management routes are not covered by credential-endpoint rate budgets.
