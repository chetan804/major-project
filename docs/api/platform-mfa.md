# Opt-in MFA for platform actions

**Implemented 2026-09-29 (ADR-0021).** This protects platform registry **mutations**
for enrolled human operators. It is **not mandatory enrollment, login-wide MFA,
phishing-resistant authentication, or break-glass**. Ordinary login and registry
reads retain their bearer-session policy. Legacy unenrolled operators without a
required-action policy retain the
[password-confirmation flow](platform-step-up.md).

## Contract

All five routes below require a live human platform operator with
`platform.tenants.write`. They operate on that operator only: no user/tenant
selector, administrator bypass, disable route or public recovery route exists.
Request bodies reject unknown fields. All responses, including failures, are
`Cache-Control: no-store`.

| Method and path under `/api/v1/platform/auth/mfa` | Body | Committed response |
|---|---|---|
| GET (root) | none | `enabled`, `required_for_platform_actions`, `pending_expires_at`, `recovery_codes_remaining` |
| POST `/enrollment` | `password` | 201: `secret`, `otpauth_uri`, `expires_at` |
| POST `/enrollment/confirm` | `password`, `totp_code` | 200: `recovery_codes` (ten strings) |
| DELETE `/enrollment` | none | 204; cancel pending enrollment only |
| POST `/recovery-codes` | `password` | 200: ten replacement `recovery_codes` |

Passwords preserve whitespace and are bounded to 1–128 characters. TOTP input is a
six-digit string (retain leading zeroes), not a JSON number. Codes are generated
from 160-bit seeds with RFC 6238 HMAC-SHA1, a 30-second period and one-step skew on
either side. Keep server and authenticator clocks synchronized.

## Enroll and authorize a mutation

1. Sign in under `ecomind-platform`; do not refresh midway through enrollment.
2. POST `/enrollment` with the current password. Import the returned seed/URI into
   an authenticator. Keep the response private; it is not retrievable. No external
   QR/image service is used. The pending seed is bound to this live session and
   expires in ten minutes, or at session expiry if sooner.
3. POST `/enrollment/confirm` with the password and a code from that authenticator.
   Only a committed activation discloses the ten recovery codes. Store them in a
   separate protected offline/password-manager location. They are 192-bit random
   values, prefixed `rc1_`, and are stored server-side only as SHA-256 hashes.
4. Activation clears **every session's** previous confirmation and consumes the
   activation TOTP counter. It does not itself grant a mutation lease. Wait for a
   later authenticator code, or use a recovery code, for the next step.
5. POST `/api/v1/platform/auth/step-up` with `password` and **exactly one** of
   `totp_code` or `recovery_code`. A success returns `method: password+totp` or
   `method: password+recovery_code` and `expires_at`. It issues no new bearer token.
6. Perform the registry mutation with that same session. The existing five-minute
   half-open lease, capped by session expiry, applies. DELETE `/auth/step-up` under
   the platform prefix clears it early; this does not cancel pending enrollment.

An enrolled account cannot obtain a password-only lease. Successful second-factor
confirmation is bound to the active factor UUID and password-confirmation timestamp.
User-row serialization prevents concurrent or cross-session reuse of recovery codes
and TOTP counters. A consumed counter or any earlier counter is refused, including
when the clock moves backwards. A future-window code can require waiting longer
before another authenticator confirmation. Clients should serialize these actions.

## Replace an authenticator or rotate recovery codes

For replacement, first establish a current strong lease with the existing
password plus authenticator/recovery code. Then start enrollment with the password.
The old factor remains active until the new seed is confirmed in the initiating
session. Starting again supersedes the pending seed; cancelling never disables the
active factor. Activation replaces the factor UUID and recovery-code set and clears
all session leases. The pending enrollment carries the bounded replacement
authority established at start; confirmation still needs the password and new code.

Recovery-code rotation requires a current strong lease **and** the password.
It atomically replaces all recovery hashes and clears every session's lease.
A failed audit/commit retains old codes and proofs. A lost successful response is
not retrievable: use the authenticator or a remaining valid recovery code to
establish another lease and rotate. Losing a newly issued code set after rotation
requires the authenticator; old codes are already invalid.

Refresh/new login never inherits a lease or pending enrollment authority. Password
change/reset cancels pending enrollment and clears all proofs, but **retains the
active factor and unused recovery codes**. Reset also revokes sessions. Email access
or password knowledge alone therefore cannot remove action MFA. Loss of both the
authenticator and all recovery codes has **no automatic repair path** in this build.
Operator recovery requires separately reviewed operational work; do not delete
factor fields as a convenience fix.

Pending expiry invalidates authority, not immediate storage: encrypted expired
pending state remains until cancellation, replacement or password change/reset.
Status does not disclose an expired enrollment; cancel it before a safe rollback.

## Transactions, abuse controls and privacy

Lifecycle operations and confirmation use the existing platform-realm → User lock
order, live session/grant checks and restricted-role PostgreSQL RLS. A password
check cannot promote an expired session. Replacement and rotation recheck lease
freshness after hashing. The four registry mutation services check current factor
binding; merely adding a timestamp/client claim cannot satisfy MFA.

Credential POSTs share step-up's pre-body IP and authenticated-account budgets.
Unavailable counters deny requests. Wrong passwords/codes clear the current proof,
share the durable five-failure/fifteen-minute lockout and commit a DENIED audit.
Audit/commit failure rolls back enrollment, counter/recovery consumption, proof and
failure-counter changes. Direct service callers must preserve the existing
`AuthenticationStateChangedError` denial-commit contract.

Events use `platform.mfa.status`, `.enrollment_start`, `.enrollment_confirm`,
`.enrollment_cancel`, `.recovery_rotate`, and existing `platform.step_up.*` actions.
Only action/subject/outcome/method metadata is recorded, not seed, URI, code, hash,
password or request body. Schema/dataclass representations and log/audit redaction
hide issuance material. There is no platform audit HTTP reader yet.

Use TLS. Disable request/response body capture in gateways, APM and browser tooling
around credentials. Never put seeds/codes in URLs, shell history, tickets or logs.
A valid lease can finish an already-authorized request after its window expires;
use bounded transaction/lock timeouts in deployment.

## Key custody, deployment and rollback

Configure **`MFA_ENCRYPTION_KEY`** with an independent Fernet key, distinct from JWT
and mail-encryption keys. Bootstrap privately generates a separate development key
without replacing an existing configured value. Production must provision and back
up keys through controlled secret management, not the development bootstrap.

An empty setting supports installations without enrollment, but seed issuance and
TOTP decryption fail closed. Invalid configured keys fail startup validation.
Ciphertext is bound to purpose, tenant, user and factor identity. Copying it to
another principal does not work. A changed/missing key cannot silently downgrade an
enrolled account to password-only. Previously issued unexpired strong proofs and
hash-based recovery codes do not depend on decrypting the seed. Key rotation and
re-encryption are **not automated**; retain the correct key with protected backups.

Migration **`c4195297efc7`**, after `1eb8da7c2793`, adds six nullable User fields and
two Session fields; `users.mfa_secret_encrypted` already existed. Counts remain
**85 tables / 74 forced tenant policies**. Existing rows receive no enrollment or
MFA proof. Legacy non-null MFA material is not automatically adopted or erased:
unsupported/partial state cannot fall back to password-only. Use valid recovery
where available, or separately reviewed remediation.

Drain/restrict platform mutations and enrollment during mixed-version rollout and
rollback. **Old application code bypasses MFA even if new columns remain.** Apply
schema before serving compatible application code; enable enrollment only when all
serving instances enforce it. Never claim database migration alone enforces MFA.

The later operator-policy migration must first pass its own guarded downgrade.
This migration obtains table locks and **refuses while any active, pending, counter,
recovery or session MFA proof state remains**, including expired pending material.
It leaves state and audit evidence intact. Do not clear active factors just to make
a downgrade pass. Rollback with enrolled operators requires a reviewed compatible
application/factor-custody migration. With no MFA state, downgrade/upgrade discards
only empty MFA columns; round-trip and guarded data-bearing cases are tested.

## Verification and remaining scope

RFC vectors, skew/replay, ciphertext binding, configuration, privacy and proof-policy
unit tests supplement real restricted-role HTTP/DB tests for enrollment, replacement,
concurrent consumption, password reset/change, refresh, denial persistence, rate
limits and failed audit/commit rollback. No physical authenticator interoperability,
external SMTP, real Redis deployment or production load test is claimed.

ADR-0022 adds [operator lifecycle and one-way required-action policy](platform-operators.md).
HTTP invitees must enroll before registry writes; legacy operators remain opt-in until
explicitly opted into required policy. All operator-administration mutations require MFA.
Global mandatory enrollment, login-wide MFA, WebAuthn, independently verified operator
recovery, consent and revocable/time-bounded break-glass remain separate work. This feature does not grant access to customer data.
