# Account recovery and email verification

**Implemented and locally verified: 2026-09-29.** API-first; no frontend links
or external SMTP-delivery claim. See ADR-0016 for security and concurrency.

## Public API

All paths below are relative to `/api/v1/auth`. No bearer token is required,
including verification requests: an invited user cannot sign in yet.

| POST path | JSON fields | Success |
|---|---|---|
| `/password-reset` | `tenant_slug`, `email` | 202, queued if eligible |
| `/password-reset/confirm` | `tenant_slug`, `token`, `new_password` | 200; all existing sessions revoked |
| `/email/verify-request` | `tenant_slug`, `email` | 202, queued if eligible |
| `/email/verify-confirm` | `tenant_slug`, `token` | 200; verified; INVITED becomes ACTIVE, with no new permissions |

Example request (substitute your own tenant and address):

```json
{"tenant_slug": "your-tenant", "email": "you@example.invalid"}
```

Configured recovery requests return the same body for eligible, nonexistent,
deleted, disabled, or otherwise ineligible accounts:

```json
{
  "status": "accepted",
  "message": "If this account is eligible, a code has been queued for delivery. Only the latest code is valid.",
  "delivery_status": "queued_if_eligible",
  "delivery_mode": "local_mailbox"
}
```

SMTP mode reports `delivery_mode: "smtp"`. Neither mode promises inbox delivery.
Messages carry the tenant slug, API confirmation path and a **one-hour,
single-use** code. Only the latest code **for that purpose** is valid. Codes are
not returned by the request API. Reset is available for ACTIVE users; verification
for unverified ACTIVE or INVITED users in enabled tenants. Unknown/wrong-tenant,
consumed and invalid codes fail with 401; expired matching codes use
`TOKEN_EXPIRED`. Successful verification creates neither a session nor role grants.

Malformed requests return 400. Budget exhaustion returns 429 with `Retry-After`.
Unconfigured/disabled delivery and unavailable security counters return 503;
these failures are checked before account lookup. Responses under `/auth/` are
`Cache-Control: no-store`. Neutral response bodies are not a claim of constant-time
account lookup, nor a replacement for edge abuse controls.

## Local workflow

```bash
./scripts/bootstrap.sh
REDIS_ADAPTER=fakeredis make run
# Submit a recovery/verification request through /docs or an API client.
# In another terminal, dispatch one pass:
make auth-mail
```

Bootstrap creates a **separate Fernet key** in the ignored, mode-0600 `.env`,
enables local delivery when no explicit setting exists, and preserves configured
keys on rerun. The raw application default is delivery disabled; copied example
settings need a real key before startup. Never copy keys, codes, credentials or
mail content into source, logs, issues or chat.

`EMAIL_PROVIDER=console` means a labelled **local mailbox**, not stdout. Files
are `.runtime/auth-mail/<tenant UUID>/<message UUID>.eml` by default; per-tenant
directories are 0700 and files 0600. Read them locally with a mail viewer, then
submit the code in the JSON confirmation body, never in a query string.
This proves the development code path, not ownership of an external mailbox.
A custom `AUTH_MAILBOX_ROOT` is resolved relative to the repository root.
Local mail contains plaintext credentials by design; do not expose the folder
through an HTTP/static server. Remove old local mail and crash-leftover `.tmp`
files when no longer needed. Files are not automatically retention-swept yet.

## Worker and production setup

* Apply migration `0a396e61910c` after `43f430493613`.
* Set `AUTH_DELIVERY_ENABLED=true` and provide `AUTH_MAIL_ENCRYPTION_KEY` to
  both API and worker through the deployment's secret manager. It must be an
  independently generated Fernet key, not the JWT signing key. The key must not
  be stored alongside database backups.
* Staging/production delivery requires `EMAIL_PROVIDER=smtp`, `SMTP_HOST`,
  `SMTP_PORT` (default 587), a valid `SMTP_FROM_ADDRESS`, and, when authentication
  is needed, **both** `SMTP_USERNAME` and `SMTP_PASSWORD`.
* SMTP always requires verified STARTTLS and fails rather than falling back to
  plaintext. `SMTP_TIMEOUT_SECONDS` defaults to 10. Implicit-TLS port 465 is not
  supported by this adapter. SMTP acceptance does not prove inbox placement.
* Schedule `make auth-mail` repeatedly (e.g. every 30 seconds). It dispatches at
  most 25 due messages **per tenant per pass**, with tenant registry pages of
  100. The Python CLI accepts `--batch-size 1..100`; explicit DB configuration is
  needed when invoking it directly rather than through Make. It is not an
  automatically running Celery task or a general notification worker.
* Monitor aggregate `sent`, `retry`, `failed`, `cancelled` counts and sanitized
  delivery audit records. Provider exceptions, recipients and message bodies
  are never emitted by the worker. Tenant viewers with `audit.read` can inspect them through `/api/v1/audit-logs`.
* Transport failure retries with exponential backoff (30s, 60s, 120s, ...;
  capped at 1800s), up to `AUTH_MAIL_MAX_ATTEMPTS` (default 5). Expired,
  invalidated or superseded messages are cancelled. Terminal rows erase their
  encrypted payload; metadata remains pending a retention policy/job.
* Delivery is **at-least-once**. A crash after SMTP acceptance but before commit
  may duplicate a message. Retries keep a stable Message-ID; local delivery
  replaces the same file atomically. Do not claim exactly-once SMTP delivery.
* Drain pending mail before key rotation. Old-key payloads cannot be recovered
  by a worker holding only the new key: they become FAILED with the payload
  cleared. Users can request a fresh code. There is no multi-key rotation
  keyring in this implementation.
* Downgrading this migration deletes the outbox and verification credentials;
  outstanding verification codes cease to work. Drain first and back up
  according to the deployment's recovery policy. Existing users and audits are
  retained.

## Authentication budgets

Separate from the optional fail-open cache, security counters **fail closed**.
Production requires `RATE_LIMIT_ENABLED=true` and `REDIS_ADAPTER=redis` using
Redis **7+**. `/ready` probes the actual atomic counter operation, not just PING;
failed security storage gives 503. `/health` remains a liveness endpoint.

| Scope | Default | Configuration |
|---|---|---|
| Login/refresh/password-change IP group | 60 / minute | `AUTH_IP_LIMIT` |
| Reset/verification confirmation IP group | 60 / minute | `AUTH_IP_LIMIT` |
| Reset/verification request IP group | 20 / hour | `RECOVERY_IP_LIMIT`, `RECOVERY_WINDOW_SECONDS` |
| Account login, password change, or opaque token budget | 10 / 15 minutes | `AUTH_ACCOUNT_LIMIT`, `AUTH_ACCOUNT_WINDOW_SECONDS` |
| Reset + verification requests for tenant/email, shared | 3 / hour | `RECOVERY_ACCOUNT_LIMIT`, `RECOVERY_WINDOW_SECONDS` |

IP checks run before body parsing. Identity checks run before account lookup;
tenant/email identifiers are normalized. Opaque credentials are hashed before
key construction; Budget keys are keyed HMAC digests, not emails, IPs or tokens.
Redis INCR/EXPIRE NX/TTL run atomically in MULTI; later hits do not slide expiry.

With `REDIS_ADAPTER=fakeredis` or `null`, auth counters use a bounded in-process
memory adapter (not the cache), disclosed as simulated in `/health`. Its default
10,000-key cap (`AUTH_RATE_LIMIT_MAX_KEYS`) refuses new keys when full rather than
evicting live limits. It resets on process restart and is **not a shared
multi-worker/production control**. Real Redis must have adequate capacity and
avoid eviction that would reset security budgets.

The app reads the ASGI peer address, **not client-supplied forwarding headers**.
Configure the ASGI server to trust only your actual ingress proxies and have
those proxies overwrite forwarded headers. Never trust `*` on an Internet-facing
listener. Without trusted-proxy configuration, shared proxy/NAT clients share
one IP budget. Apply independent edge request/body-size and abuse limits.

## Evidence and limits

`test_auth_delivery.py`, `test_auth_rate_limits.py`, `test_auth_mail.py`, and
`test_rate_limits.py` cover HTTP behavior with restricted-role PostgreSQL RLS,
private MIME delivery, encryption/redaction, expiry/replay/purpose isolation,
rollback, concurrency, retry and throttling. The real local CLI mailbox flow was
also exercised. SMTP TLS ordering/certificate policy and Redis command atomicity
were tested with doubles/fakeredis: **no external SMTP delivery or real Redis
server was tested in this environment**. Deployment integration, deliverability,
queue-age alerting and retention scheduling remain operational work.

## Platform-provisioned administrator onboarding

New `/platform/tenants` provisioning creates an INVITED TENANT_ADMIN with an
unshared random password, then queues verification atomically. The recipient
confirms verification, requests password reset, confirms the separately delivered
reset code to choose a password, and signs in. No password or code is returned to
the operator. Both messages still require the auth-mail worker. See
[`platform-tenants.md`](platform-tenants.md) for bootstrap and deployment limits.

Tenant suspension now clears reset/verification hashes and revokes sessions.
Delivery rechecks eligibility/hash, so pending old messages are cancelled; delivered
old codes fail confirmation. Activation does not resurrect old codes/sessions.
Login and recovery re-read tenant state after user-lock waits rather than trusting
an earlier ORM snapshot; public recovery responses remain neutral.
