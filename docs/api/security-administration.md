# Tenant audit browsing and administrative sessions

**Implemented and verified locally: 2026-09-29.** All routes require a live
bearer session and the named permission. Tenant identity comes from that session,
not a query/body parameter. Foreign identifiers return the same 404 as missing
ones. These are tenant APIs, not platform/break-glass access.

## Routes

Paths are relative to `/api/v1`.

| Method | Path | Permission | Result |
|---|---|---|---|
| GET | `/audit-logs` | `audit.read` | Bounded cursor page; successful read audited |
| GET | `/audit-logs/{audit_id}` | `audit.read` | One event, with a separate read event |
| GET | `/sessions` | `sessions.read` | Paginated session metadata across the tenant; read audited |
| DELETE | `/sessions/{session_id}` | `sessions.revoke` | 204; revoke the whole device rotation family |
| POST | `/users/{user_id}/sessions/revoke-all` | `sessions.revoke` | `{ "revoked_sessions": <count> }` |

No request body is required by revocation routes. IDs use their real schema
types: audit IDs are positive integers, session/user IDs are UUIDs. The existing
`/auth/sessions` routes remain **self-service**, not a way to administer another
user. No access/refresh tokens or credential hashes are returned by these APIs.
Successful responses are `Cache-Control: no-store`.

## Audit queries

Supported query parameters:

* `page_size`: 1–100, default 25; `cursor`: opaque continuation value.
* Exact-match `action`, `actor_user_id`, `actor_api_key_id`, `resource_type`, `resource_id`,
  `request_id`, and `outcome` (`SUCCESS`, `FAILURE`, `DENIED`). Wildcards are literal.
* Inclusive `from_time` and `to_time`: ISO-8601 timestamps **with timezone**;
  an inverted range is invalid.

Unknown parameters, invalid IDs/ranges, oversized pages and invalid/expired
cursors return 400. There is no client-controlled tenant or sort field. Ordering
is descending `(created_at, id)`; the ID tie-breaker handles simultaneous events.

```json
{
  "items": [],
  "next_cursor": null,
  "has_more": false
}
```

Pass `next_cursor` with the **same filters** to continue. A page-size change is
allowed. Cursors are HMAC-signed with domain separation from JWTs, tenant/filter
bound and expire one hour after the first continuation is issued; subsequent
pages do not extend that expiry. Signing-key rotation invalidates cursors.
A cursor is not an authorization credential: every page rechecks live access.

There is no expensive total-count query. The current read's own event is appended
after selection, so normal forward traversal does not chase its read receipts.
This is a live keyset traversal, **not a database snapshot/export**: transactions
committed later with older timestamps may become visible on later pages. A fresh
first-page request includes newer activity and previous read events.

Successful reads record actor identity, request correlation and returned event
IDs (or a detail resource ID). Failed audit writes/commits prevent data from being
returned; they are not silently ignored. Denied/invalid/not-found requests remain
in HTTP access/error logs; this slice does not add a database event for every
failed read. There is no export, mutation or deletion API.

### Privacy and append-only controls

Audit DTOs expose only explicit fields. Metadata is bounded and credential-shaped
keys/bearer strings are redacted both on new repository writes and on read of
legacy rows. Raw request/response/mail bodies are excluded. Limits include
six levels, 100 entries per collection, a traversal budget and a 16 KiB text
budget; long values get truncation markers. This is **not a detector for arbitrary
unlabelled secrets**. Producers must still send curated, JSON-compatible metadata,
never arbitrary payloads. Read-time redaction does not rewrite existing history.

New repository events capture request IDs automatically and snapshot a caller's
name when the caller supplies it. Historical/null actor labels are not invented
by joining the current user name. Authorized viewers can see audit IP/user-agent
metadata; this is permission-protected personal data, not a public feed.

`AuditLogRepository.update` and `soft_delete` explicitly refuse mutations. The
old generic inherited methods were not append-only merely because the table
lacked update/delete timestamps; those paths are now closed.

**Deployment requirement:** the runtime DB role must be a non-owner,
non-superuser without BYPASSRLS, with only SELECT/INSERT on `audit_logs` and
USAGE on its ID sequence. Revoke UPDATE, DELETE and TRUNCATE, including inherited
privileges. Tests enforce these permissions on a real restricted PostgreSQL role.
The migration does not create/configure production database roles. This is not a
tamper-proof ledger against a database owner; retention/anonymization needs a
separately controlled role and is not implemented here.

## Administrative session controls

`GET /sessions` supports `page` (1–10,000), `page_size` (1–100, default 25),
optional tenant-local `user_id`, and `state`:

* `active` (default): unrevoked and unexpired.
* `revoked`: includes consumed refresh ancestors.
* `expired`: unrevoked but expired; revoked rows are in the previous category.
* `all`: retained history, including disabled/soft-deleted users.

It uses the standard `{items, meta}` page envelope and descending `(issued_at,
id)` order. Totals/pages are live and can change as sessions are issued/revoked.
Metadata includes user/family/predecessor IDs, timestamps, revocation reason,
IP and user-agent, **never token values or hashes**.

Revoking a session ID revokes any unrevoked descendants in its rotation family,
including a refresh completed while the administrator waited. Other devices
remain signed in. Repeating a revocation is a no-op 204 with a new audit record;
history is retained. Bulk revocation includes **every device, including the
caller's own session when targeting themselves**. Its count is newly marked rows,
including previously unrevoked expired rows, not necessarily active browsers.
A later legitimate password login is still allowed; revocation is not suspension.

Service checks repeat after the tenant mutex is acquired. Revoking users with
permissions the caller lacks additionally requires `roles.assign.elevate`,
matching the existing administrative privilege ceiling. In particular, an
OPERATIONS_MANAGER cannot use session revocation to sign out a TENANT_ADMIN.

Lock order is tenant **NO KEY UPDATE** -> caller User -> target User -> session
updates. The tenant lock still serializes administrators, while remaining
compatible with the KEY SHARE locks taken by recovery-outbox foreign-key checks.
A stronger tenant FOR UPDATE lock would deadlock with User-locked recovery issuance.
The regression suite now forces that actual outbox interleaving. Correction from
the earlier note: sessions and audit logs use TenantKeyMixin and have no tenant
FK; their refresh test alone did not prove the FK claim. Revocation and its
audit commit together; a failure rolls both back.

## Migration, evidence and remaining work

Revision `ca9642749b58` adds the audit index's ID tie-breaker and a tenant-first
session paging index. It changes no row data and is reversible. Standard index
DDL may block writes during construction: schedule maintenance or prepare a
separately reviewed online migration for a large deployment.

Tests: `test_security_administration.py` (restricted-role HTTP/service tests,
all nine seeded tenant roles, custom auditor, cross-tenant/privacy/rollback and
forced concurrency) and `test_audit_safety.py` (cursor and redaction contracts).
All five routes were also exercised against the local development seed.

This slice includes no frontend, export/retention jobs or platform audit/break-glass.
API-key lifecycle is now implemented separately; see `api-keys.md`. Apply ingress
abuse controls: these routes are not included in the credential-specific auth rate
budgets. Production-scale performance and external
infrastructure remain deployment work, not claims from this local gate.
