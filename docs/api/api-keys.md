# Tenant API-key lifecycle

**Implemented and locally verified: 2026-09-29.** These are human-administered,
tenant-owned device credentials. Management uses existing bearer sessions.
Machine authentication is implemented/tested at the service boundary; **no
telemetry ingestion or other machine-key HTTP endpoint is mounted yet**.

## Management endpoints

All paths are relative to `/api/v1`.

| Method | Path | Permission | Success |
|---|---|---|---|
| GET | `/api-key-scopes` | `apikeys.read` | Explicit delegation catalogue, currently marked `endpoint_status: planned` |
| GET | `/api-keys` | `apikeys.read` | Metadata-only `{items, meta}` page |
| GET | `/api-keys/{id}` | `apikeys.read` | Metadata only |
| POST | `/api-keys` | `apikeys.write` | 201; new metadata plus one-time `api_key` |
| POST | `/api-keys/{id}/rotate` | `apikeys.write` | 201; replacement metadata plus one-time `api_key` |
| DELETE | `/api-keys/{id}` | `apikeys.write` | Idempotent 204; exact credential revoked |

Tenant identity is server-derived from the live bearer session. Foreign/missing
IDs return the same 404. Unknown fields and invalid filters return 400. Service
checks repeat live permissions/account/session eligibility after the tenant mutex;
a stale actor or API-key actor cannot administer keys. Seeded role bundles were
not changed: TENANT_ADMIN has these permissions, or a tenant can explicitly grant
them in a custom role. `apikeys.write` is a dangerous delegation capability.

Metadata includes UUID, name, public prefix, scopes, creator ID, timestamps,
expiry/revocation and `rotation_of_id`. It never includes the stored hash or a
retrievable secret. All successful responses use `Cache-Control: no-store` and
`Pragma: no-cache`; issuance waits for database commit before disclosure.
There is no reveal/recover-secret endpoint, name/scope PATCH, hard delete, export
or automatic key-delivery mail.

## Create and store securely

```json
{
  "name": "North depot gateway",
  "scopes": ["bins.telemetry.ingest"]
}
```

Optionally include `expires_at` as a timezone-aware ISO-8601 timestamp. Omission
means **90 days**; explicit null, past/naive dates and lifetimes beyond **365 days**
are rejected. Non-expiring issuance is not supported. Names are public-to-key-readers
metadata: never put credentials or other secrets in them.

Only `bins.telemetry.ingest` is delegable in this build. Arbitrary human,
identity, API-key-management, platform, own-user and model-management permissions
are refused, even for TENANT_ADMIN. No wildcard, implicit all-scope, empty or
duplicate scope list is accepted. This is an explicit allowlist, not an
intersection with the creator's roles: humans do not directly hold the device
scope, but `apikeys.write` deliberately permits provisioning it. A compromised
**provisioning administrator** can therefore mint device credentials; ordinary
human sessions cannot directly act as device principals.

The opaque key contains a 12-character random public lookup prefix and an
independent 256-bit random secret. Only the full key's SHA-256 hash is persisted.
Clients must treat the complete value as opaque, transfer it over TLS and put it
in an appropriate secret manager—not source, logs, query strings, screenshots,
issues or chat. Prefixes are identifiers, not authentication credentials.
Issuance DTO/service representations hide the secret. Credential fields, key
hashes and the recognizable key format are covered by log/audit redaction, but
redaction is not a substitute for never recording arbitrary secret-bearing data.

## Rotation and revocation

Send `{}` to `/api-keys/{id}/rotate` to retain scopes and the original expiry.
An optional finite `expires_at` can reset the lifetime within policy. Optional
`scopes` must remain a nonempty subset of the existing scopes **and** the current
allowlist. Rotation is not a scope-escalation route. Legacy null-expiry rows
require replacement; rotating an otherwise eligible one gives a finite default
lifetime. Unsupported legacy scopes must be narrowed or the key revoked/recreated.

Rotation creates a new UUID/prefix/hash and records `rotation_of_id`. The old key
is revoked atomically with replacement creation and audit: **no overlap/grace
period**. Coordinate device cutover accordingly. Revoked/expired keys cannot be
rotated (409). Tenant/key locking and a unique non-null rotation-source index
prevent concurrent requests from creating multiple children. Prefix collisions
produce a sanitized 409 and roll back, leaving the old key unchanged.

A lost successful response cannot be replayed to reveal the secret. Inspect
metadata for the replacement ID, then rotate that live replacement (or revoke it
and create a fresh key). Do not repeatedly rotate the original ID expecting to
recover credentials; it now returns 409.

DELETE revokes the **exact row**, not an entire rotation family. Deleting an
already revoked predecessor does not revoke its replacement: revoke the current
key ID to stop it. Rows/hashes/lineage remain as evidence. Repeated DELETE is a
no-op 204 with an audit event. No secret is disclosed on revoke.

Keys belong to the tenant, **not a creator's continuing user session or role**.
Disabling/deleting the creator or revoking their grants does not implicitly stop
an integration. Explicitly inventory and revoke relevant keys during offboarding
or an incident. Disabled/deleted tenants, expired/revoked keys, null expiry and
unsupported/empty scopes fail authentication. A user password login does not
restore a revoked key, and a key cannot be used as a human bearer JWT.

## Listing and evidence

`page` is 1–10,000; `page_size` is 1–100 (default 25). `state` supports:

* `active` (default): unrevoked, finite, unexpired rows.
* `expired`: unrevoked rows whose finite expiry has passed.
* `revoked`: retained revoked rows, including rotation predecessors.
* `all`: includes legacy null-expiry rows, which cannot authenticate.

Ordering is descending `(created_at, id)`; counts/pages reflect live data.
An `active` filter describes expiry/revocation, not a guarantee that legacy scopes
satisfy today's delegation policy. Unknown tenant/sort filters are rejected.
Successful metadata list/detail reads and lifecycle writes are audited. Failure
to record or commit the event prevents disclosure and rolls back mutations.

`audit_logs.actor_api_key_id` identifies a machine principal separately from
`actor_user_id`. Machine-authentication events have `actor_type=API_KEY`, a null
user reference, the real key UUID and the key-name snapshot. Filter the audit API
by `actor_api_key_id`. No key value/hash is recorded. The shared actor object's
principal UUID remains in its `user_id` slot for compatibility; code must respect
`auth_type` and must not treat an API-key principal as a User row.

## Consuming-service contract and deployment limits

A future machine endpoint must resolve a tenant, then call
`AuthService.authenticate_api_key(presented_key, tenant_id=resolved_id)` within
its database transaction. There is no global-prefix authentication lookup, JWT
issuance, role inheritance or cache authorization shortcut. Authentication binds
RLS, validates tenant/key/hash/expiry/scopes and records last-use plus machine audit.
The caller must commit business work and authentication evidence together, or
roll back both on failure.

Machine authentication locks Tenant SHARE -> key UPDATE. Management takes Tenant
NO KEY UPDATE -> caller User -> key UPDATE. Revocation/rotation waits for in-flight
machine transactions; after it commits, new authentications fail on the old key.
Already-authorized in-flight work may complete first. Keep transactions short,
validate/bound payloads before expensive work, and configure deployment timeouts.
Do not hold these locks across external calls or background jobs.

Revision `600bc6193a23` adds the rotation integrity/paging indexes and machine audit
reference. Manually provisioned duplicate rotation sources must be reviewed before
upgrade; migration intentionally fails instead of discarding history. Ordinary
DDL can block writes and needs scheduling. On downgrade, actor UUIDs are archived
under reserved metadata `_machine_actor_ref_v1` before dropping the column;
re-upgrade restores references to matching surviving keys in the same tenant.
Tenant contexts are explicitly iterated while RLS stays forced. This is a
privileged, documented schema data step, not a runtime audit-mutation API.

The tests use real PostgreSQL with a restricted role for HTTP/service behavior,
plus migration rollback/re-upgrade with machine evidence. The local seed smoke
exercised all six management routes and service authentication/attribution;
its disposable keys were revoked afterward. No real device, ingestion endpoint,
production-scale throughput, per-key HTTP abuse budgets, grace-period rotation,
quota/retention job or frontend is claimed. Apply ingress limits to management;
device auth/rate controls must be wired when device endpoints are implemented.
