# EcoMind-AI — Error Catalogue

The error `code` is a **closed enumeration** defined in
`backend/app/core/errors.py`. It is impossible to raise an error code that is
not in this table (the exception constructor validates against the enum), which
means the API contract cannot drift from this document.

Envelope (section 34):

```json
{
  "error": {
    "code": "RESOURCE_NOT_FOUND",
    "message": "Bin not found",
    "details": { "bin_id": "..." },
    "request_id": "01J...",
    "timestamp": "2026-09-24T10:15:00Z"
  }
}
```

**Never present in a response:** stack traces, SQL text, file-system paths,
secrets, environment values, dependency versions, internal hostnames.

---

## 1. Client errors

| HTTP | Code | Meaning | `details` typically contains |
|---|---|---|---|
| 400 | `MALFORMED_REQUEST` | Body is not parseable JSON / wrong content type | — |
| 400 | `VALIDATION_ERROR` | Field-level validation failed | `fields: [{field, message, type}]` |
| 400 | `INVALID_DATE_RANGE` | `from` ≥ `to`, or range exceeds the max window | `from`, `to`, `max_days` |
| 400 | `INVALID_PAGINATION` | `page_size` out of bounds, bad cursor | `max_page_size` |
| 400 | `INVALID_SORT_FIELD` | Sort field not in the allow-list | `allowed` |
| 400 | `INVALID_FILTER` | Unknown or mistyped filter | `parameter`, `allowed_values` |
| 400 | `INVALID_COORDINATES` | Latitude/longitude outside valid ranges | `latitude`, `longitude` |
| 400 | `INVALID_GEOMETRY` | Malformed polygon/boundary | `reason` |
| 400 | `INVALID_IDEMPOTENCY_KEY` | Key reused with a different payload | `idempotency_key` |
| 401 | `AUTHENTICATION_REQUIRED` | No credentials supplied | — |
| 401 | `INVALID_CREDENTIALS` | Login failed (generic: no user enumeration) | — |
| 401 | `TOKEN_EXPIRED` | Access token past `exp` | — |
| 401 | `TOKEN_INVALID` | Bad signature, wrong issuer/audience, malformed | — |
| 401 | `SESSION_REVOKED` | Session revoked, rotated away, or logged out | — |
| 401 | `REFRESH_TOKEN_REUSED` | Reuse detected; family revoked | — |
| 403 | `PERMISSION_DENIED` | Authenticated but lacks the permission | `required_permissions` |
| 403 | `TENANT_ACCESS_DENIED` | Requested tenant is not one of the caller's memberships | — |
| 403 | `ACCOUNT_SUSPENDED` | Account not `ACTIVE` | `status` |
| 403 | `ACCOUNT_LOCKED` | Temporary lockout from failed logins | `locked_until` |
| 403 | `BREAK_GLASS_REQUIRED` | Platform user attempted tenant data access | `action_required` |
| 403 | `READ_ONLY_ROLE` | Role cannot perform this action (informational) | `role` |
| 404 | `RESOURCE_NOT_FOUND` | Not found **or** not visible to this tenant | `resource_type`, `resource_id` |
| 404 | `ENDPOINT_NOT_FOUND` | No such route | `path` |
| 405 | `METHOD_NOT_ALLOWED` | Wrong verb | `allowed` |
| 409 | `DUPLICATE_RESOURCE` | Unique constraint violated | `field`, `value` |
| 409 | `CONFLICT` | Generic concurrent-modification conflict | — |
| 409 | `STALE_RESOURCE` | `If-Match` version mismatch | `current_version` |
| 409 | `INVALID_STATE_TRANSITION` | Illegal lifecycle transition (BR-13/§4) | `current_status`, `allowed_transitions`, `requested` |
| 409 | `RESOURCE_IN_USE` | Cannot delete while referenced | `references: [{type, id}]` |
| 409 | `TASK_ALREADY_COMPLETED` | Idempotency conflict on completion | `completed_at` |
| 413 | `FILE_TOO_LARGE` | Upload exceeds the limit | `max_mb`, `actual_mb` |
| 415 | `UNSUPPORTED_MEDIA_TYPE` | Content type not allowed (client-declared or sniffed) | `detected_type`, `allowed` |
| 422 | `BUSINESS_RULE_VIOLATION` | Domain rule failed | `rule_code`, `rule_description` |
| 422 | `CAPACITY_EXCEEDED` | Route load > vehicle capacity (BR-06) | `capacity_kg`, `planned_kg` |
| 422 | `COMPOSITION_INVALID` | Composition percentages ≠ 100 ± 0.01 (BR-08) | `sum`, `items` |
| 422 | `QUANTITY_EXCEEDS_LOAD` | Outcomes exceed load weight (BR-09) | `load_kg`, `recorded_kg` |
| 422 | `FACILITY_NOT_CAPABLE` | Facility cannot accept this category (BR-10) | `facility_id`, `category`, `accepted` |
| 422 | `INSUFFICIENT_DATA` | Not enough data to compute honestly (BR-17) | `required`, `available`, `what_is_missing` |
| 422 | `UNSUPPORTED_WASTE_CATEGORY` | Category not in the taxonomy | `category` |
| 422 | `CONFIDENCE_BELOW_THRESHOLD` | Action requires higher confidence (BR-15) | `confidence`, `threshold`, `queued_for_review` |
| 422 | `HARD_CONSTRAINT_UNSATISFIABLE` | Optimization constraints cannot be met | `constraints`, `suggestions` |
| 429 | `RATE_LIMIT_EXCEEDED` | Too many requests | `limit`, `window_seconds`, `retry_after` + `Retry-After` header |
| 451 | `LEGAL_HOLD` | Deletion blocked by retention/legal hold | `policy` |

---

## 2. Server errors

| HTTP | Code | Meaning | Client-visible message |
|---|---|---|---|
| 500 | `INTERNAL_ERROR` | Unhandled exception | "An unexpected error occurred." (details only in logs, correlated by `request_id`) |
| 500 | `COMPUTATION_ERROR` | A metric/model computation failed after retries | "The calculation could not be completed." |
| 502 | `EXTERNAL_PROVIDER_ERROR` | Adapter returned an invalid response | "An external service returned an unexpected response." |
| 503 | `DEPENDENCY_UNAVAILABLE` | DB/cache/solver/model/provider unavailable | "A required service is temporarily unavailable." + `dependency` |
| 503 | `CIRCUIT_OPEN` | Provider circuit breaker open after repeated failures | "The provider is temporarily disabled after repeated failures." + `retry_after` |
| 503 | `MAINTENANCE_MODE` | Platform maintenance | `until` |
| 504 | `TIMEOUT` | Operation exceeded its budget | `timeout_seconds` |
| 504 | `SOLVER_TIMEOUT` | Optimization hit the time limit (a **partial** result may accompany it) | "Optimization reached the time limit; the best solution found is returned and marked as not proven optimal." |

---

## 3. Non-error status semantics that callers must understand

| Status | Used for | Body |
|---|---|---|
| 200 | Synchronous success | Resource or collection envelope |
| 201 | Created | Resource + `Location` header |
| 202 | Accepted, async | `{ "job_id" \| "run_id", "status": "QUEUED", "status_url": "..." }` |
| 204 | Deleted / no content | empty |
| 304 | Not modified (ETag) | empty |

---

## 4. `details` discipline

* `details` is a **bounded, typed** object (`dict[str, str|int|float|bool|list]`),
  validated before serialisation; it never contains a traceback, a SQL string, a
  file path or a secret.
* Values are echoed back only when they came from validated input, so reflection
  cannot be used to smuggle content into a UI that renders `details` verbatim.
* Field-level validation errors always populate `fields` so the frontend can
  attach errors to the right inputs without string parsing.
* Warnings that are not failures appear in `meta.warnings` on successful
  responses (e.g. "12 of 96 bins have no sensor; overflow risk is unavailable for
  those bins"). This is how the platform avoids turning partial data into a
  silent success.
