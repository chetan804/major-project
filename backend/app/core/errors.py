"""
Error contract.

Every client-visible failure is expressed as one of a **closed** set of error
codes defined here. The catalogue mirrors ``docs/api/error-catalogue.md`` exactly,
and because :class:`ErrorCode` is an enum, it is impossible to raise an
undocumented code — the contract cannot silently drift from the documentation.

Envelope::

    {
      "error": {
        "code": "RESOURCE_NOT_FOUND",
        "message": "Bin not found",
        "details": {"resource_type": "bin", "resource_id": "..."},
        "request_id": "01J...",
        "timestamp": "2026-09-24T10:15:00Z"
      }
    }

Security requirements encoded here (master directive, section 34):

* stack traces, SQL, file paths, secrets and infrastructure details are **never**
  returned to a client;
* ``details`` is sanitised to JSON-safe scalars/containers so that a value from
  an internal object can never leak by being passed through unexamined;
* an unexpected exception yields a generic ``INTERNAL_ERROR`` message while the
  real cause is logged server-side and correlated by ``request_id``.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import Enum, StrEnum
from typing import Any

from fastapi import status

__all__ = [
    "AppError",
    "AuthenticationError",
    "BusinessRuleError",
    "ConflictError",
    "DependencyUnavailableError",
    "ErrorCode",
    "ErrorDetail",
    "InputValidationError",
    "InsufficientDataError",
    "NotFoundError",
    "PermissionDeniedError",
    "RateLimitError",
    "ServiceTimeoutError",
    "problem",
]


class ErrorCode(StrEnum):
    """
    Closed enumeration of every error code the API may return.

    Values are the wire representation; ``ERROR_STATUS`` maps each to its HTTP
    status. Grouping follows the catalogue's structure (client, server).
    """

    # -- 400 ---------------------------------------------------------------
    MALFORMED_REQUEST = "MALFORMED_REQUEST"
    VALIDATION_ERROR = "VALIDATION_ERROR"
    INVALID_DATE_RANGE = "INVALID_DATE_RANGE"
    INVALID_PAGINATION = "INVALID_PAGINATION"
    INVALID_SORT_FIELD = "INVALID_SORT_FIELD"
    INVALID_FILTER = "INVALID_FILTER"
    INVALID_COORDINATES = "INVALID_COORDINATES"
    INVALID_GEOMETRY = "INVALID_GEOMETRY"
    INVALID_IDEMPOTENCY_KEY = "INVALID_IDEMPOTENCY_KEY"

    # -- 401 ---------------------------------------------------------------
    AUTHENTICATION_REQUIRED = "AUTHENTICATION_REQUIRED"
    INVALID_CREDENTIALS = "INVALID_CREDENTIALS"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"  # noqa: S105 - an error-code identifier, not a credential
    TOKEN_INVALID = "TOKEN_INVALID"  # noqa: S105 - an error-code identifier, not a credential
    SESSION_REVOKED = "SESSION_REVOKED"
    REFRESH_TOKEN_REUSED = "REFRESH_TOKEN_REUSED"  # noqa: S105 - an error-code identifier, not a credential

    # -- 403 ---------------------------------------------------------------
    PERMISSION_DENIED = "PERMISSION_DENIED"
    TENANT_ACCESS_DENIED = "TENANT_ACCESS_DENIED"
    ACCOUNT_SUSPENDED = "ACCOUNT_SUSPENDED"
    ACCOUNT_LOCKED = "ACCOUNT_LOCKED"
    BREAK_GLASS_REQUIRED = "BREAK_GLASS_REQUIRED"
    READ_ONLY_ROLE = "READ_ONLY_ROLE"

    # -- 404 / 405 ---------------------------------------------------------
    RESOURCE_NOT_FOUND = "RESOURCE_NOT_FOUND"
    ENDPOINT_NOT_FOUND = "ENDPOINT_NOT_FOUND"
    METHOD_NOT_ALLOWED = "METHOD_NOT_ALLOWED"

    # -- 409 ---------------------------------------------------------------
    DUPLICATE_RESOURCE = "DUPLICATE_RESOURCE"
    CONFLICT = "CONFLICT"
    STALE_RESOURCE = "STALE_RESOURCE"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    RESOURCE_IN_USE = "RESOURCE_IN_USE"
    TASK_ALREADY_COMPLETED = "TASK_ALREADY_COMPLETED"

    # -- 413 / 415 ---------------------------------------------------------
    FILE_TOO_LARGE = "FILE_TOO_LARGE"
    UNSUPPORTED_MEDIA_TYPE = "UNSUPPORTED_MEDIA_TYPE"

    # -- 422 ---------------------------------------------------------------
    BUSINESS_RULE_VIOLATION = "BUSINESS_RULE_VIOLATION"
    CAPACITY_EXCEEDED = "CAPACITY_EXCEEDED"
    COMPOSITION_INVALID = "COMPOSITION_INVALID"
    QUANTITY_EXCEEDS_LOAD = "QUANTITY_EXCEEDS_LOAD"
    FACILITY_NOT_CAPABLE = "FACILITY_NOT_CAPABLE"
    INSUFFICIENT_DATA = "INSUFFICIENT_DATA"
    UNSUPPORTED_WASTE_CATEGORY = "UNSUPPORTED_WASTE_CATEGORY"
    CONFIDENCE_BELOW_THRESHOLD = "CONFIDENCE_BELOW_THRESHOLD"
    HARD_CONSTRAINT_UNSATISFIABLE = "HARD_CONSTRAINT_UNSATISFIABLE"

    # -- 429 / 451 ---------------------------------------------------------
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    LEGAL_HOLD = "LEGAL_HOLD"

    # -- 5xx ---------------------------------------------------------------
    INTERNAL_ERROR = "INTERNAL_ERROR"
    COMPUTATION_ERROR = "COMPUTATION_ERROR"
    EXTERNAL_PROVIDER_ERROR = "EXTERNAL_PROVIDER_ERROR"
    DEPENDENCY_UNAVAILABLE = "DEPENDENCY_UNAVAILABLE"
    CIRCUIT_OPEN = "CIRCUIT_OPEN"
    MAINTENANCE_MODE = "MAINTENANCE_MODE"
    TIMEOUT = "TIMEOUT"
    SOLVER_TIMEOUT = "SOLVER_TIMEOUT"


ERROR_STATUS: dict[ErrorCode, int] = {
    # 400
    ErrorCode.MALFORMED_REQUEST: status.HTTP_400_BAD_REQUEST,
    ErrorCode.VALIDATION_ERROR: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_DATE_RANGE: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_PAGINATION: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_SORT_FIELD: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_FILTER: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_COORDINATES: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_GEOMETRY: status.HTTP_400_BAD_REQUEST,
    ErrorCode.INVALID_IDEMPOTENCY_KEY: status.HTTP_400_BAD_REQUEST,
    # 401
    ErrorCode.AUTHENTICATION_REQUIRED: status.HTTP_401_UNAUTHORIZED,
    ErrorCode.INVALID_CREDENTIALS: status.HTTP_401_UNAUTHORIZED,
    ErrorCode.TOKEN_EXPIRED: status.HTTP_401_UNAUTHORIZED,
    ErrorCode.TOKEN_INVALID: status.HTTP_401_UNAUTHORIZED,
    ErrorCode.SESSION_REVOKED: status.HTTP_401_UNAUTHORIZED,
    ErrorCode.REFRESH_TOKEN_REUSED: status.HTTP_401_UNAUTHORIZED,
    # 403
    ErrorCode.PERMISSION_DENIED: status.HTTP_403_FORBIDDEN,
    ErrorCode.TENANT_ACCESS_DENIED: status.HTTP_403_FORBIDDEN,
    ErrorCode.ACCOUNT_SUSPENDED: status.HTTP_403_FORBIDDEN,
    ErrorCode.ACCOUNT_LOCKED: status.HTTP_403_FORBIDDEN,
    ErrorCode.BREAK_GLASS_REQUIRED: status.HTTP_403_FORBIDDEN,
    ErrorCode.READ_ONLY_ROLE: status.HTTP_403_FORBIDDEN,
    # 404 / 405
    ErrorCode.RESOURCE_NOT_FOUND: status.HTTP_404_NOT_FOUND,
    ErrorCode.ENDPOINT_NOT_FOUND: status.HTTP_404_NOT_FOUND,
    ErrorCode.METHOD_NOT_ALLOWED: status.HTTP_405_METHOD_NOT_ALLOWED,
    # 409
    ErrorCode.DUPLICATE_RESOURCE: status.HTTP_409_CONFLICT,
    ErrorCode.CONFLICT: status.HTTP_409_CONFLICT,
    ErrorCode.STALE_RESOURCE: status.HTTP_409_CONFLICT,
    ErrorCode.INVALID_STATE_TRANSITION: status.HTTP_409_CONFLICT,
    ErrorCode.RESOURCE_IN_USE: status.HTTP_409_CONFLICT,
    ErrorCode.TASK_ALREADY_COMPLETED: status.HTTP_409_CONFLICT,
    # 413 / 415
    ErrorCode.FILE_TOO_LARGE: status.HTTP_413_CONTENT_TOO_LARGE,
    ErrorCode.UNSUPPORTED_MEDIA_TYPE: status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
    # 422
    ErrorCode.BUSINESS_RULE_VIOLATION: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.CAPACITY_EXCEEDED: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.COMPOSITION_INVALID: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.QUANTITY_EXCEEDS_LOAD: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.FACILITY_NOT_CAPABLE: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.INSUFFICIENT_DATA: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.UNSUPPORTED_WASTE_CATEGORY: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.CONFIDENCE_BELOW_THRESHOLD: status.HTTP_422_UNPROCESSABLE_CONTENT,
    ErrorCode.HARD_CONSTRAINT_UNSATISFIABLE: status.HTTP_422_UNPROCESSABLE_CONTENT,
    # 429 / 451
    ErrorCode.RATE_LIMIT_EXCEEDED: status.HTTP_429_TOO_MANY_REQUESTS,
    ErrorCode.LEGAL_HOLD: 451,
    # 5xx
    ErrorCode.INTERNAL_ERROR: status.HTTP_500_INTERNAL_SERVER_ERROR,
    ErrorCode.COMPUTATION_ERROR: status.HTTP_500_INTERNAL_SERVER_ERROR,
    ErrorCode.EXTERNAL_PROVIDER_ERROR: status.HTTP_502_BAD_GATEWAY,
    ErrorCode.DEPENDENCY_UNAVAILABLE: status.HTTP_503_SERVICE_UNAVAILABLE,
    ErrorCode.CIRCUIT_OPEN: status.HTTP_503_SERVICE_UNAVAILABLE,
    ErrorCode.MAINTENANCE_MODE: status.HTTP_503_SERVICE_UNAVAILABLE,
    ErrorCode.TIMEOUT: status.HTTP_504_GATEWAY_TIMEOUT,
    ErrorCode.SOLVER_TIMEOUT: status.HTTP_504_GATEWAY_TIMEOUT,
}

#: Client-safe default message per code. Internal codes deliberately carry a
#: vague message so an implementation detail can never be inferred from it.
DEFAULT_MESSAGES: dict[ErrorCode, str] = {
    ErrorCode.INTERNAL_ERROR: "An unexpected error occurred.",
    ErrorCode.COMPUTATION_ERROR: "The calculation could not be completed.",
    ErrorCode.EXTERNAL_PROVIDER_ERROR: ("An external service returned an unexpected response."),
    ErrorCode.DEPENDENCY_UNAVAILABLE: "A required service is temporarily unavailable.",
    ErrorCode.CIRCUIT_OPEN: ("The provider is temporarily disabled after repeated failures."),
    ErrorCode.MAINTENANCE_MODE: "The platform is in maintenance mode.",
    ErrorCode.TIMEOUT: "The operation exceeded its time budget.",
    ErrorCode.SOLVER_TIMEOUT: (
        "Optimization reached the time limit; the best solution found is returned "
        "and is marked as not proven optimal."
    ),
}

#: Keys that must never appear in ``details``, matched case-insensitively.
_FORBIDDEN_DETAIL_KEYS = frozenset(
    {
        "password",
        "password_hash",
        "passwd",
        "secret",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "api_key",
        "apikey",
        "jwt_secret_key",
        "cookie",
        "set-cookie",
        "smtp_password",
        "s3_secret_access_key",
        "llm_api_key",
        "private_key",
        "traceback",
        "sql",
        "query",
    }
)

_REDACTED = "[redacted]"
_MAX_DETAIL_DEPTH = 4
_MAX_DETAIL_ITEMS = 100
_MAX_DETAIL_STRING = 500


def _sanitise(value: Any, *, depth: int = 0) -> Any:
    """
    Convert an arbitrary value into something safe to serialise to a client.

    Unknown objects are replaced by their type name rather than their ``repr``,
    because a repr of a database row or connection object can disclose internal
    structure. Strings are length-capped so a response cannot be used as an
    exfiltration channel.
    """
    if depth >= _MAX_DETAIL_DEPTH:
        return "[truncated]"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return value if len(value) <= _MAX_DETAIL_STRING else value[:_MAX_DETAIL_STRING] + "…"
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        out: dict[str, Any] = {}
        for index, (key, item) in enumerate(value.items()):
            if index >= _MAX_DETAIL_ITEMS:
                out["_truncated"] = True
                break
            key_str = str(key)
            if key_str.lower() in _FORBIDDEN_DETAIL_KEYS:
                out[key_str] = _REDACTED
            else:
                out[key_str] = _sanitise(item, depth=depth + 1)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_sanitise(item, depth=depth + 1) for item in list(value)[:_MAX_DETAIL_ITEMS]]
    # Anything else (exceptions, ORM objects, clients, sockets) is described by
    # type only — never by repr.
    return f"<{type(value).__name__}>"


@dataclass(slots=True)
class ErrorDetail:
    """A single field-level validation problem, safe to bind to a form input."""

    field: str
    message: str
    type: str = "value_error"

    def as_dict(self) -> dict[str, str]:
        return {"field": self.field, "message": self.message, "type": self.type}


@dataclass(slots=True)
class AppError(Exception):
    """
    Base class for every deliberately raised API error.

    Services raise these; a single handler converts them to the error envelope.
    Raising anything else is treated as a bug and surfaces as ``INTERNAL_ERROR``
    with the cause logged server-side.
    """

    code: ErrorCode
    message: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    #: Optional Retry-After hint (seconds) for 429/503 responses.
    retry_after_seconds: int | None = None
    #: Optional list of machine-readable warnings (e.g. partial acceptance).
    warnings: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.message is None:
            self.message = DEFAULT_MESSAGES.get(
                self.code, self.code.value.replace("_", " ").capitalize()
            )
        # Exception.__init__ is called explicitly so the message is visible to
        # loggers and tracebacks even though this is a dataclass.
        Exception.__init__(self, self.message)
        self.details = dict(_sanitise(self.details) or {})

    @property
    def status_code(self) -> int:
        return ERROR_STATUS[self.code]

    def to_payload(self, request_id: str, timestamp: str) -> dict[str, Any]:
        """Serialise to the documented envelope body."""
        error: dict[str, Any] = {
            "code": self.code.value,
            "message": self.message,
            "details": self.details,
            "request_id": request_id,
            "timestamp": timestamp,
        }
        if self.warnings:
            error["warnings"] = list(self.warnings)
        return {"error": error}


# ---------------------------------------------------------------------------
# Convenience subclasses
# ---------------------------------------------------------------------------
class AuthenticationError(AppError):
    """401 — credentials missing, invalid, expired or revoked."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.AUTHENTICATION_REQUIRED,
        message: str | None = None,
        **details: Any,
    ) -> None:
        super().__init__(code=code, message=message, details=details)


class PermissionDeniedError(AppError):
    """403 — authenticated but not allowed."""

    def __init__(
        self,
        message: str | None = None,
        required_permissions: Sequence[str] | None = None,
        code: ErrorCode = ErrorCode.PERMISSION_DENIED,
        **details: Any,
    ) -> None:
        if required_permissions is not None:
            details["required_permissions"] = list(required_permissions)
        super().__init__(code=code, message=message, details=details)


class NotFoundError(AppError):
    """
    404 — the resource does not exist **or** is not visible to this tenant.

    The two cases deliberately share one code and one message so that a
    cross-tenant probe cannot distinguish "absent" from "forbidden"
    (master directive, section 12; ADR-0003).
    """

    def __init__(
        self,
        resource_type: str,
        resource_id: str | None = None,
        message: str | None = None,
    ) -> None:
        details: dict[str, Any] = {"resource_type": resource_type}
        if resource_id is not None:
            details["resource_id"] = resource_id
        super().__init__(
            code=ErrorCode.RESOURCE_NOT_FOUND,
            message=message or f"{resource_type.replace('_', ' ').capitalize()} not found",
            details=details,
        )


class ConflictError(AppError):
    """409 — state conflict, duplicate, or stale write."""

    def __init__(
        self,
        code: ErrorCode = ErrorCode.CONFLICT,
        message: str | None = None,
        **details: Any,
    ) -> None:
        super().__init__(code=code, message=message, details=details)


class InputValidationError(AppError):
    """400 — a request field failed validation outside the Pydantic layer."""

    def __init__(
        self, message: str, errors: Sequence[ErrorDetail] | None = None, **details: Any
    ) -> None:
        if errors:
            details["fields"] = [error.as_dict() for error in errors]
        super().__init__(code=ErrorCode.VALIDATION_ERROR, message=message, details=details)


class BusinessRuleError(AppError):
    """422 — a domain rule rejected the operation (BR-xx codes)."""

    def __init__(
        self,
        rule_code: str,
        message: str,
        code: ErrorCode = ErrorCode.BUSINESS_RULE_VIOLATION,
        **details: Any,
    ) -> None:
        details.setdefault("rule_code", rule_code)
        details.setdefault("rule_description", message)
        super().__init__(code=code, message=message, details=details)


class InsufficientDataError(AppError):
    """
    422 — honest refusal to compute.

    Required by BR-17: a metric with insufficient data must return an explicit
    reason, never a zero or an interpolation presented as a measurement.
    """

    def __init__(
        self,
        what_is_missing: str,
        required: int | str | None = None,
        available: int | str | None = None,
        **details: Any,
    ) -> None:
        details.setdefault("what_is_missing", what_is_missing)
        if required is not None:
            details.setdefault("required", required)
        if available is not None:
            details.setdefault("available", available)
        super().__init__(
            code=ErrorCode.INSUFFICIENT_DATA,
            message="There is not enough data to compute this reliably.",
            details=details,
        )


class RateLimitError(AppError):
    """429 — too many requests."""

    def __init__(self, limit: int, window_seconds: int, retry_after_seconds: int) -> None:
        super().__init__(
            code=ErrorCode.RATE_LIMIT_EXCEEDED,
            message="Too many requests. Please retry later.",
            details={"limit": limit, "window_seconds": window_seconds},
            retry_after_seconds=retry_after_seconds,
        )


class DependencyUnavailableError(AppError):
    """
    503 — a dependency the request needs is down.

    ``dependency`` names the component (``database``, ``cache``, ``solver``,
    ``model``) so an operator can act without reading the logs.
    """

    def __init__(
        self,
        dependency: str,
        message: str | None = None,
        retry_after_seconds: int | None = None,
        **details: Any,
    ) -> None:
        details.setdefault("dependency", dependency)
        super().__init__(
            code=ErrorCode.DEPENDENCY_UNAVAILABLE,
            message=message or f"The {dependency} is temporarily unavailable.",
            details=details,
            retry_after_seconds=retry_after_seconds,
        )


class ServiceTimeoutError(AppError):
    """504 — an operation exceeded its budget."""

    def __init__(self, timeout_seconds: float, message: str | None = None, **details: Any) -> None:
        details.setdefault("timeout_seconds", timeout_seconds)
        super().__init__(code=ErrorCode.TIMEOUT, message=message, details=details)


def problem(
    code: ErrorCode,
    message: str | None = None,
    **details: Any,
) -> AppError:
    """Construct an :class:`AppError` for any code, with sanitised details."""
    return AppError(code=code, message=message, details=details)
