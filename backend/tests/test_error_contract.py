"""
The error contract.

``docs/api/error-catalogue.md`` is a promise to API consumers. These tests hold
the implementation to the parts of that promise which are easy to break
silently: the envelope shape, the status mapping, and — most importantly — that
nothing internal leaks into a response.
"""

from __future__ import annotations

import pytest

from app.core.errors import (
    ERROR_STATUS,
    AppError,
    BusinessRuleError,
    ErrorCode,
    InsufficientDataError,
    NotFoundError,
    PermissionDeniedError,
)

pytestmark = pytest.mark.api


async def test_unknown_endpoint_returns_the_error_envelope(client) -> None:
    response = await client.get("/api/v1/does-not-exist")

    assert response.status_code == 404
    body = response.json()
    assert set(body) == {"error"}
    error = body["error"]
    assert set(error) == {"code", "message", "details", "request_id", "timestamp"}
    assert error["code"] == "ENDPOINT_NOT_FOUND"
    assert error["request_id"]
    assert error["timestamp"].endswith("Z")


async def test_wrong_method_is_reported_as_such(client) -> None:
    response = await client.post("/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "METHOD_NOT_ALLOWED"


async def test_request_id_in_body_matches_response_header(client) -> None:
    """
    The correlation id must be identical in the body, the header and the logs.

    A mismatch would make the quoted ``request_id`` useless for support, so the
    two are asserted together rather than separately.
    """
    response = await client.get("/api/v1/nope")

    assert response.json()["error"]["request_id"] == response.headers["x-request-id"]


async def test_no_internal_detail_leaks_in_an_error(client) -> None:
    """
    A client-visible error must disclose nothing about the implementation.

    Rather than checking for one specific string, this asserts the absence of a
    class of disclosures: no traceback text, no SQL, no file paths, no exception
    type names, and no configuration values.
    """
    body = (await client.get("/api/v1/nope")).text.lower()

    for forbidden in (
        "traceback",
        "sqlalchemy",
        "select ",
        "postgresql",
        "asyncpg",
        "/home/",
        "/usr/",
        ".py",
        "jwt_secret",
        "password",
        "exception",
    ):
        assert forbidden not in body, f"error response leaked {forbidden!r}"


# ---------------------------------------------------------------------------
# Unit-level: the catalogue itself
# ---------------------------------------------------------------------------
def test_every_error_code_has_an_http_status() -> None:
    """
    The catalogue must be complete.

    A code without a status mapping would raise ``KeyError`` at the moment of the
    failure — turning a handled error into a 500 precisely when the system is
    already in trouble.
    """
    missing = [code for code in ErrorCode if code not in ERROR_STATUS]
    assert not missing, f"error codes without a status mapping: {missing}"


def test_error_status_codes_are_valid_and_grouped_correctly() -> None:
    """Statuses must be real HTTP codes, and the client/server split must hold."""
    server_codes = {
        ErrorCode.INTERNAL_ERROR,
        ErrorCode.COMPUTATION_ERROR,
        ErrorCode.EXTERNAL_PROVIDER_ERROR,
        ErrorCode.DEPENDENCY_UNAVAILABLE,
        ErrorCode.CIRCUIT_OPEN,
        ErrorCode.MAINTENANCE_MODE,
        ErrorCode.TIMEOUT,
        ErrorCode.SOLVER_TIMEOUT,
    }

    for code, status in ERROR_STATUS.items():
        assert 400 <= status <= 599, f"{code} maps to a non-error status {status}"
        if code in server_codes:
            assert status >= 500, f"{code} should be a 5xx"
        else:
            assert status < 500, f"{code} should be a 4xx"


def test_details_are_sanitised() -> None:
    """
    ``details`` must be safe to serialise and must never carry credentials.

    The sanitisation is performed in ``AppError.__post_init__``, so it applies to
    every raised error regardless of who constructed it.
    """
    error = AppError(
        code=ErrorCode.BUSINESS_RULE_VIOLATION,
        details={
            "password": "super-secret",
            "refresh_token": "abc.def.ghi",
            "api_key": "key-123",
            "bin_id": "1e3a5c7b-0000-0000-0000-000000000000",
            "count": 3,
            "nested": {"secret": "shh", "kept": "visible"},
        },
    )

    assert error.details["password"] == "[redacted]"
    assert error.details["refresh_token"] == "[redacted]"
    assert error.details["api_key"] == "[redacted]"
    assert error.details["nested"]["secret"] == "[redacted]"
    assert error.details["nested"]["kept"] == "visible"
    assert error.details["bin_id"] == "1e3a5c7b-0000-0000-0000-000000000000"
    assert error.details["count"] == 3


def test_unknown_objects_are_described_by_type_only() -> None:
    """
    An internal object must be described by its type, never by its ``repr``.

    A repr of a database row or connection can disclose internal structure, and
    exceptions can carry connection strings in their message.
    """

    class Sensitive:
        def __repr__(self) -> str:
            return "Sensitive(password='leaked-in-repr')"

    error = AppError(code=ErrorCode.INTERNAL_ERROR, details={"obj": Sensitive()})

    assert error.details["obj"] == "<Sensitive>"
    assert "leaked-in-repr" not in str(error.details)


def test_not_found_is_indistinguishable_from_forbidden_but_absent() -> None:
    """
    Cross-tenant probes must not be able to distinguish absent from forbidden.

    ADR-0003 requires a ``404`` with no hint that the resource exists in another
    tenant, and no mention of tenancy at all.
    """
    error = NotFoundError(resource_type="bin", resource_id="abc")

    assert error.status_code == 404
    assert error.code is ErrorCode.RESOURCE_NOT_FOUND
    assert "bin" in error.message.lower()
    assert "tenant" not in error.message.lower()
    assert "permission" not in error.message.lower()


def test_retry_after_is_surfaced_for_rate_limited_responses() -> None:
    from app.core.errors import RateLimitError

    error = RateLimitError(limit=100, window_seconds=60, retry_after_seconds=30)

    assert error.status_code == 429
    assert error.retry_after_seconds == 30


def test_permission_error_names_the_permissions_required() -> None:
    """
    A ``403`` for a multi-endpoint permission should say what was missing.

    Naming the permission is safe (a caller cannot use it to escalate) and turns
    an opaque denial into an actionable message.
    """
    error = PermissionDeniedError(required_permissions=["bins.write", "bins.delete"])

    assert error.status_code == 403
    assert error.details["required_permissions"] == ["bins.write", "bins.delete"]


def test_insufficient_data_reports_what_is_missing() -> None:
    """
    BR-17: missing data must produce an explicit reason, never a zero.

    The error carries the counts so a UI can say "3 of 20 bins instrumented"
    rather than showing a misleading figure.
    """
    error = InsufficientDataError(what_is_missing="telemetry history", required=14, available=3)

    assert error.status_code == 422
    assert error.code is ErrorCode.INSUFFICIENT_DATA
    assert error.details["what_is_missing"] == "telemetry history"
    assert error.details["required"] == 14
    assert error.details["available"] == 3


def test_business_rule_error_carries_the_rule_identifier() -> None:
    """A rule violation cites the numbered rule from the domain model."""
    error = BusinessRuleError(
        rule_code="BR-06",
        message="Planned load exceeds the vehicle capacity.",
        capacity_kg="10000",
        planned_kg="12500",
    )

    assert error.status_code == 422
    assert error.details["rule_code"] == "BR-06"
    assert error.details["capacity_kg"] == "10000"
