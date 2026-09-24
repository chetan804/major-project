"""
Security headers and CORS behaviour.

Headers are asserted on both a successful and a failing response: a hardening
header that is applied only on the happy path is worse than useless, because the
responses most likely to be probed are the error ones.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.security

EXPECTED_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "strict-origin-when-cross-origin",
    "cross-origin-opener-policy": "same-origin",
    "cross-origin-resource-policy": "same-site",
}


async def test_security_headers_present_on_success(client) -> None:
    response = await client.get("/health")

    for header, expected in EXPECTED_HEADERS.items():
        assert response.headers.get(header) == expected, f"missing or wrong {header}"


async def test_security_headers_present_on_error_responses(client) -> None:
    """
    Error responses must carry the same hardening.

    This is the case that catches a middleware-ordering mistake: if the error
    envelope were generated *outside* the security-header layer, its response
    would pass back without them.
    """
    response = await client.get("/api/v1/definitely-not-real")

    assert response.status_code == 404
    for header, expected in EXPECTED_HEADERS.items():
        assert response.headers.get(header) == expected, f"missing or wrong {header}"


async def test_hsts_absent_when_disabled(client) -> None:
    """
    HSTS must not be sent over plain HTTP in development.

    Sending it would pin a developer's browser to HTTPS for localhost and break
    their environment for a year.
    """
    response = await client.get("/health")
    assert "strict-transport-security" not in response.headers


async def test_permissions_policy_denies_microphone(client) -> None:
    """
    Unused capabilities are denied by default.

    A waste-management console has no business requesting audio, and an explicit
    denial documents that intent.
    """
    policy = (await client.get("/health")).headers["permissions-policy"]

    assert "microphone=()" in policy


async def test_cors_allows_configured_origin(client) -> None:
    """The configured frontend origin receives an allow-origin header."""
    response = await client.options(
        "/health",
        headers={
            "Origin": "http://localhost:5173",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers.get("access-control-allow-origin") == "http://localhost:5173"
    assert response.headers.get("access-control-allow-credentials") == "true"


async def test_cors_rejects_unconfigured_origin(client) -> None:
    """
    An origin outside the allow-list must not be granted access.

    Starlette omits the allow-origin header rather than returning a specific
    error, so the assertion is on the absence of the grant.
    """
    response = await client.options(
        "/health",
        headers={
            "Origin": "https://evil.example.com",
            "Access-Control-Request-Method": "GET",
        },
    )

    assert response.headers.get("access-control-allow-origin") is None
