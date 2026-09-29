"""The published contract must describe the classified live API, not phantom routes."""

import pytest

from app.api.route_policy import mounted_surface, policy_exceptions
from app.main import create_app

pytestmark = pytest.mark.api


def test_openapi_matches_live_surface_and_authentication(test_settings):
    app = create_app(test_settings)
    schema = app.openapi()
    public, _ = policy_exceptions(test_settings.api_v1_prefix)
    mounted = {
        (method.lower(), s.path)
        for s in mounted_surface(app)
        for method in s.methods
        if s.include_in_schema and s.path.startswith(test_settings.api_v1_prefix)
    }
    documented = {
        (method, path)
        for path, methods in schema["paths"].items()
        for method in methods
        if method in {"get", "post", "put", "patch", "delete", "head", "options"}
        and path.startswith(test_settings.api_v1_prefix)
    }
    assert mounted == documented and len(mounted) == 60
    assert not any("break-glass" in path for _, path in documented)
    for method, path in mounted:
        operation = schema["paths"][path][method]
        assert bool(operation.get("security")) is ((method.upper(), path) not in public)
        for status in ("400", "401", "403", "422", "429", "500", "503"):
            assert (
                operation["responses"][status]["content"]["application/json"]["schema"]["$ref"]
                == "#/components/schemas/ErrorEnvelope"
            )
        if "requestBody" in operation:
            body = operation["requestBody"]["content"].get("application/json", {}).get("schema", {})
            if "$ref" in body:
                definition = schema["components"]["schemas"][body["$ref"].rsplit("/", 1)[1]]
                assert definition["additionalProperties"] is False, (method, path)


async def test_live_validation_and_authentication_errors_match_published_envelope(client):
    from app.api.schemas.errors import ErrorEnvelope

    for method, path, payload, status in (
        ("POST", "/api/v1/auth/login", {}, 400),
        ("GET", "/api/v1/auth/me", None, 401),
        ("GET", "/api/v1/missing", None, 404),
    ):
        response = await client.request(
            method, path, **({"json": payload} if payload is not None else {})
        )
        assert response.status_code == status
        parsed = ErrorEnvelope.model_validate(response.json())
        assert parsed.error.request_id == response.headers["x-request-id"]
