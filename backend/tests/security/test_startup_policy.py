"""Production startup policy, including surfaces OpenAPI cannot see."""

from __future__ import annotations

from typing import Annotated

import pytest
from fastapi import APIRouter, Depends, WebSocket
from starlette.responses import Response

from app.api.deps import CurrentActor, require_permission
from app.api.route_policy import permission_dependencies, validate_route_policy
from app.main import create_app

pytestmark = [pytest.mark.security]


def check(app):
    return validate_route_policy(app, app.state.settings.api_v1_prefix)


def test_current_surface_has_exact_classification(test_settings):
    from app.api.route_policy import policy_exceptions

    app = create_app(test_settings)
    surfaces = check(app)
    public, own = policy_exceptions(test_settings.api_v1_prefix)
    versioned = [
        (method, s.path) for s in surfaces for method in s.methods if s.path.startswith("/api/v1/")
    ]
    assert len(versioned) == 60
    assert sum(op in public for op in versioned) == 6
    assert sum(op in own for op in versioned) == 8
    assert (
        sum(bool(permission_dependencies(s)[1]) for s in surfaces if s.path.startswith("/api/v1/"))
        == 46
    )


@pytest.mark.parametrize(
    "case",
    [
        "bare",
        "hidden",
        "auth_only",
        "endpoint_marker",
        "empty_permission",
        "unknown_permission",
        "fake_auth_marker",
    ],
)
def test_missing_or_misleading_guards_fail_closed(test_settings, case):
    app = create_app(test_settings)

    async def bare():
        return Response(status_code=204)

    async def auth_only(actor: CurrentActor):
        return Response(status_code=204)

    endpoint = auth_only if case in {"auth_only", "endpoint_marker"} else bare
    if case == "endpoint_marker":
        endpoint.__ecomind_permissions__ = ["users.read"]
    dependencies = []
    if case in {"empty_permission", "unknown_permission"}:
        dependencies = [
            Depends(
                require_permission(*([] if case == "empty_permission" else ["missing.permission"]))
            )
        ]
    if case == "fake_auth_marker":

        async def fake():
            return None

        fake.__ecomind_requires_authentication__ = True
        fake.__ecomind_permissions__ = ["users.read"]
        dependencies = [Depends(fake)]
    app.add_api_route(
        "/api/v1/probe",
        endpoint,
        methods=["GET"],
        dependencies=dependencies,
        include_in_schema=case != "hidden",
    )
    with pytest.raises(RuntimeError, match="refusing startup"):
        check(app)


@pytest.mark.parametrize("case", ["exact", "parameter_alias", "same_object"])
def test_shadowing_duplicate_registrations_are_refused(test_settings, case):
    app = create_app(test_settings)
    router = APIRouter(dependencies=[Depends(require_permission("users.read"))])

    async def endpoint():
        return Response(status_code=204)

    router.add_api_route("/{user_id}", endpoint, methods=["GET"])
    if case == "same_object":
        router.routes.append(router.routes[0])
    else:
        router.add_api_route(
            "/{other}" if case == "parameter_alias" else "/{user_id}", endpoint, methods=["GET"]
        )
    app.include_router(router, prefix="/api/v1/probe")
    with pytest.raises(RuntimeError, match="Duplicate"):
        check(app)


def test_include_time_nested_dependencies_and_hidden_routes_are_inspected(test_settings):
    app = create_app(test_settings)
    leaf = APIRouter()

    @leaf.get("/private", include_in_schema=False)
    async def endpoint():
        return Response(status_code=204)

    middle = APIRouter()
    middle.include_router(
        leaf, prefix="/nested", dependencies=[Depends(require_permission("users.read"))]
    )
    app.include_router(middle, prefix="/api/v1/probe")
    surface = next(s for s in check(app) if s.path == "/api/v1/probe/nested/private")
    authenticated, guards = permission_dependencies(surface)
    assert authenticated and guards and not surface.include_in_schema
    assert surface.path not in app.openapi()["paths"]


@pytest.mark.parametrize("case", ["mount", "websocket", "nested_websocket"])
def test_unreviewed_transports_are_not_silently_skipped(test_settings, case):
    app = create_app(test_settings)
    if case == "mount":

        async def asgi(scope, receive, send):
            pass

        app.mount("/unchecked", asgi)
    else:
        router = APIRouter()

        @router.websocket("/socket")
        async def websocket(websocket: WebSocket):
            await websocket.close()

        if case == "nested_websocket":
            app.include_router(router, prefix="/nested")
        else:
            app.router.routes.extend(router.routes)
    with pytest.raises(RuntimeError, match=r"[Ww]eb[Ss]ocket|Uninspectable"):
        check(app)


def test_nondefault_api_prefix_is_supported(test_settings):
    test_settings.api_v1_prefix = "/api/review"
    app = create_app(test_settings)
    assert any(s.path == "/api/review/auth/me" for s in check(app))


@pytest.mark.parametrize("method", ["HEAD", "OPTIONS"])
def test_standalone_methods_do_not_borrow_public_get_exception(test_settings, method):
    app = create_app(test_settings)

    async def endpoint():
        return Response(status_code=204)

    app.add_api_route("/health", endpoint, methods=[method])
    with pytest.raises(RuntimeError, match="declared permissions"):
        check(app)


def test_removed_exception_is_not_silently_retained(test_settings):
    app = create_app(test_settings)
    app.router.routes = [r for r in app.routes if getattr(r, "path", None) != "/docs"]
    with pytest.raises(RuntimeError, match="Stale"):
        check(app)


async def test_invalid_policy_aborts_actual_lifespan_before_resource_initialization(
    test_settings, monkeypatch
):
    app = create_app(test_settings)

    @app.get("/unprotected")
    async def endpoint():
        return {}

    def resources_must_not_open(*args, **kwargs):
        pytest.fail("Resource initialization happened before the route-policy guard")

    monkeypatch.setattr("app.main.init_database", resources_must_not_open)
    with pytest.raises(RuntimeError, match="refusing startup"):
        async with app.router.lifespan_context(app):
            pytest.fail("Startup must fail")


def test_permission_dependency_in_signature_is_inspected(test_settings):
    app = create_app(test_settings)

    async def endpoint(actor: Annotated[object, Depends(require_permission("users.read"))]):
        return {}

    app.add_api_route("/api/v1/probe", endpoint, methods=["GET"])
    assert any(s.path == "/api/v1/probe" for s in check(app))
