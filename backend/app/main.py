"""
Application factory and lifespan.

Run locally with::

    uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload

The factory pattern (rather than a module-level ``app`` built at import time) is
what makes the application testable: a test can construct an app bound to an
isolated database and a fresh in-process cache, without re-importing modules or
mutating global state that another test depends on. The module-level ``app``
object at the bottom exists purely as the uvicorn entry point.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.utils import get_openapi

from app.api.errors import register_exception_handlers
from app.api.health import router as system_router
from app.api.v1 import api_v1_router
from app.core.cache import init_cache, reset_cache
from app.core.config import Settings, get_settings
from app.core.logging import configure_logging, get_logger
from app.core.metrics import get_metrics
from app.core.middleware import (
    ErrorEnvelopeMiddleware,
    RequestContextMiddleware,
    SecurityHeadersMiddleware,
)
from app.db.session import init_database, reset_database

logger = get_logger(__name__)

API_DESCRIPTION = """
EcoMind-AI is an environmental intelligence platform that converts
waste-management data into operational decisions.

It covers the operational lifecycle end to end: telemetry ingestion, bin
monitoring, collection planning, route optimisation, driver execution,
facility processing, material recovery, carbon estimation, forecasting,
anomaly detection and reporting.

**Conventions**

* All endpoints are versioned under `/api/v1`.
* Timestamps are ISO-8601 in UTC. Tenant-local conversion happens in the UI.
* Measured quantities are exact decimals, never floating point.
* Values that are not directly measured carry an explicit provenance label:
  `MEASURED`, `ESTIMATED`, `PREDICTED`, `SIMULATED`, `USER_ENTERED` or
  `DERIVED`. Simulated development data is labelled as such and is never
  presented as live operational data.
* Errors use a single envelope; the `request_id` in the body also appears in the
  `X-Request-ID` response header and in the server logs.
* Cross-tenant access returns `404`, not `403`, so resource existence is never
  disclosed.
"""


def _configure_lifespan(app: FastAPI) -> None:  # pragma: no cover - wiring only
    """Attach the startup/shutdown lifespan to ``app``."""

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        settings: Settings = app.state.settings

        configure_logging(settings, force=True)

        # Fail fast and completely: report every configuration problem at once
        # so an operator fixes one deploy, not one problem per restart.
        problems = settings.validate_for_startup()
        if problems:
            for problem in problems:
                logger.error("configuration_problem", problem=problem)
            raise RuntimeError(
                "Refusing to start with an invalid configuration:\n  - " + "\n  - ".join(problems)
            )

        # Both initialisers adopt a handle that a harness or embedding process has
        # already bound, and build one from these settings only if nothing is
        # bound. That is what lets the test suite supply a NullPool database, and
        # it means the app records exactly the resources it is actually using.
        app.state.database = init_database(
            settings.database_url,
            pool_size=settings.db_pool_size,
            max_overflow=settings.db_max_overflow,
            pool_recycle_seconds=settings.db_pool_recycle_seconds,
            echo=settings.db_echo,
        )
        app.state.cache = init_cache(settings)

        get_metrics().app_info.labels(
            version=settings.app_version, environment=settings.environment
        ).set(1)

        adapter_summary = settings.adapter_summary()
        simulated = sorted(
            name
            for name, info in adapter_summary.items()
            if isinstance(info, dict) and info.get("is_simulated")
        )
        logger.info(
            "application_started",
            version=settings.app_version,
            environment=settings.environment,
            simulated_components=simulated or None,
        )
        if simulated:
            # Stated once, prominently, at every startup. A reader must never have
            # to infer that part of the running system is simulated (ADR-0013).
            logger.warning(
                "simulated_components_active",
                components=simulated,
                note=(
                    "These components are development adapters or simulators. "
                    "Data they produce is labelled accordingly in API responses "
                    "and in the UI."
                ),
            )

        try:
            yield
        finally:
            from app.core.cache import get_cache
            from app.db.session import get_database

            await get_cache().close()
            await get_database().dispose()
            reset_database()
            reset_cache()
            logger.info("application_stopped")

    app.router.lifespan_context = lifespan


def create_app(settings: Settings | None = None) -> FastAPI:
    """
    Build and return a configured FastAPI application.

    ``settings`` defaults to the process-wide cached settings; tests pass an
    explicit instance to bind an isolated configuration.
    """
    resolved = settings or get_settings()

    app = FastAPI(
        title=resolved.app_name,
        description=API_DESCRIPTION,
        version=resolved.app_version,
        docs_url="/docs",
        # ReDoc is disabled: one interactive console is enough, and every extra
        # documentation surface is an extra thing to keep patched.
        redoc_url=None,
        openapi_url="/openapi.json",
        lifespan=None,
        contact={"name": "EcoMind-AI"},
        license_info={"name": "Proprietary"},
    )
    app.state.settings = resolved

    _configure_lifespan(app)

    # -----------------------------------------------------------------------
    # Middleware. add_middleware inserts at the front of the stack, so the LAST
    # call is the OUTERMOST layer. The resulting order, outermost first, is:
    #
    #   RequestContext → SecurityHeaders → CORS → ErrorEnvelope → routing
    #
    # ErrorEnvelope is innermost of the custom layers so that the response it
    # generates still travels back out through CORS, the security headers and
    # the request context, and therefore carries the complete header set.
    # -----------------------------------------------------------------------
    app.add_middleware(ErrorEnvelopeMiddleware, debug=resolved.debug)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=resolved.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        # Exposed so browser code can read the correlation id and honour a
        # rate-limit backoff without a second round trip.
        expose_headers=[resolved.request_id_header, "Retry-After"],
        max_age=600,
    )
    app.add_middleware(
        SecurityHeadersMiddleware,
        enabled=resolved.security_headers_enabled,
        hsts_enabled=resolved.hsts_enabled,
    )
    app.add_middleware(RequestContextMiddleware, settings=resolved)

    register_exception_handlers(app)

    app.include_router(system_router)
    app.include_router(api_v1_router, prefix=resolved.api_v1_prefix)

    _install_openapi(app, resolved)
    return app


def _install_openapi(app: FastAPI, settings: Settings) -> None:
    """Attach a custom OpenAPI generator so the schema is self-describing."""

    def custom_openapi() -> dict[str, Any]:
        if app.openapi_schema:
            return app.openapi_schema
        schema = get_openapi(
            title=app.title,
            version=app.version,
            description=app.description,
            routes=app.routes,
        )
        schema.setdefault("info", {})["x-environment"] = settings.environment
        schema["info"]["x-api-version"] = "v1"
        # Documented once here so clients can discover the correlation contract
        # without reading the prose description.
        schema.setdefault("components", {}).setdefault("headers", {})["RequestId"] = {
            "description": (
                "Correlation id for this request. Quote it in a support request; "
                "it identifies the exact server log line."
            ),
            "schema": {"type": "string", "example": "9f4c1a2b7d8e4f6a9b3c5d7e8f1a2b3c"},
        }
        app.openapi_schema = schema
        return schema

    app.openapi = custom_openapi  # type: ignore[method-assign]


#: uvicorn entry point. Tests should call :func:`create_app` instead so they can
#: inject an isolated database and cache.
app = create_app()
