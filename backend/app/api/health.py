"""
Liveness, readiness and metrics endpoints.

These routes live at the **root** (``/health``, ``/ready``, ``/metrics``) rather
than under ``/api/v1``: orchestrators, load balancers and Prometheus scrapers
expect stable, unversioned probe paths, and moving them when the API version
changes would break every deployment.

Semantics are deliberately distinct — conflating them is how a rolling deploy
takes down a healthy service:

``/health``  (liveness)
    "Is this process able to serve?" It performs **no** I/O. If it depended on
    the database, a brief database blip would cause the orchestrator to kill
    every API container at once, turning a recoverable dependency outage into a
    total failure.

``/ready``  (readiness)
    "Should this instance receive traffic?" It probes the database and the
    cache. A database failure returns ``503`` so the instance is removed from
    rotation; a cache failure is reported but still returns ``200``, because the
    cache is an optimisation and the application is designed to serve correctly
    without it (section 67).

``/metrics``
    Prometheus exposition. Restrict this path at the reverse proxy in
    production; the value is operational telemetry, not public information.
"""

from __future__ import annotations

import time
from typing import Any

from fastapi import APIRouter, Response, status
from fastapi.responses import PlainTextResponse

from app.api.deps import CacheDep, DatabaseDep, SettingsDep
from app.core.cache import Cache, CacheHealth
from app.core.config import Settings
from app.core.metrics import get_metrics
from app.core.time import isoformat_utc, utc_now

router = APIRouter(tags=["system"])

#: Process start time, used to report uptime. Read-only after import.
_PROCESS_STARTED_AT = time.time()


def _base_payload(settings: Settings) -> dict[str, Any]:
    return {
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
        "uptime_seconds": round(time.time() - _PROCESS_STARTED_AT, 3),
        "timestamp": isoformat_utc(utc_now()),
    }


@router.get(
    "/health",
    summary="Liveness probe",
    description=(
        "Reports that the process is running and which adapter implementation "
        "backs each pluggable component. Performs no I/O, so a dependency "
        "outage cannot cause the orchestrator to restart healthy containers."
    ),
    responses={200: {"description": "The process is alive."}},
)
async def health(settings: SettingsDep) -> dict[str, Any]:
    """
    Liveness plus an adapter inventory.

    The adapter block is included here rather than only in logs so that any
    reader — a reviewer, an operator, an auditor — can see at a glance whether
    the running system is backed by real infrastructure or by a development
    adapter, and cannot mistake one for the other (ADR-0013).
    """
    return {
        **_base_payload(settings),
        "status": "ok",
        "adapters": settings.adapter_summary(),
    }


@router.get(
    "/ready",
    summary="Readiness probe",
    description=(
        "Probes the database and cache. Returns 503 when the database is "
        "unreachable so the instance is drained from rotation. A cache failure "
        "is reported as degraded but still returns 200, because the cache is an "
        "optimisation and requests are designed to succeed without it."
    ),
    responses={
        200: {"description": "Ready to serve traffic (possibly with warnings)."},
        503: {"description": "A required dependency is unavailable."},
    },
)
async def ready(
    settings: SettingsDep,
    database: DatabaseDep,
    cache: CacheDep,
    response: Response,
) -> dict[str, Any]:
    """
    Dependency health with an honest status and explicit reasons.

    The outcome is never a bare boolean: each dependency reports its own state,
    and ``warnings`` names anything a reader should not overlook — including the
    case where the database is reachable but older than the minimum supported
    version.
    """
    warnings: list[str] = []

    db_health = await database.health()
    checks: dict[str, Any] = {"database": db_health.as_dict()}

    if not db_health.reachable:
        warnings.append(
            "The database is unreachable. Requests that require persistence will "
            "fail with DEPENDENCY_UNAVAILABLE."
        )
    elif not db_health.supported:
        warnings.append(
            "The PostgreSQL server is older than the minimum supported version; "
            "schema features such as gen_random_uuid() may be unavailable."
        )

    cache_health = await _safe_cache_health(cache)
    checks["cache"] = cache_health.as_dict()
    if not cache_health.reachable:
        warnings.append(
            "The cache is unreachable. The service continues to operate without "
            "caching; latency may increase."
        )
    if cache_health.is_simulated:
        warnings.append(
            "The cache is backed by the in-process 'fakeredis' development "
            "adapter, not a real Redis server. Do not use this configuration in "
            "production."
        )

    if settings.redis_adapter == "fakeredis" or settings.job_runner == "inline":
        checks["deployment_adapters"] = settings.adapter_summary()

    healthy = db_health.reachable
    if not healthy:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        **_base_payload(settings),
        "status": "ok" if healthy else "degraded",
        "checks": checks,
        "warnings": warnings,
    }


async def _safe_cache_health(cache: Cache) -> CacheHealth:
    try:
        return await cache.health()
    except Exception as exc:
        return CacheHealth(
            backend=getattr(cache.backend, "name", "unknown"),
            is_simulated=getattr(cache.backend, "is_simulated", False),
            reachable=False,
            detail=type(exc).__name__,
        )


@router.get(
    "/metrics",
    summary="Prometheus metrics",
    description=(
        "Prometheus text exposition of HTTP and dependency metrics. Restrict "
        "this endpoint at the reverse proxy in production."
    ),
    response_class=PlainTextResponse,
    include_in_schema=True,
)
async def metrics(settings: SettingsDep) -> PlainTextResponse:
    if not settings.metrics_enabled:
        return PlainTextResponse(
            "# metrics are disabled (METRICS_ENABLED=false)\n",
            status_code=200,
        )

    # Refresh dependency gauges at scrape time so Prometheus sees current state
    # rather than the value recorded at the last probe.
    metrics_instance = get_metrics()
    metrics_instance.app_info.labels(
        version=settings.app_version, environment=settings.environment
    ).set(1)

    payload = metrics_instance.render()
    return PlainTextResponse(
        payload,
        headers={"Content-Type": "text/plain; version=1.0.0; charset=utf-8"},
    )
