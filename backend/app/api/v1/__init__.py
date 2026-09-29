"""
Version 1 API router.

Every feature router is registered here so the mounted surface of ``/api/v1`` is
visible in one place. Phase 1 establishes the aggregator and the system routes;
feature routers are added by the phases that implement them:

* Phase 2  — ``auth``, ``users``, ``tenants``, ``roles``
* Phase 3  — ``bins``, ``zones``, ``vehicles``, ``drivers``, ``facilities``
* Phase 4  — ``telemetry``, ``alerts``
* Phase 5  — ``collections``
* Phase 6  — ``routes``
* Phase 7  — ``analytics``
* Phase 8  — ``forecasts``, ``anomalies``, ``waste`` (classification)
* Phase 9  — ``assistant``, ``recommendations``
* Phase 10 — ``waste-loads``, ``recovery``
* Phase 11 — ``reports``, ``notifications``

A route inventory test (``tests/architecture/test_route_inventory.py``) fails the
build if a router is defined but never mounted, which is how a dead navigation
target (section 19) is prevented rather than noticed later.
"""

from __future__ import annotations

from fastapi import APIRouter

from app.api.v1 import (
    api_keys,
    auth,
    platform_mfa,
    platform_operators,
    platform_step_up,
    platform_tenants,
    roles,
    security_administration,
    tenants,
    users,
)

__all__ = ["api_v1_router"]

api_v1_router = APIRouter()

# Authentication is mounted first because every other router depends on the actor
# it produces. Later phases add their routers here in the order the phase plan
# lists them.
api_v1_router.include_router(auth.router)

api_v1_router.include_router(users.router)
api_v1_router.include_router(roles.router)
api_v1_router.include_router(tenants.router)

api_v1_router.include_router(security_administration.router)

api_v1_router.include_router(api_keys.router)

api_v1_router.include_router(platform_tenants.router)


api_v1_router.include_router(platform_step_up.router)

api_v1_router.include_router(platform_mfa.router)

api_v1_router.include_router(platform_operators.router)
