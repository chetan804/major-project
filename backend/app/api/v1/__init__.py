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

__all__ = ["api_v1_router"]

api_v1_router = APIRouter()
