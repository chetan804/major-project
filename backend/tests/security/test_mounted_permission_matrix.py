"""All baseline roles x mounted permission gates, not a service/MFA bypass test.

The role table is separately checked against the reviewed markdown matrix. Here
actual mounted dependency callables run through FastAPI with a supplied actor;
only the final business handler is replaced by a sentinel. Real DB/resource/MFA
checks remain covered by the restricted-role integration suites.
"""

from __future__ import annotations

from uuid import UUID, uuid4

import httpx
import pytest
from fastapi import Depends, FastAPI
from starlette.responses import Response

from app.api.deps import get_current_actor
from app.api.errors import register_exception_handlers
from app.api.route_policy import mounted_surface, permission_dependencies, policy_exceptions
from app.authorization.context import Actor
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.main import create_app

pytestmark = pytest.mark.security

SURFACES = [
    s
    for s in mounted_surface(create_app())
    if s.path.startswith("/api/v1/") and permission_dependencies(s)[1]
]
CASES = [
    (role, surface, method)
    for role in ROLE_DEFINITIONS
    for surface in SURFACES
    for method in sorted(surface.methods)
]


@pytest.mark.parametrize(
    "role,surface,method", CASES, ids=[f"{role}:{method}:{s.path}" for role, s, method in CASES]
)
async def test_each_baseline_role_against_mounted_permission_gate(role, surface, method):
    _, guards = permission_dependencies(surface)
    required = {code for guard in guards for code in guard.__ecomind_permissions__}
    grants = ROLE_DEFINITIONS[role].permissions
    actor = Actor(
        user_id=uuid4(),
        tenant_id=UUID(int=0) if role == "SUPER_ADMIN" else uuid4(),
        email="matrix@example.test",
        full_name="Matrix actor",
        roles=frozenset({role}),
        permissions=grants,
        session_id=uuid4(),
        is_platform_operator=role == "SUPER_ADMIN",
    )
    app = FastAPI()
    register_exception_handlers(app)

    async def supplied_actor():
        return actor

    app.dependency_overrides[get_current_actor] = supplied_actor
    calls = []

    async def sentinel():
        calls.append(True)
        return Response(status_code=204)

    app.add_api_route(
        "/gate", sentinel, methods=[method], dependencies=[Depends(g) for g in guards]
    )
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://matrix"
    ) as client:
        response = await client.request(method, "/gate")
    allowed = required <= grants
    assert response.status_code == (204 if allowed else 403)
    assert bool(calls) is allowed


AUTHENTICATED = [
    (method, s.path)
    for s in mounted_surface(create_app())
    for method in s.methods
    if s.path.startswith("/api/v1/") and (method, s.path) not in policy_exceptions("/api/v1")[0]
]


@pytest.mark.parametrize("method,path", AUTHENTICATED)
async def test_every_authenticated_real_route_rejects_anonymous_requests(client, method, path):
    import re

    path = re.sub(r"\{([^}]+)\}", lambda m: "1" if m[1] == "audit_id" else str(UUID(int=1)), path)
    response = await client.request(
        method, path, **({"json": {}} if method in {"POST", "PUT", "PATCH"} else {})
    )
    assert response.status_code == 401
