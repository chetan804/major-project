"""Real HTTP authentication against PostgreSQL as a NON-superuser.

No actor/session dependency is mocked. Only the database binding is replaced,
so token validation, the transaction error path and forced RLS all run for real.
"""

from __future__ import annotations

from app.authorization.context import SYSTEM_ACTOR
from app.repositories.identity import (
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)
from app.services.auth import AuthService


def service(session, settings, tenant_id=SYSTEM_ACTOR.tenant_id):
    return AuthService(
        settings=settings,
        users=UserRepository(session, tenant_id),
        sessions=SessionRepository(session, tenant_id),
        audit=AuditLogRepository(session, tenant_id),
        tenants=TenantRepository(session),
    )


async def login(env, index=0, **overrides):
    body = {
        "email": env.users[index].email,
        "password": env.password,
        "tenant_slug": env.tenants[index].slug,
    }
    body.update(overrides)
    return await env.client.post("/api/v1/auth/login", json=body)


def bearer(tokens):
    return {"Authorization": f"Bearer {tokens['access_token']}"}


async def refresh(env, tokens):
    return await env.client.post(
        "/api/v1/auth/refresh", json={"refresh_token": tokens["refresh_token"]}
    )
