"""IP throttling before parsing/querying, normalized account budgets, outage handling."""

from __future__ import annotations

import pytest

from app.api.deps import get_database_dep
from app.core.rate_limits import MemoryCounter

from .support import login

pytestmark = [pytest.mark.api, pytest.mark.security, pytest.mark.db]


async def test_ip_budget_applies_before_body_parsing_and_preserves_headers(auth_env):
    env = auth_env
    env.settings.auth_ip_limit = 1
    first = await env.client.post(
        "/api/v1/auth/login", content="not-json", headers={"Content-Type": "application/json"}
    )
    assert first.status_code == 400
    before = len(env.bindings)
    second = await env.client.post(
        "/api/v1/auth/login",
        json={},
        headers={
            "X-Forwarded-For": "203.0.113.27",
            "Origin": "http://localhost:5173",
        },
    )
    assert second.status_code == 429
    assert second.json()["error"]["code"] == "RATE_LIMIT_EXCEEDED"
    assert 1 <= int(second.headers["retry-after"]) <= 60
    assert second.headers["access-control-allow-origin"] == "http://localhost:5173"
    assert second.headers["x-content-type-options"] == "nosniff"
    assert second.headers["x-request-id"] == second.json()["error"]["request_id"]
    assert second.headers["cache-control"] == "no-store"
    assert len(env.bindings) == before  # rejected before database dependency
    assert (await env.client.get("/health")).status_code == 200


async def test_account_budget_normalizes_email_and_tenant(auth_env, db_session):
    env = auth_env
    env.settings.auth_account_limit = 2
    assert (await login(env, email="MEMBER@EXAMPLE.TEST")).status_code == 200
    assert (await login(env, tenant_slug=env.tenants[0].slug.upper())).status_code == 200
    blocked = await login(env, email=" member@example.test ")
    assert blocked.status_code == 429
    assert int(blocked.headers["retry-after"]) <= env.settings.auth_account_window_seconds
    assert (await login(env, 1)).status_code == 200  # same email, different tenant
    await db_session.refresh(env.users[0])
    assert env.users[0].failed_login_attempts == 0


async def test_unknown_accounts_get_identical_rate_limit_budgets(auth_env):
    env = auth_env
    env.settings.auth_account_limit = 1
    for email in (env.users[0].email, "absent@example.test"):
        assert (await login(env, email=email, password="incorrect credential")).status_code == 401
        assert (await login(env, email=email, password="incorrect credential")).status_code == 429


async def test_reset_and_verification_share_per_account_abuse_budget(auth_env):
    env = auth_env
    env.settings.recovery_account_limit = 1
    payload = {"tenant_slug": env.tenants[0].slug, "email": env.users[0].email}
    assert (await env.client.post("/api/v1/auth/password-reset", json=payload)).status_code == 202
    response = await env.client.post("/api/v1/auth/email/verify-request", json=payload)
    assert response.status_code == 429
    assert int(response.headers["retry-after"]) <= env.settings.recovery_window_seconds


async def test_rate_store_failure_is_not_treated_as_cache_miss(auth_env, app):
    class Broken(MemoryCounter):
        async def hit(self, key, window):
            raise RuntimeError("backend credential-shaped diagnostic")

        async def ping(self):
            raise RuntimeError("unreachable")

    app.state.auth_rate_limiter.counter = Broken()
    response = await login(auth_env)
    assert response.status_code == 503
    assert response.json()["error"]["details"]["dependency"] == "auth_rate_limits"
    assert "credential-shaped" not in response.text
    assert response.headers["retry-after"] == "5"
    assert (await auth_env.client.get("/health")).status_code == 200
    # The auth fixture overrides the DB with a restricted session-only binding.
    # Readiness probes the real Database health object, not that test facade.
    original = app.dependency_overrides.pop(get_database_dep)
    try:
        ready = await auth_env.client.get("/ready")
    finally:
        app.dependency_overrides[get_database_dep] = original
    assert ready.status_code == 503
    assert ready.json()["checks"]["auth_rate_limits"]["status"] == "unavailable"


async def test_rate_window_expiry_allows_requests_without_sleep(auth_env, app):
    env = auth_env
    now = [100.0]
    app.state.auth_rate_limiter.counter = MemoryCounter(clock=lambda: now[0])
    env.settings.auth_account_limit = 1
    env.settings.auth_account_window_seconds = 10
    assert (await login(env)).status_code == 200
    assert (await login(env)).status_code == 429
    now[0] += 10
    assert (await login(env)).status_code == 200


@pytest.mark.parametrize(
    "path", ["/password-reset/confirm", "/email/verify-confirm", "/refresh", "/me/password"]
)
async def test_credential_routes_are_ip_limited_even_with_invalid_bodies(auth_env, path):
    env = auth_env
    env.settings.auth_ip_limit = 1
    await env.client.post("/api/v1/auth" + path, json={})
    response = await env.client.post("/api/v1/auth" + path, json={})
    assert response.status_code == 429
