"""Adversarial SQL-shaped inputs through real restricted-role HTTP/ORM paths."""

import pytest
from sqlalchemy import func, select

from app.models.identity import User

from .support import login

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]

PROBES = ("' OR 1=1 --", "'; SELECT pg_sleep(1); --", '"; DROP TABLE users; --')


@pytest.mark.parametrize("field", ["search", "role", "sort"])
@pytest.mark.parametrize("probe", PROBES)
async def test_query_injection_cannot_widen_scope_or_execute_sql(
    admin_env, db_session, field, probe
):
    before = await db_session.scalar(select(func.count()).select_from(User))
    response = await admin_env.client.get(
        "/api/v1/users", headers=admin_env.headers, params={field: probe}
    )
    assert response.status_code == (400 if field == "sort" else 200), response.text
    if field != "sort":
        assert response.json()["items"] == []
        assert response.json()["meta"]["total_items"] == 0
    assert await db_session.scalar(select(func.count()).select_from(User)) == before
    normal = await admin_env.client.get("/api/v1/users", headers=admin_env.headers)
    assert normal.status_code == 200
    assert normal.json()["meta"]["total_items"] == 2
    assert {row["id"] for row in normal.json()["items"]} == {
        str(admin_env.users[0].id),
        str(admin_env.colleague.id),
    }


@pytest.mark.parametrize("field", ["email", "tenant_slug", "password"])
async def test_login_injection_cannot_issue_credentials(auth_env, field):
    body = {
        "email": auth_env.users[0].email,
        "tenant_slug": auth_env.tenants[0].slug,
        "password": auth_env.password,
    }
    body[field] = PROBES[0]
    response = await auth_env.client.post("/api/v1/auth/login", json=body)
    assert response.status_code == 401, response.text
    assert "access_token" not in response.json()
    assert PROBES[0] not in response.text
    assert (await login(auth_env)).status_code == 200


async def test_sql_shaped_mutation_is_stored_as_literal_data(admin_env, db_session):
    before = await db_session.scalar(select(func.count()).select_from(User))
    path = f"/api/v1/users/{admin_env.colleague.id}"
    response = await admin_env.client.patch(
        path, headers=admin_env.headers, json={"full_name": PROBES[2]}
    )
    assert response.status_code == 200, response.text
    fetched = await admin_env.client.get(path, headers=admin_env.headers)
    assert fetched.status_code == 200
    assert fetched.json()["full_name"] == PROBES[2]
    assert await db_session.scalar(select(func.count()).select_from(User)) == before
    foreign = await db_session.get(User, admin_env.users[1].id, populate_existing=True)
    assert foreign.full_name == "Test member"
