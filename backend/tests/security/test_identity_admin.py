"""Administrative workflows, escalation and tenant isolation under real RLS."""

from __future__ import annotations

import asyncio
from datetime import timedelta
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete, select

from app.authorization.context import Actor
from app.authorization.role_matrix import ROLE_DEFINITIONS
from app.core.errors import PermissionDeniedError
from app.core.time import utc_now
from app.db.rls import apply_tenant_context
from app.models.identity import AuditLog, Session, User, UserRole
from app.services.identity import IdentityService

from .support import bearer, login

pytestmark = [pytest.mark.security, pytest.mark.api, pytest.mark.db]


async def test_user_list_filters_pagination_and_safe_responses(admin_env):
    env = admin_env
    response = await env.client.get("/api/v1/users", headers=env.headers, params={"page_size": 1})
    assert response.status_code == 200, response.text
    assert response.json()["meta"]["total_items"] == 2
    assert len(response.json()["items"]) == 1
    assert "password_hash" not in response.text
    other_page = await env.client.get(
        "/api/v1/users", headers=env.headers, params={"page_size": 1, "page": 2}
    )
    assert other_page.json()["items"][0]["id"] != response.json()["items"][0]["id"]
    for query, count in [
        ({"search": "COLLEAGUE"}, 1),
        ({"search": "%"}, 0),
        ({"role": "TENANT_ADMIN"}, 1),
    ]:
        result = await env.client.get("/api/v1/users", headers=env.headers, params=query)
        assert result.json()["meta"]["total_items"] == count
    for query in ({"page_size": 101}, {"page": 0}, {"sort": "password_hash"}, {"status": "bogus"}):
        result = await env.client.get("/api/v1/users", headers=env.headers, params=query)
        assert result.status_code == 400, result.text
    assert env.bindings


@pytest.mark.parametrize(
    "operation",
    [
        "get_user",
        "update_user",
        "delete_user",
        "assign_foreign_user",
        "assign_foreign_role",
        "revoke_foreign_role",
        "read_role",
        "update_role",
        "permissions",
    ],
)
async def test_cross_tenant_records_return_404(admin_env, operation):
    env = admin_env
    foreign_user = env.users[1].id
    own_role = env.roles[env.tenants[0].id, "VIEWER"].id
    foreign_role = env.roles[env.tenants[1].id, "VIEWER"].id
    cases = {
        "get_user": ("GET", f"/users/{foreign_user}", None),
        "update_user": ("PATCH", f"/users/{foreign_user}", {"full_name": "Changed"}),
        "delete_user": ("DELETE", f"/users/{foreign_user}", None),
        "assign_foreign_user": ("POST", f"/users/{foreign_user}/roles", {"role_id": str(own_role)}),
        "assign_foreign_role": (
            "POST",
            f"/users/{env.colleague.id}/roles",
            {"role_id": str(foreign_role)},
        ),
        "revoke_foreign_role": ("DELETE", f"/users/{env.colleague.id}/roles/{foreign_role}", None),
        "read_role": ("GET", f"/roles/{foreign_role}", None),
        "update_role": ("PATCH", f"/roles/{foreign_role}", {"name": "Changed"}),
        "permissions": ("PUT", f"/roles/{foreign_role}/permissions", {"permissions": []}),
    }
    method, path, payload = cases[operation]
    response = await env.client.request(method, "/api/v1" + path, json=payload, headers=env.headers)
    assert response.status_code == 404, response.text
    assert response.json()["error"]["code"] == "RESOURCE_NOT_FOUND"


async def test_invite_activate_suspend_and_soft_delete(admin_env, db_session):
    env = admin_env
    invited = await env.client.post(
        "/api/v1/users/invite",
        headers=env.headers,
        json={
            "email": "invited@example.test",
            "password": env.password,
            "full_name": "Invited Member",
        },
    )
    assert invited.status_code == 201, invited.text
    user_id = invited.json()["id"]
    assert invited.json()["status"] == "INVITED"
    viewer = env.roles[env.tenants[0].id, "VIEWER"].id
    assigned = await env.client.post(
        f"/api/v1/users/{user_id}/roles", headers=env.headers, json={"role_id": str(viewer)}
    )
    assert assigned.status_code == 204, assigned.text
    active = await env.client.patch(
        f"/api/v1/users/{user_id}", headers=env.headers, json={"status": "ACTIVE", "phone": "123"}
    )
    assert active.status_code == 200, active.text
    assert active.json()["roles"] == ["VIEWER"]
    assert active.json()["email_verified_at"] is None  # admin activation is not email verification
    signed_in = await login(env, email="invited@example.test")
    assert signed_in.status_code == 200, signed_in.text
    suspended = await env.client.patch(
        f"/api/v1/users/{user_id}", headers=env.headers, json={"status": "SUSPENDED", "phone": None}
    )
    assert suspended.status_code == 200, suspended.text
    assert suspended.json()["phone"] is None
    assert (
        await env.client.get("/api/v1/auth/me", headers=bearer(signed_in.json()))
    ).status_code == 401
    row = await db_session.get(Session, UUID(signed_in.json()["session_id"]))
    assert row.revoked_at is not None
    deleted = await env.client.delete(f"/api/v1/users/{user_id}", headers=env.headers)
    assert deleted.status_code == 204, deleted.text
    assert (
        await env.client.get(f"/api/v1/users/{user_id}", headers=env.headers)
    ).status_code == 404
    audit = (
        await db_session.execute(
            select(AuditLog).where(
                AuditLog.action == "user.delete", AuditLog.resource_id == user_id
            )
        )
    ).scalar_one()
    assert audit.actor_user_id == env.users[0].id
    assert audit.tenant_id == env.tenants[0].id
    assert (await db_session.get(User, UUID(user_id))).deleted_at is not None


@pytest.mark.parametrize(
    "payload",
    [
        {"full_name": None},
        {"status": None},
        {"status": "INVITED"},
        {"tenant_id": str(uuid4())},
        {"password_hash": "not allowed"},
        {"email": "changed@example.test"},
        {"roles": []},
        {"full_name": "  "},
        {"preferred_timezone": "Unknown/Place"},
    ],
)
async def test_invalid_user_updates_are_rejected(admin_env, payload):
    response = await admin_env.client.patch(
        f"/api/v1/users/{admin_env.colleague.id}", headers=admin_env.headers, json=payload
    )
    assert response.status_code == 400, response.text


@pytest.mark.parametrize("operation", ["suspend", "delete", "revoke", "expire", "role_permissions"])
async def test_last_administrator_cannot_be_removed(admin_env, operation):
    env = admin_env
    admin_id = env.users[0].id
    role_id = env.roles[env.tenants[0].id, "TENANT_ADMIN"].id
    cases = {
        "suspend": ("PATCH", f"/users/{admin_id}", {"status": "SUSPENDED"}),
        "delete": ("DELETE", f"/users/{admin_id}", None),
        "revoke": ("DELETE", f"/users/{admin_id}/roles/{role_id}", None),
        "expire": (
            "POST",
            f"/users/{admin_id}/roles",
            {"role_id": str(role_id), "expires_at": (utc_now() + timedelta(days=1)).isoformat()},
        ),
        "role_permissions": (
            "PUT",
            f"/roles/{role_id}/permissions",
            {"permissions": ["users.read"]},
        ),
    }
    method, path, payload = cases[operation]
    response = await env.client.request(method, "/api/v1" + path, json=payload, headers=env.headers)
    assert response.status_code == 422, response.text
    assert response.json()["error"]["details"]["rule_code"] == "BR-IDENTITY-LAST-ADMIN"
    me = await env.client.get("/api/v1/auth/me", headers=env.headers)
    assert me.status_code == 200
    assert "roles.assign.elevate" in me.json()["permissions"]


async def test_concurrent_admin_removals_leave_one_admin(admin_env, db_session):
    env = admin_env
    role = env.roles[env.tenants[0].id, "TENANT_ADMIN"]
    grant = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/roles",
        headers=env.headers,
        json={"role_id": str(role.id)},
    )
    assert grant.status_code == 204
    results = await asyncio.gather(
        *[
            env.client.patch(
                f"/api/v1/users/{user_id}", headers=env.headers, json={"status": "SUSPENDED"}
            )
            for user_id in (env.users[0].id, env.colleague.id)
        ]
    )
    assert sum(r.status_code == 200 for r in results) == 1, [r.text for r in results]
    assert all(r.status_code in (200, 401, 403, 422) for r in results)
    from app.repositories.identity import UserRepository

    assert await UserRepository(db_session, env.tenants[0].id).count_admins() == 1


async def test_role_editor_and_live_permission_resolution(admin_env):
    env = admin_env
    created = await env.client.post(
        "/api/v1/roles",
        headers=env.headers,
        json={"code": "CUSTOM_READER", "name": "Custom Reader", "permissions": ["users.read"]},
    )
    assert created.status_code == 201, created.text
    role_id = created.json()["id"]
    colleague_tokens = (await login(env, email=env.colleague.email)).json()
    assert (
        await env.client.get("/api/v1/users", headers=bearer(colleague_tokens))
    ).status_code == 403
    assert (
        await env.client.post(
            f"/api/v1/users/{env.colleague.id}/roles",
            headers=env.headers,
            json={"role_id": role_id},
        )
    ).status_code == 204
    assert (
        await env.client.get("/api/v1/users", headers=bearer(colleague_tokens))
    ).status_code == 200
    renamed = await env.client.patch(
        f"/api/v1/roles/{role_id}",
        headers=env.headers,
        json={"name": "Readers", "description": None},
    )
    assert renamed.status_code == 200, renamed.text
    assert renamed.json()["name"] == "Readers"
    edited = await env.client.put(
        f"/api/v1/roles/{role_id}/permissions", headers=env.headers, json={"permissions": []}
    )
    assert edited.status_code == 200, edited.text
    me = await env.client.get("/api/v1/auth/me", headers=bearer(colleague_tokens))
    assert "CUSTOM_READER" in me.json()["roles"], "An empty role is still a membership"
    assert "None" not in me.json()["permissions"]
    assert (
        await env.client.get("/api/v1/users", headers=bearer(colleague_tokens))
    ).status_code == 403
    assert (
        await env.client.delete(
            f"/api/v1/users/{env.colleague.id}/roles/{role_id}", headers=env.headers
        )
    ).status_code == 204
    duplicate = await env.client.post(
        "/api/v1/roles", headers=env.headers, json={"code": "CUSTOM_READER", "name": "Duplicate"}
    )
    assert duplicate.status_code == 409
    catalogue = (await env.client.get("/api/v1/permissions", headers=env.headers)).json()
    assert all(row["scope"] == "TENANT" for row in catalogue)
    assert not ({"bins.telemetry.ingest", "models.manage"} & {row["code"] for row in catalogue})


@pytest.mark.parametrize(
    "permission",
    ["platform.tenants.write", "bins.telemetry.ingest", "models.manage", "unknown.code"],
)
async def test_role_editor_rejects_platform_device_and_unknown_grants(admin_env, permission):
    response = await admin_env.client.post(
        "/api/v1/roles",
        headers=admin_env.headers,
        json={"code": "FORBIDDEN", "name": "Forbidden", "permissions": [permission]},
    )
    assert response.status_code == (400 if permission == "unknown.code" else 403), response.text


async def test_operations_manager_cannot_escalate_or_disable_admin(admin_env, db_session):
    env = admin_env
    manager = env.roles[env.tenants[0].id, "OPERATIONS_MANAGER"]
    db_session.add(
        UserRole(tenant_id=env.tenants[0].id, user_id=env.colleague.id, role_id=manager.id)
    )
    await db_session.commit()
    headers = bearer((await login(env, email=env.colleague.email)).json())
    admin_role = env.roles[env.tenants[0].id, "TENANT_ADMIN"]
    assigned = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/roles",
        headers=headers,
        json={"role_id": str(admin_role.id)},
    )
    assert assigned.status_code == 403, assigned.text
    disabled = await env.client.patch(
        f"/api/v1/users/{env.users[0].id}", headers=headers, json={"status": "SUSPENDED"}
    )
    assert disabled.status_code == 403, disabled.text
    # A role within the caller's effective permissions remains assignable.
    own = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/roles",
        headers=headers,
        json={"role_id": str(manager.id)},
    )
    assert own.status_code == 204, own.text


async def test_tenant_metadata_is_scoped_audited_and_allowlisted(admin_env, db_session):
    env = admin_env
    read = await env.client.get(
        "/api/v1/tenants/current", headers={**env.headers, "X-Tenant-Id": str(env.tenants[1].id)}
    )
    assert read.status_code == 200
    assert read.json()["id"] == str(env.tenants[0].id)
    response = await env.client.patch(
        "/api/v1/tenants/current",
        headers=env.headers,
        json={"name": "Campus", "timezone": "UTC", "locale": "en-IN"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["timezone"] == "UTC"
    await db_session.refresh(env.tenants[1])
    assert env.tenants[1].name == "Auth test"
    for body in (
        {"id": str(env.tenants[1].id)},
        {"status": "ACTIVE"},
        {"name": None},
        {"timezone": "Not/AZone"},
        {"plan": "enterprise"},
    ):
        response = await env.client.patch("/api/v1/tenants/current", headers=env.headers, json=body)
        assert response.status_code == 400, response.text


@pytest.mark.parametrize(
    "method,path,body",
    [
        ("GET", "/users", None),
        ("POST", "/users/invite", {}),
        ("PATCH", "/users/00000000-0000-0000-0000-000000000001", {}),
        ("DELETE", "/users/00000000-0000-0000-0000-000000000001", None),
        ("POST", "/users/00000000-0000-0000-0000-000000000001/roles", {}),
        ("GET", "/roles", None),
        ("POST", "/roles", {}),
        ("GET", "/permissions", None),
        ("PATCH", "/tenants/current", {}),
    ],
)
async def test_viewer_cannot_use_admin_endpoints(admin_env, method, path, body):
    headers = bearer((await login(admin_env, email=admin_env.colleague.email)).json())
    response = await admin_env.client.request(method, "/api/v1" + path, json=body, headers=headers)
    assert response.status_code == 403, response.text


async def test_service_rechecks_live_permissions_not_stale_actor(admin_env, db_session):
    env = admin_env
    actor = Actor(
        user_id=env.users[0].id,
        tenant_id=env.tenants[0].id,
        email=env.users[0].email,
        full_name="Admin",
        permissions=ROLE_DEFINITIONS["TENANT_ADMIN"].permissions,
    )
    await db_session.execute(delete(UserRole).where(UserRole.user_id == actor.user_id))
    await db_session.commit()
    async with env.factory() as session:
        await apply_tenant_context(session, actor.tenant_id)
        with pytest.raises(PermissionDeniedError):
            await IdentityService(session, actor).update_user(
                env.colleague.id, {"full_name": "Denied"}
            )


async def test_elevation_bit_alone_cannot_replace_last_admin(admin_env):
    env = admin_env
    role_id = env.roles[env.tenants[0].id, "TENANT_ADMIN"].id
    response = await env.client.put(
        f"/api/v1/roles/{role_id}/permissions",
        headers=env.headers,
        json={"permissions": ["roles.assign.elevate"]},
    )
    assert response.status_code == 422, response.text
    assert (await env.client.get("/api/v1/users", headers=env.headers)).status_code == 200


async def test_expired_grant_is_not_shown_or_used(admin_env, db_session):
    env = admin_env
    role = env.roles[env.tenants[0].id, "ANALYST"]
    db_session.add(
        UserRole(
            tenant_id=env.tenants[0].id,
            user_id=env.colleague.id,
            role_id=role.id,
            expires_at=utc_now() - timedelta(seconds=1),
        )
    )
    await db_session.commit()
    response = await env.client.get(f"/api/v1/users/{env.colleague.id}", headers=env.headers)
    assert "ANALYST" not in response.json()["roles"]
    result = await env.client.get("/api/v1/users", headers=env.headers, params={"role": "ANALYST"})
    assert result.json()["meta"]["total_items"] == 0


async def test_deleted_email_remains_reserved_and_concurrent_invites_conflict(admin_env):
    env = admin_env
    payload = {"email": "reserved@example.test", "full_name": "Reserved", "password": env.password}
    results = await asyncio.gather(
        *[
            env.client.post("/api/v1/users/invite", headers=env.headers, json=payload)
            for _ in range(2)
        ]
    )
    assert sorted(r.status_code for r in results) == [201, 409]
    user_id = next(r.json()["id"] for r in results if r.status_code == 201)
    assert (
        await env.client.delete(f"/api/v1/users/{user_id}", headers=env.headers)
    ).status_code == 204
    response = await env.client.post("/api/v1/users/invite", headers=env.headers, json=payload)
    assert response.status_code == 409, response.text


@pytest.mark.parametrize("expiry", ["2020-01-01T00:00:00Z", "2040-01-01T00:00:00"])
async def test_role_expiry_requires_aware_future_datetime(admin_env, expiry):
    env = admin_env
    response = await env.client.post(
        f"/api/v1/users/{env.colleague.id}/roles",
        headers=env.headers,
        json={"role_id": str(env.roles[env.tenants[0].id, "VIEWER"].id), "expires_at": expiry},
    )
    assert response.status_code == 400


@pytest.mark.parametrize("role_code", [code for code in ROLE_DEFINITIONS if code != "SUPER_ADMIN"])
async def test_all_tenant_roles_against_admin_route_permissions(admin_env, db_session, role_code):
    """Exercise every new route with each of the nine documented tenant roles.

    Missing IDs let destructive routes pass the permission gate without changing
    the fixture. 404 proves authorization succeeded, not that the action did.
    Separate workflow tests above assert successful writes and their side effects.
    """
    env = admin_env
    user = env.colleague
    await db_session.execute(delete(UserRole).where(UserRole.user_id == user.id))
    db_session.add(
        UserRole(
            user_id=user.id,
            tenant_id=user.tenant_id,
            role_id=env.roles[user.tenant_id, role_code].id,
        )
    )
    await db_session.commit()
    headers = bearer((await login(env, email=user.email)).json())
    missing = uuid4()
    cases = [
        ("GET", "/users", None, "users.read", 200),
        ("GET", f"/users/{user.id}", None, "users.read", 200),
        (
            "POST",
            "/users/invite",
            {"email": "matrix@example.test", "full_name": "Matrix", "password": env.password},
            "users.write",
            201,
        ),
        ("PATCH", f"/users/{missing}", {"full_name": "Updated"}, "users.write", 404),
        ("DELETE", f"/users/{missing}", None, "users.delete", 404),
        ("POST", f"/users/{missing}/roles", {"role_id": str(missing)}, "roles.assign", 404),
        ("DELETE", f"/users/{missing}/roles/{missing}", None, "roles.assign", 404),
        ("GET", "/roles", None, "roles.read", 200),
        ("GET", f"/roles/{missing}", None, "roles.read", 404),
        ("POST", "/roles", {"code": "MATRIX", "name": "Matrix"}, "roles.write", 201),
        ("PATCH", f"/roles/{missing}", {"name": "Updated"}, "roles.write", 404),
        ("PUT", f"/roles/{missing}/permissions", {"permissions": []}, "roles.write", 404),
        ("GET", "/permissions", None, "roles.read", 200),
        ("GET", "/tenants/current", None, "settings.read", 200),
        ("PATCH", "/tenants/current", {"name": "Matrix tenant"}, "settings.write", 200),
    ]
    for method, path, payload, permission, allowed_status in cases:
        response = await env.client.request(method, "/api/v1" + path, json=payload, headers=headers)
        expected = allowed_status if permission in ROLE_DEFINITIONS[role_code].permissions else 403
        assert response.status_code == expected, (role_code, method, path, response.text)
    response = await env.client.get("/api/v1/users/me/permissions", headers=headers)
    assert response.status_code == 200
    assert set(response.json()["permissions"]) == ROLE_DEFINITIONS[role_code].permissions
