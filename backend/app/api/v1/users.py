"""Tenant user administration. Every mutation also checks permissions in service."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import AuthenticatedActor, CurrentActor, TenantSessionDep, require_permission
from app.api.schemas.administration import MyPermissionsResponse, RoleAssignmentRequest
from app.api.schemas.common import Page, PageMeta
from app.api.schemas.identity import UserResponse, UserUpdateRequest
from app.api.v1.auth import create_user
from app.core.time import utc_now
from app.models._enums import UserStatus
from app.models.identity import User
from app.services.identity import IdentityService

router = APIRouter(prefix="/users", tags=["users"])


def user_response(user: User) -> UserResponse:
    now = utc_now()
    return UserResponse(
        **{field: getattr(user, field) for field in UserResponse.model_fields if field != "roles"},
        roles=sorted(
            {
                grant.role.code
                for grant in user.roles
                if grant.tenant_id == user.tenant_id
                and grant.role.tenant_id == user.tenant_id
                and (grant.expires_at is None or grant.expires_at > now)
            }
        ),
    )


@router.get("/me/permissions", response_model=MyPermissionsResponse)
async def my_permissions(actor: AuthenticatedActor) -> MyPermissionsResponse:
    return MyPermissionsResponse(roles=sorted(actor.roles), permissions=sorted(actor.permissions))


@router.get(
    "", response_model=Page[UserResponse], dependencies=[Depends(require_permission("users.read"))]
)
async def list_users(
    actor: CurrentActor,
    session: TenantSessionDep,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
    search: Annotated[str | None, Query(max_length=200)] = None,
    status: UserStatus | None = None,
    role: Annotated[str | None, Query(max_length=64)] = None,
    sort: Annotated[str, Query(max_length=100)] = "created_at",
) -> Page[UserResponse]:
    result = await IdentityService(session, actor).list_users(
        page=page,
        page_size=page_size,
        search=search,
        status=status,
        role_code=role,
        sort=tuple(sort.split(",")),
    )
    return Page(
        items=[user_response(row) for row in result],
        meta=PageMeta.build(page=page, page_size=page_size, total_items=result.total),
    )


# Keep /auth/users as a compatibility alias; both paths run the same invitation
# handler, transaction and service permission check. No duplicate business logic.
router.add_api_route(
    "/invite",
    create_user,
    methods=["POST"],
    response_model=UserResponse,
    status_code=201,
    dependencies=[Depends(require_permission("users.write"))],
)


@router.get(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_permission("users.read"))],
)
async def get_user(user_id: UUID, actor: CurrentActor, session: TenantSessionDep) -> UserResponse:
    return user_response(await IdentityService(session, actor).get_user(user_id))


@router.patch(
    "/{user_id}",
    response_model=UserResponse,
    dependencies=[Depends(require_permission("users.write"))],
)
async def update_user(
    user_id: UUID, payload: UserUpdateRequest, actor: CurrentActor, session: TenantSessionDep
) -> UserResponse:
    row = await IdentityService(session, actor).update_user(
        user_id, payload.model_dump(exclude_unset=True)
    )
    response = user_response(row)
    await session.commit()
    return response


@router.delete(
    "/{user_id}", status_code=204, dependencies=[Depends(require_permission("users.delete"))]
)
async def delete_user(user_id: UUID, actor: CurrentActor, session: TenantSessionDep) -> Response:
    await IdentityService(session, actor).delete_user(user_id)
    await session.commit()
    return Response(status_code=204)


@router.post(
    "/{user_id}/roles", status_code=204, dependencies=[Depends(require_permission("roles.assign"))]
)
async def assign_role(
    user_id: UUID, payload: RoleAssignmentRequest, actor: CurrentActor, session: TenantSessionDep
) -> Response:
    await IdentityService(session, actor).assign_role(user_id, payload.role_id, payload.expires_at)
    await session.commit()
    return Response(status_code=204)


@router.delete(
    "/{user_id}/roles/{role_id}",
    status_code=204,
    dependencies=[Depends(require_permission("roles.assign"))],
)
async def revoke_role(
    user_id: UUID, role_id: UUID, actor: CurrentActor, session: TenantSessionDep
) -> Response:
    await IdentityService(session, actor).revoke_role(user_id, role_id)
    await session.commit()
    return Response(status_code=204)
