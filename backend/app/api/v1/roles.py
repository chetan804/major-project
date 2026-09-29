"""Tenant role editor and permission catalogue (no platform/device grants)."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query

from app.api.deps import CurrentActor, TenantSessionDep, require_permission
from app.api.schemas.administration import (
    PermissionResponse,
    RoleCreateRequest,
    RolePermissionsRequest,
    RoleResponse,
    RoleUpdateRequest,
)
from app.api.schemas.common import Page, PageMeta
from app.models.identity import Role
from app.services.identity import IdentityService

router = APIRouter(tags=["roles"])


async def role_response(service: IdentityService, row: Role) -> RoleResponse:
    return RoleResponse(
        **{
            field: getattr(row, field)
            for field in RoleResponse.model_fields
            if field != "permissions"
        },
        permissions=sorted(await service.roles.permission_codes(row.id)),
    )


@router.get(
    "/roles",
    response_model=Page[RoleResponse],
    dependencies=[Depends(require_permission("roles.read"))],
)
async def list_roles(
    actor: CurrentActor,
    session: TenantSessionDep,
    page: Annotated[int, Query(ge=1)] = 1,
    page_size: Annotated[int, Query(ge=1, le=100)] = 25,
) -> Page[RoleResponse]:
    service = IdentityService(session, actor)
    result = await service.list_roles(page=page, page_size=page_size)
    return Page(
        items=[await role_response(service, row) for row in result],
        meta=PageMeta.build(page=page, page_size=page_size, total_items=result.total),
    )


@router.get(
    "/roles/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(require_permission("roles.read"))],
)
async def get_role(role_id: UUID, actor: CurrentActor, session: TenantSessionDep) -> RoleResponse:
    service = IdentityService(session, actor)
    await service.role_permissions(role_id)
    return await role_response(service, await service.roles.get_or_404(role_id))


@router.post(
    "/roles",
    response_model=RoleResponse,
    status_code=201,
    dependencies=[Depends(require_permission("roles.write"))],
)
async def create_role(
    payload: RoleCreateRequest, actor: CurrentActor, session: TenantSessionDep
) -> RoleResponse:
    service = IdentityService(session, actor)
    row = await service.create_role(
        code=payload.code,
        name=payload.name,
        description=payload.description,
        permissions=frozenset(payload.permissions),
    )
    response = await role_response(service, row)
    await session.commit()
    return response


@router.patch(
    "/roles/{role_id}",
    response_model=RoleResponse,
    dependencies=[Depends(require_permission("roles.write"))],
)
async def update_role(
    role_id: UUID, payload: RoleUpdateRequest, actor: CurrentActor, session: TenantSessionDep
) -> RoleResponse:
    service = IdentityService(session, actor)
    row = await service.update_role(role_id, payload.model_dump(exclude_unset=True))
    response = await role_response(service, row)
    await session.commit()
    return response


@router.put(
    "/roles/{role_id}/permissions",
    response_model=RoleResponse,
    dependencies=[Depends(require_permission("roles.write"))],
)
async def set_permissions(
    role_id: UUID, payload: RolePermissionsRequest, actor: CurrentActor, session: TenantSessionDep
) -> RoleResponse:
    service = IdentityService(session, actor)
    row = await service.set_role_permissions(role_id, frozenset(payload.permissions))
    response = await role_response(service, row)
    await session.commit()
    return response


@router.get(
    "/permissions",
    response_model=list[PermissionResponse],
    dependencies=[Depends(require_permission("roles.read"))],
)
async def list_permissions(
    actor: CurrentActor, session: TenantSessionDep
) -> list[PermissionResponse]:
    return [
        PermissionResponse.model_validate(row)
        for row in await IdentityService(session, actor).list_permissions()
    ]
