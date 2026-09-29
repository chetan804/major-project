"""Explicit platform control plane. It never changes the authenticated tenant claim."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import CurrentActor, SessionDep, SettingsDep, require_permission
from app.api.schemas.administration import TenantResponse
from app.api.schemas.common import Page, PageMeta
from app.api.schemas.platform_tenants import (
    OperatorReason,
    PlatformTenantCreate,
    PlatformTenantQuery,
    PlatformTenantUpdate,
)
from app.services.platform_tenants import PlatformTenantService

router = APIRouter(prefix="/platform/tenants", tags=["platform tenants"])


def private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.get(
    "",
    response_model=Page[TenantResponse],
    dependencies=[Depends(require_permission("platform.tenants.read"))],
)
async def list_tenants(
    query: Annotated[PlatformTenantQuery, Query()],
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> Page[TenantResponse]:
    rows = await PlatformTenantService(session, actor, settings).list_tenants_platform(
        **query.model_dump()
    )
    result = Page[TenantResponse](
        items=[TenantResponse.model_validate(row) for row in rows],
        meta=PageMeta.build(page=query.page, page_size=query.page_size, total_items=rows.total),
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "",
    response_model=TenantResponse,
    status_code=201,
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)
async def create_tenant(
    payload: PlatformTenantCreate,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> TenantResponse:
    result = TenantResponse.model_validate(
        await PlatformTenantService(session, actor, settings).create_tenant_platform(
            **payload.model_dump()
        )
    )
    await session.commit()
    private(response)
    return result


@router.get(
    "/{tenant_id}",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("platform.tenants.read"))],
)
async def get_tenant(
    tenant_id: UUID,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> TenantResponse:
    result = TenantResponse.model_validate(
        await PlatformTenantService(session, actor, settings).get_tenant_platform(tenant_id)
    )
    await session.commit()
    private(response)
    return result


@router.patch(
    "/{tenant_id}",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)
async def update_tenant(
    tenant_id: UUID,
    payload: PlatformTenantUpdate,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> TenantResponse:
    values = payload.model_dump(exclude_unset=True, exclude={"reason"})
    result = TenantResponse.model_validate(
        await PlatformTenantService(session, actor, settings).update_tenant_platform(
            tenant_id, reason=payload.reason, values=values
        )
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "/{tenant_id}/suspend",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)
async def suspend_tenant(
    tenant_id: UUID,
    payload: OperatorReason,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> TenantResponse:
    result = TenantResponse.model_validate(
        await PlatformTenantService(session, actor, settings).set_status_platform(
            tenant_id, suspended=True, reason=payload.reason
        )
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "/{tenant_id}/activate",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)
async def activate_tenant(
    tenant_id: UUID,
    payload: OperatorReason,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> TenantResponse:
    result = TenantResponse.model_validate(
        await PlatformTenantService(session, actor, settings).set_status_platform(
            tenant_id, suspended=False, reason=payload.reason
        )
    )
    await session.commit()
    private(response)
    return result
