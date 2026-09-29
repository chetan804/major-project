"""Current tenant metadata; no client-controlled tenant selector."""

from fastapi import APIRouter, Depends

from app.api.deps import CurrentActor, TenantSessionDep, require_permission
from app.api.schemas.administration import TenantResponse, TenantUpdateRequest
from app.services.identity import IdentityService

router = APIRouter(prefix="/tenants", tags=["tenants"])


@router.get(
    "/current",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("settings.read"))],
)
async def current_tenant(actor: CurrentActor, session: TenantSessionDep) -> TenantResponse:
    return TenantResponse.model_validate(await IdentityService(session, actor).current_tenant())


@router.patch(
    "/current",
    response_model=TenantResponse,
    dependencies=[Depends(require_permission("settings.write"))],
)
async def update_tenant(
    payload: TenantUpdateRequest, actor: CurrentActor, session: TenantSessionDep
) -> TenantResponse:
    row = await IdentityService(session, actor).update_tenant(
        payload.model_dump(exclude_unset=True)
    )
    response = TenantResponse.model_validate(row)
    await session.commit()
    return response
