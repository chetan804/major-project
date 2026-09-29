"""Session-bound credential confirmation, with no new token or tenant selector."""

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import CurrentActor, SessionDep, SettingsDep, require_permission
from app.api.rate_limits import account_limit
from app.api.schemas.platform_step_up import PlatformStepUpRequest, PlatformStepUpResponse
from app.services.platform_step_up import PlatformStepUpService

router = APIRouter(prefix="/platform/auth/step-up", tags=["platform authentication"])


@router.post(
    "",
    response_model=PlatformStepUpResponse,
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)
async def confirm(
    payload: PlatformStepUpRequest,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> PlatformStepUpResponse:
    await account_limit(
        request, settings, "platform_step_up", str(actor.tenant_id), str(actor.user_id)
    )
    service = PlatformStepUpService(session, actor, settings)
    expiry = await service.confirm(**payload.model_dump())
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"
    return PlatformStepUpResponse(method=service.method, expires_at=expiry)


@router.delete(
    "", status_code=204, dependencies=[Depends(require_permission("platform.tenants.write"))]
)
async def clear(actor: CurrentActor, session: SessionDep, settings: SettingsDep) -> Response:
    await PlatformStepUpService(session, actor, settings).clear()
    await session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
