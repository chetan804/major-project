"""Own-factor lifecycle only. No administrator factor bypass or disable endpoint."""

from fastapi import APIRouter, Depends, Request, Response

from app.api.deps import CurrentActor, SessionDep, SettingsDep, require_permission
from app.api.rate_limits import account_limit
from app.api.schemas.platform_mfa import (
    MfaConfirmRequest,
    MfaEnrollmentResponse,
    MfaPasswordRequest,
    MfaRecoveryResponse,
    MfaStatusResponse,
)
from app.services.platform_mfa import PlatformMfaService

router = APIRouter(
    prefix="/platform/auth/mfa",
    tags=["platform MFA"],
    dependencies=[Depends(require_permission("platform.tenants.write"))],
)


def private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.get("", response_model=MfaStatusResponse)
async def status(
    actor: CurrentActor, session: SessionDep, settings: SettingsDep, response: Response
) -> MfaStatusResponse:
    result = MfaStatusResponse.model_validate(
        await PlatformMfaService(session, actor, settings).status()
    )
    await session.commit()
    private(response)
    return result


@router.post("/enrollment", response_model=MfaEnrollmentResponse, status_code=201)
async def start(
    payload: MfaPasswordRequest,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> MfaEnrollmentResponse:
    await account_limit(
        request, settings, "platform_step_up", str(actor.tenant_id), str(actor.user_id)
    )
    result = MfaEnrollmentResponse.model_validate(
        await PlatformMfaService(session, actor, settings).start(payload.password)
    )
    await session.commit()
    private(response)
    return result


@router.post("/enrollment/confirm", response_model=MfaRecoveryResponse)
async def activate(
    payload: MfaConfirmRequest,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> MfaRecoveryResponse:
    await account_limit(
        request, settings, "platform_step_up", str(actor.tenant_id), str(actor.user_id)
    )
    result = MfaRecoveryResponse(
        recovery_codes=await PlatformMfaService(session, actor, settings).activate(
            **payload.model_dump()
        )
    )
    await session.commit()
    private(response)
    return result


@router.delete("/enrollment", status_code=204)
async def cancel(actor: CurrentActor, session: SessionDep, settings: SettingsDep) -> Response:
    await PlatformMfaService(session, actor, settings).cancel()
    await session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})


@router.post("/recovery-codes", response_model=MfaRecoveryResponse)
async def regenerate(
    payload: MfaPasswordRequest,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> MfaRecoveryResponse:
    await account_limit(
        request, settings, "platform_step_up", str(actor.tenant_id), str(actor.user_id)
    )
    result = MfaRecoveryResponse(
        recovery_codes=await PlatformMfaService(session, actor, settings).regenerate(
            payload.password
        )
    )
    await session.commit()
    private(response)
    return result
