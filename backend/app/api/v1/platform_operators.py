"""Human-only, MFA-gated operator administration in the reserved platform realm."""

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Request, Response

from app.api.deps import CurrentActor, SessionDep, SettingsDep, require_permission
from app.api.rate_limits import account_limit
from app.api.schemas.common import Page, PageMeta
from app.api.schemas.platform_operators import OperatorInvite, OperatorQuery, OperatorResponse
from app.api.schemas.platform_tenants import OperatorReason
from app.services.platform_operators import PlatformOperatorService

router = APIRouter(prefix="/platform/operators", tags=["platform operators"])


def private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


@router.get(
    "",
    response_model=Page[OperatorResponse],
    dependencies=[Depends(require_permission("platform.operators.read"))],
)
async def list_operators(
    query: Annotated[OperatorQuery, Query()],
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> Page[OperatorResponse]:
    rows = await PlatformOperatorService(session, actor, settings).list_operators(
        **query.model_dump()
    )
    result = Page[OperatorResponse](
        items=[OperatorResponse.model_validate(row) for row in rows],
        meta=PageMeta.build(page=query.page, page_size=query.page_size, total_items=rows.total),
    )
    await session.commit()
    private(response)
    return result


@router.get(
    "/{user_id}",
    response_model=OperatorResponse,
    dependencies=[Depends(require_permission("platform.operators.read"))],
)
async def detail(
    user_id: UUID,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> OperatorResponse:
    result = OperatorResponse.model_validate(
        await PlatformOperatorService(session, actor, settings).detail(user_id)
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "",
    status_code=201,
    response_model=OperatorResponse,
    dependencies=[Depends(require_permission("platform.operators.write"))],
)
async def invite(
    payload: OperatorInvite,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> OperatorResponse:
    await account_limit(
        request, settings, "platform_operators", str(actor.tenant_id), str(actor.user_id)
    )
    result = OperatorResponse.model_validate(
        await PlatformOperatorService(session, actor, settings).invite(**payload.model_dump())
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "/{user_id}/suspend",
    response_model=OperatorResponse,
    dependencies=[Depends(require_permission("platform.operators.write"))],
)
async def suspend(
    user_id: UUID,
    payload: OperatorReason,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> OperatorResponse:
    await account_limit(
        request, settings, "platform_operators", str(actor.tenant_id), str(actor.user_id)
    )
    result = OperatorResponse.model_validate(
        await PlatformOperatorService(session, actor, settings).set_suspended(
            user_id, suspended=True, **payload.model_dump()
        )
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "/{user_id}/activate",
    response_model=OperatorResponse,
    dependencies=[Depends(require_permission("platform.operators.write"))],
)
async def activate(
    user_id: UUID,
    payload: OperatorReason,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> OperatorResponse:
    await account_limit(
        request, settings, "platform_operators", str(actor.tenant_id), str(actor.user_id)
    )
    result = OperatorResponse.model_validate(
        await PlatformOperatorService(session, actor, settings).set_suspended(
            user_id, suspended=False, **payload.model_dump()
        )
    )
    await session.commit()
    private(response)
    return result


@router.post(
    "/{user_id}/require-mfa",
    response_model=OperatorResponse,
    dependencies=[Depends(require_permission("platform.operators.write"))],
)
async def require_mfa(
    user_id: UUID,
    payload: OperatorReason,
    request: Request,
    actor: CurrentActor,
    session: SessionDep,
    settings: SettingsDep,
    response: Response,
) -> OperatorResponse:
    await account_limit(
        request, settings, "platform_operators", str(actor.tenant_id), str(actor.user_id)
    )
    result = OperatorResponse.model_validate(
        await PlatformOperatorService(session, actor, settings).require_mfa(
            user_id, **payload.model_dump()
        )
    )
    await session.commit()
    private(response)
    return result
