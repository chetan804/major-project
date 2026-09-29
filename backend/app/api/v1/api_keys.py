"""Bearer-authenticated key management. No machine-key HTTP auth route is mounted."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Query, Response

from app.api.deps import CurrentActor, TenantSessionDep, require_permission
from app.api.schemas.api_keys import (
    ApiKeyCreateRequest,
    ApiKeyIssuedResponse,
    ApiKeyQuery,
    ApiKeyResponse,
    ApiKeyRotateRequest,
    ApiKeyScopeResponse,
)
from app.api.schemas.common import Page, PageMeta
from app.services.api_keys import ApiKeyService, IssuedApiKey

router = APIRouter(tags=["API keys"])


def private(response: Response) -> None:
    response.headers["Cache-Control"] = "no-store"
    response.headers["Pragma"] = "no-cache"


def issuance(result: IssuedApiKey) -> ApiKeyIssuedResponse:
    return ApiKeyIssuedResponse(
        **ApiKeyResponse.model_validate(result.row).model_dump(), api_key=result.plaintext
    )


@router.get(
    "/api-key-scopes",
    response_model=list[ApiKeyScopeResponse],
    dependencies=[Depends(require_permission("apikeys.read"))],
)
async def scopes(
    actor: CurrentActor, session: TenantSessionDep, response: Response
) -> list[ApiKeyScopeResponse]:
    codes = await ApiKeyService(session, actor).scope_catalogue()
    await session.commit()
    private(response)
    return [
        ApiKeyScopeResponse(
            code=code,
            description="Device telemetry ingestion capability. The ingestion endpoint is not implemented yet.",
        )
        for code in codes
    ]


@router.get(
    "/api-keys",
    response_model=Page[ApiKeyResponse],
    dependencies=[Depends(require_permission("apikeys.read"))],
)
async def list_keys(
    query: Annotated[ApiKeyQuery, Query()],
    actor: CurrentActor,
    session: TenantSessionDep,
    response: Response,
) -> Page[ApiKeyResponse]:
    rows = await ApiKeyService(session, actor).list_keys(**query.model_dump())
    result = Page[ApiKeyResponse](
        items=[ApiKeyResponse.model_validate(row) for row in rows],
        meta=PageMeta.build(page=query.page, page_size=query.page_size, total_items=rows.total),
    )
    await session.commit()
    private(response)
    return result


@router.get(
    "/api-keys/{key_id}",
    response_model=ApiKeyResponse,
    dependencies=[Depends(require_permission("apikeys.read"))],
)
async def get_key(
    key_id: UUID, actor: CurrentActor, session: TenantSessionDep, response: Response
) -> ApiKeyResponse:
    result = ApiKeyResponse.model_validate(await ApiKeyService(session, actor).get_key(key_id))
    await session.commit()
    private(response)
    return result


@router.post(
    "/api-keys",
    response_model=ApiKeyIssuedResponse,
    status_code=201,
    dependencies=[Depends(require_permission("apikeys.write"))],
)
async def create_key(
    payload: ApiKeyCreateRequest, actor: CurrentActor, session: TenantSessionDep, response: Response
) -> ApiKeyIssuedResponse:
    result = issuance(await ApiKeyService(session, actor).create_key(**payload.model_dump()))
    await session.commit()  # A usable credential is disclosed only after commit.
    private(response)
    return result


@router.post(
    "/api-keys/{key_id}/rotate",
    response_model=ApiKeyIssuedResponse,
    status_code=201,
    dependencies=[Depends(require_permission("apikeys.write"))],
)
async def rotate_key(
    key_id: UUID,
    payload: ApiKeyRotateRequest,
    actor: CurrentActor,
    session: TenantSessionDep,
    response: Response,
) -> ApiKeyIssuedResponse:
    result = issuance(
        await ApiKeyService(session, actor).rotate_key(key_id, **payload.model_dump())
    )
    await session.commit()
    private(response)
    return result


@router.delete(
    "/api-keys/{key_id}",
    status_code=204,
    dependencies=[Depends(require_permission("apikeys.write"))],
)
async def revoke_key(key_id: UUID, actor: CurrentActor, session: TenantSessionDep) -> Response:
    await ApiKeyService(session, actor).revoke_key(key_id)
    await session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store", "Pragma": "no-cache"})
