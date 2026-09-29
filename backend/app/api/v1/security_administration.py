"""Tenant audit browsing and administrator session controls; no credential output."""

from __future__ import annotations

from typing import Annotated, Any
from uuid import UUID

from fastapi import APIRouter, Depends, Path, Query, Response

from app.api.deps import CurrentActor, SettingsDep, TenantSessionDep, require_permission
from app.api.schemas.common import Page, PageMeta
from app.api.schemas.security_administration import (
    AdminSessionResponse,
    AuditPage,
    AuditQuery,
    AuditResponse,
    RevokeAllResponse,
    SessionsQuery,
)
from app.core.audit_privacy import safe_audit_data
from app.models.identity import AuditLog, Session
from app.services.security_administration import SecurityAdministrationService

router = APIRouter(tags=["security administration"])


def safe_fields(row: AuditLog | Session, names: set[str]) -> dict[str, Any]:
    fields = {name: getattr(row, name) for name in names}
    if fields.get("ip_address") is not None:
        fields["ip_address"] = str(fields["ip_address"])
    fields.update(
        safe_audit_data({key: value for key, value in fields.items() if isinstance(value, str)})
    )
    return fields


def audit_response(row: AuditLog) -> AuditResponse:
    return AuditResponse(
        **safe_fields(row, set(AuditResponse.model_fields) - {"metadata"}),
        metadata=safe_audit_data(row.event_metadata),
    )


@router.get(
    "/audit-logs",
    response_model=AuditPage,
    dependencies=[Depends(require_permission("audit.read"))],
)
async def list_audit_logs(
    query: Annotated[AuditQuery, Query()],
    actor: CurrentActor,
    session: TenantSessionDep,
    settings: SettingsDep,
    response: Response,
) -> AuditPage:
    rows, cursor = await SecurityAdministrationService(session, actor).audit_page(
        secret=settings.jwt_secret_key,
        page_size=query.page_size,
        cursor=query.cursor,
        filters=query.model_dump(exclude={"page_size", "cursor"}),
    )
    result = AuditPage(
        items=[audit_response(row) for row in rows], next_cursor=cursor, has_more=cursor is not None
    )
    await session.commit()  # Do not release audit data if recording the read fails.
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get(
    "/audit-logs/{audit_id}",
    response_model=AuditResponse,
    dependencies=[Depends(require_permission("audit.read"))],
)
async def get_audit_log(
    audit_id: Annotated[int, Path(ge=1, le=2147483647)],
    actor: CurrentActor,
    session: TenantSessionDep,
    response: Response,
) -> AuditResponse:
    result = audit_response(
        await SecurityAdministrationService(session, actor).audit_detail(audit_id)
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return result


@router.get(
    "/sessions",
    response_model=Page[AdminSessionResponse],
    dependencies=[Depends(require_permission("sessions.read"))],
)
async def list_sessions(
    query: Annotated[SessionsQuery, Query()],
    actor: CurrentActor,
    session: TenantSessionDep,
    response: Response,
) -> Page[AdminSessionResponse]:
    rows = await SecurityAdministrationService(session, actor).sessions_page(**query.model_dump())
    result = Page[AdminSessionResponse](
        items=[
            AdminSessionResponse(**safe_fields(row, set(AdminSessionResponse.model_fields)))
            for row in rows
        ],
        meta=PageMeta.build(page=query.page, page_size=query.page_size, total_items=rows.total),
    )
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return result


@router.delete(
    "/sessions/{session_id}",
    status_code=204,
    dependencies=[Depends(require_permission("sessions.revoke"))],
)
async def revoke_session(
    session_id: UUID, actor: CurrentActor, session: TenantSessionDep
) -> Response:
    await SecurityAdministrationService(session, actor).revoke_session(session_id)
    await session.commit()
    return Response(status_code=204, headers={"Cache-Control": "no-store"})


@router.post(
    "/users/{user_id}/sessions/revoke-all",
    response_model=RevokeAllResponse,
    dependencies=[Depends(require_permission("sessions.revoke"))],
)
async def revoke_user_sessions(
    user_id: UUID, actor: CurrentActor, session: TenantSessionDep, response: Response
) -> RevokeAllResponse:
    count = await SecurityAdministrationService(session, actor).revoke_user_sessions(user_id)
    await session.commit()
    response.headers["Cache-Control"] = "no-store"
    return RevokeAllResponse(revoked_sessions=count)
