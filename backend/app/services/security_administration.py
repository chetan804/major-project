"""Audited tenant security reads and refresh-safe administrative revocation.

Lock order: tenant -> caller User -> target User -> session updates. All admin
operations reuse IdentityService's live permission/session recheck. Authentication
for password sessions locks User, not the tenant mutex; refresh cannot escape a
completed revocation. Machine-key authentication has its own Tenant -> key order.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, cast
from uuid import UUID

from sqlalchemy import func, literal, select, tuple_, update
from sqlalchemy.engine import CursorResult

from app.core.audit_cursor import AuditCursor, AuditPosition
from app.core.errors import InputValidationError, NotFoundError
from app.core.time import utc_now
from app.models.identity import AuditLog, Session, User
from app.repositories.base import PaginationResult
from app.services.identity import IdentityService

AUDIT_FILTERS = frozenset(
    {
        "action",
        "actor_user_id",
        "actor_api_key_id",
        "resource_type",
        "resource_id",
        "outcome",
        "request_id",
        "from_time",
        "to_time",
    }
)


class SecurityAdministrationService(IdentityService):
    async def audit_page(
        self,
        *,
        secret: str,
        filters: dict[str, Any],
        page_size: int = 25,
        cursor: str | None = None,
    ) -> tuple[list[AuditLog], str | None]:
        await self._write("audit.read")
        if not 1 <= page_size <= 100 or filters.keys() - AUDIT_FILTERS:
            raise InputValidationError(message="Invalid audit query.")
        filters = {key: value for key, value in filters.items() if value is not None}
        for field in ("from_time", "to_time"):
            when = filters.get(field)
            if when is not None and (not isinstance(when, datetime) or when.tzinfo is None):
                raise InputValidationError(message="Audit timestamps must include a timezone.")
        if (
            filters.get("from_time")
            and filters.get("to_time")
            and filters["from_time"] > filters["to_time"]
        ):
            raise InputValidationError(message="Invalid audit time range.")
        digest = hashlib.sha256(
            json.dumps(filters, sort_keys=True, default=str).encode()
        ).hexdigest()
        codec = AuditCursor(secret, f"{self.actor.tenant_id}:{digest}")
        position = codec.decode(cursor) if cursor else None
        query = select(AuditLog).where(AuditLog.tenant_id == self.actor.tenant_id)
        for key, value in filters.items():
            if key == "from_time":
                query = query.where(AuditLog.created_at >= value)
            elif key == "to_time":
                query = query.where(AuditLog.created_at <= value)
            else:
                query = query.where(getattr(AuditLog, key) == value)
        if position:
            query = query.where(
                tuple_(AuditLog.created_at, AuditLog.id)
                < tuple_(literal(position.created_at), literal(position.id))
            )
        result = list(
            (
                await self.session.execute(
                    query.order_by(AuditLog.created_at.desc(), AuditLog.id.desc()).limit(
                        page_size + 1
                    )
                )
            ).scalars()
        )
        has_more = len(result) > page_size
        rows = result[:page_size]
        next_cursor = None
        if has_more:
            last = rows[-1]
            next_cursor = codec.encode(
                AuditPosition(
                    last.created_at,
                    last.id,
                    position.expires if position else int(utc_now().timestamp()) + 3600,
                )
            )
        await self.audit.record(
            action="audit.list",
            actor=self.actor,
            resource_type="audit_log",
            metadata={
                "filter_names": sorted(filters),
                "returned_count": len(rows),
                "returned_ids": [row.id for row in rows],
                "has_more": has_more,
                "cursor_used": cursor is not None,
            },
        )
        return rows, next_cursor

    async def audit_detail(self, audit_id: int) -> AuditLog:
        await self._write("audit.read")
        row = (
            await self.session.execute(
                select(AuditLog).where(
                    AuditLog.tenant_id == self.actor.tenant_id,
                    AuditLog.id == audit_id,
                )
            )
        ).scalar_one_or_none()
        if row is None:
            raise NotFoundError(resource_type="audit log", resource_id=str(audit_id))
        await self.audit.record(
            action="audit.read",
            actor=self.actor,
            resource_type="audit_log",
            resource_id=str(row.id),
        )
        return row

    async def _session_user(self, user_id: UUID, *, lock: bool = False) -> User:
        # Historical sessions of disabled/soft-deleted users remain inspectable.
        query = select(User).where(User.tenant_id == self.actor.tenant_id, User.id == user_id)
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        user = (await self.session.execute(query)).scalar_one_or_none()
        if user is None:
            raise NotFoundError(resource_type="user", resource_id=str(user_id))
        return user

    async def sessions_page(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        user_id: UUID | None = None,
        state: str = "active",
    ) -> PaginationResult:
        await self._write("sessions.read")
        if (
            not 1 <= page <= 10000
            or not 1 <= page_size <= 100
            or state not in {"active", "revoked", "expired", "all"}
        ):
            raise InputValidationError(message="Invalid session query.")
        query = select(Session).where(Session.tenant_id == self.actor.tenant_id)
        if user_id:
            await self._session_user(user_id)
            query = query.where(Session.user_id == user_id)
        if state == "active":
            query = query.where(Session.revoked_at.is_(None), Session.expires_at > utc_now())
        elif state == "revoked":
            query = query.where(Session.revoked_at.is_not(None))
        elif state == "expired":
            query = query.where(Session.revoked_at.is_(None), Session.expires_at <= utc_now())
        total = int(
            (
                await self.session.execute(select(func.count()).select_from(query.subquery()))
            ).scalar_one()
        )
        rows = list(
            (
                await self.session.execute(
                    query.order_by(Session.issued_at.desc(), Session.id.desc())
                    .limit(page_size)
                    .offset((page - 1) * page_size)
                )
            ).scalars()
        )
        await self.audit.record(
            action="session.list",
            actor=self.actor,
            resource_type="session",
            metadata={
                "state": state,
                "returned_count": len(rows),
                "user_filtered": user_id is not None,
                "user_id": str(user_id) if user_id else None,
                "returned_ids": [str(row.id) for row in rows],
            },
        )
        return PaginationResult(rows, page=page, page_size=page_size, total=total)

    async def revoke_session(self, session_id: UUID) -> int:
        await self._write("sessions.revoke")
        target = (
            await self.session.execute(
                select(Session).where(
                    Session.tenant_id == self.actor.tenant_id,
                    Session.id == session_id,
                )
            )
        ).scalar_one_or_none()
        if target is None:
            raise NotFoundError(resource_type="session", resource_id=str(session_id))
        user = await self._session_user(target.user_id, lock=True)
        await self._target_guard(user)
        # Family identity is immutable. Locking User serializes against refresh,
        # including a descendant created while we waited on the user lock.
        count = await self._revoke(user.id, family_id=target.family_id)
        await self.audit.record(
            action="session.admin_revoke",
            actor=self.actor,
            resource_type="session",
            resource_id=str(session_id),
            metadata={"family_id": str(target.family_id), "revoked_sessions": count},
        )
        return count

    async def revoke_user_sessions(self, user_id: UUID) -> int:
        await self._write("sessions.revoke")
        user = await self._session_user(user_id, lock=True)
        await self._target_guard(user)
        count = await self._revoke(user.id)
        await self.audit.record(
            action="user.sessions_revoke_all",
            actor=self.actor,
            resource_type="user",
            resource_id=str(user.id),
            metadata={"revoked_sessions": count},
        )
        return count

    async def _revoke(self, user_id: UUID, *, family_id: UUID | None = None) -> int:
        statement = update(Session).where(
            Session.tenant_id == self.actor.tenant_id,
            Session.user_id == user_id,
            Session.revoked_at.is_(None),
        )
        if family_id:
            statement = statement.where(Session.family_id == family_id)
        result = await self.session.execute(
            statement.values(
                revoked_at=utc_now(), revoked_reason="administrative revocation"
            ).execution_options(synchronize_session=False)
        )
        # PostgreSQL reports the affected-row count without materializing a
        # potentially large user's expired-session history. No mutable Session
        # state is serialized after this terminal mutation in the API request.
        return cast(CursorResult[Any], result).rowcount
