"""Explicit metadata-only security administration responses and closed filters."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, model_validator

from app.api.schemas.common import ORMModel, RequestModel


class AuditQuery(RequestModel):
    page_size: int = Field(default=25, ge=1, le=100)
    cursor: str | None = Field(default=None, min_length=1, max_length=2048)
    action: str | None = Field(default=None, min_length=1, max_length=128)
    actor_user_id: UUID | None = None
    actor_api_key_id: UUID | None = None
    resource_type: str | None = Field(default=None, min_length=1, max_length=128)
    resource_id: str | None = Field(default=None, min_length=1, max_length=200)
    outcome: Literal["SUCCESS", "FAILURE", "DENIED"] | None = None
    request_id: str | None = Field(default=None, min_length=1, max_length=128)
    from_time: AwareDatetime | None = None
    to_time: AwareDatetime | None = None

    @model_validator(mode="after")
    def chronological(self) -> AuditQuery:
        if self.from_time and self.to_time and self.from_time > self.to_time:
            raise ValueError("from_time must not be later than to_time")
        return self


class AuditResponse(ORMModel):
    id: int
    actor_user_id: UUID | None
    actor_api_key_id: UUID | None
    actor_type: str
    actor_label: str | None
    action: str
    resource_type: str | None
    resource_id: str | None
    outcome: str
    request_id: str | None
    ip_address: str | None
    user_agent: str | None
    created_at: datetime
    metadata: dict[str, Any]


class AuditPage(ORMModel):
    items: list[AuditResponse]
    next_cursor: str | None
    has_more: bool


class SessionsQuery(RequestModel):
    page: int = Field(default=1, ge=1, le=10000)
    page_size: int = Field(default=25, ge=1, le=100)
    user_id: UUID | None = None
    state: Literal["active", "revoked", "expired", "all"] = "active"


class AdminSessionResponse(ORMModel):
    id: UUID
    user_id: UUID
    family_id: UUID
    previous_session_id: UUID | None
    issued_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoked_reason: str | None
    ip_address: str | None
    user_agent: str | None
    last_used_at: datetime | None


class RevokeAllResponse(ORMModel):
    revoked_sessions: int
