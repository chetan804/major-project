"""Closed input contracts; only issuance responses ever contain a usable key."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.api.schemas.common import ORMModel, RequestModel, Timestamped

ScopeCode = Annotated[str, Field(min_length=1, max_length=128)]


class ApiKeyCreateRequest(RequestModel):
    name: str = Field(min_length=1, max_length=200)
    scopes: list[ScopeCode] = Field(min_length=1, max_length=32)
    expires_at: AwareDatetime | None = None

    @field_validator("expires_at")
    @classmethod
    def finite_expiry(cls, value: datetime | None) -> datetime:
        if value is None:
            raise ValueError("expires_at cannot be null; omit it for the default lifetime")
        return value


class ApiKeyRotateRequest(RequestModel):
    scopes: list[ScopeCode] | None = Field(default=None, min_length=1, max_length=32)
    expires_at: AwareDatetime | None = None

    @field_validator("scopes", "expires_at")
    @classmethod
    def not_null(cls, value: list[str] | datetime | None) -> list[str] | datetime:
        if value is None:
            raise ValueError("field cannot be null; omit it to retain the existing value")
        return value


class ApiKeyQuery(RequestModel):
    page: int = Field(default=1, ge=1, le=10000)
    page_size: int = Field(default=25, ge=1, le=100)
    state: Literal["active", "expired", "revoked", "all"] = "active"


class ApiKeyResponse(Timestamped):
    id: UUID
    name: str
    key_prefix: str
    scopes: list[str]
    created_by: UUID | None
    last_used_at: datetime | None
    expires_at: datetime | None
    revoked_at: datetime | None
    rotation_of_id: UUID | None


class ApiKeyIssuedResponse(ApiKeyResponse):
    api_key: str = Field(
        repr=False,
        description="Shown only in this issuance response. Store securely; never log it.",
    )


class ApiKeyScopeResponse(ORMModel):
    code: str
    description: str
    endpoint_status: Literal["planned"] = "planned"
