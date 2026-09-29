"""Closed administration contracts. Tenant identity is never a writable field."""

from __future__ import annotations

from datetime import datetime
from typing import Literal
from uuid import UUID

from pydantic import AwareDatetime, Field, field_validator

from app.api.schemas.common import ORMModel, RequestModel, Timestamped


class RoleCreateRequest(RequestModel):
    code: str = Field(min_length=1, max_length=64, pattern=r"^[A-Z][A-Z0-9_]*$")
    name: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)
    permissions: list[str] = Field(default_factory=list, max_length=100)


class RoleUpdateRequest(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def non_null_name(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("name cannot be null")
        return value


class RolePermissionsRequest(RequestModel):
    permissions: list[str] = Field(max_length=100)


class RoleAssignmentRequest(RequestModel):
    role_id: UUID
    expires_at: AwareDatetime | None = None


class RoleResponse(Timestamped):
    id: UUID
    code: str
    name: str
    description: str | None
    is_system: bool
    is_default: bool
    level: int
    permissions: list[str]


class PermissionResponse(ORMModel):
    code: str
    resource: str
    action: str
    description: str | None
    scope: str
    is_dangerous: bool


class MyPermissionsResponse(ORMModel):
    roles: list[str]
    permissions: list[str]


class TenantResponse(Timestamped):
    id: UUID
    name: str
    slug: str
    type: str
    status: str
    timezone: str
    locale: str
    plan: str
    trial_ends_at: datetime | None


class TenantUpdateRequest(RequestModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    timezone: str | None = Field(default=None, min_length=1, max_length=64)
    locale: str | None = Field(
        default=None, min_length=2, max_length=16, pattern=r"^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"
    )

    @field_validator("name", "timezone", "locale")
    @classmethod
    def non_null(cls, value: str | None) -> str:
        if value is None:
            raise ValueError("field cannot be null")
        return value


EditableUserStatus = Literal["ACTIVE", "SUSPENDED", "DISABLED"]
