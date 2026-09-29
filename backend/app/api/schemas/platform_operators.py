"""Own-realm metadata; never serialize User credential fields."""

from datetime import datetime
from uuid import UUID

from pydantic import Field

from app.api.schemas.common import ORMModel, RequestModel
from app.api.schemas.platform_tenants import OperatorReason
from app.models._enums import UserStatus


class OperatorInvite(OperatorReason):
    email: str = Field(min_length=3, max_length=320)
    full_name: str = Field(min_length=1, max_length=200)


class OperatorQuery(RequestModel):
    page: int = Field(default=1, ge=1, le=10000)
    page_size: int = Field(default=25, ge=1, le=100)


class OperatorResponse(ORMModel):
    id: UUID
    email: str
    full_name: str
    status: UserStatus
    platform_mfa_required: bool
    email_verified_at: datetime | None
    last_login_at: datetime | None
    locked_until: datetime | None
    created_at: datetime
    updated_at: datetime
