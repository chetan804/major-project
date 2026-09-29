"""Closed control-plane inputs. Never accept credentials, grants or tenant selectors."""

from typing import Literal

from pydantic import Field

from app.api.schemas.administration import TenantUpdateRequest
from app.api.schemas.common import RequestModel
from app.models._enums import TenantType


class OperatorReason(RequestModel):
    reason: str = Field(min_length=10, max_length=1000)


class PlatformTenantCreate(OperatorReason):
    name: str = Field(min_length=1, max_length=200)
    slug: str = Field(min_length=3, max_length=120, pattern=r"^[a-z0-9]+(?:-[a-z0-9]+)*$")
    type: TenantType
    timezone: str = Field(default="UTC", min_length=1, max_length=64)
    locale: str = Field(
        default="en-IN", min_length=2, max_length=16, pattern=r"^[a-z]{2,3}(?:-[A-Za-z0-9]{2,8})*$"
    )
    admin_email: str = Field(min_length=3, max_length=320)
    admin_name: str = Field(min_length=1, max_length=200)


class PlatformTenantUpdate(TenantUpdateRequest, OperatorReason):
    pass


class PlatformTenantQuery(RequestModel):
    page: int = Field(default=1, ge=1, le=10000)
    page_size: int = Field(default=25, ge=1, le=100)
    status: Literal["ACTIVE", "TRIAL", "SUSPENDED", "CANCELLED"] | None = None
