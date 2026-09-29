"""Confirmation input never strips password whitespace or exposes it via repr."""

from datetime import datetime
from typing import Literal

from pydantic import Field

from app.api.schemas.common import ORMModel, RequestModel
from app.api.schemas.identity import Password


class PlatformStepUpRequest(RequestModel):
    password: Password = Field(min_length=1, max_length=128, repr=False)
    totp_code: str | None = Field(
        default=None, pattern=r"^[0-9]{6}$", min_length=6, max_length=6, repr=False
    )
    recovery_code: str | None = Field(
        default=None, pattern=r"^rc1_[A-Za-z0-9_-]{32}$", min_length=36, max_length=36, repr=False
    )


class PlatformStepUpResponse(ORMModel):
    method: Literal["password", "password+totp", "password+recovery_code"] = "password"
    expires_at: datetime
