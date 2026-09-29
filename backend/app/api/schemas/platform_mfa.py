"""MFA material is disclosed only in committed, private issuance responses."""

from datetime import datetime

from pydantic import Field

from app.api.schemas.common import ORMModel, RequestModel
from app.api.schemas.identity import Password


class MfaPasswordRequest(RequestModel):
    password: Password = Field(min_length=1, max_length=128, repr=False)


class MfaConfirmRequest(MfaPasswordRequest):
    totp_code: str = Field(pattern=r"^[0-9]{6}$", min_length=6, max_length=6, repr=False)


class MfaEnrollmentResponse(ORMModel):
    secret: str = Field(repr=False)
    otpauth_uri: str = Field(repr=False)
    expires_at: datetime


class MfaRecoveryResponse(ORMModel):
    recovery_codes: list[str] = Field(repr=False)


class MfaStatusResponse(ORMModel):
    enabled: bool
    required_for_platform_actions: bool
    pending_expires_at: datetime | None
    recovery_codes_remaining: int
