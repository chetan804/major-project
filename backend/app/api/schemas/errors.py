"""Published error envelope; runtime construction remains in core.responses."""

from typing import Any

from pydantic import AwareDatetime, BaseModel, ConfigDict

from app.core.errors import ErrorCode


class ErrorBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: ErrorCode
    message: str
    details: dict[str, Any]
    request_id: str
    timestamp: AwareDatetime
    warnings: list[str] | None = None


class ErrorEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    error: ErrorBody
