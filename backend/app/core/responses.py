"""
Response construction helpers.

Kept in one module so the error envelope has exactly **one** implementation,
shared by the FastAPI exception handlers and by the catch-all middleware. Two
implementations would inevitably drift, and the API contract in
``docs/api/error-catalogue.md`` is a promise to callers.
"""

from __future__ import annotations

from typing import Any

import orjson
from fastapi import status
from fastapi.responses import JSONResponse

from app.core.context import get_request_id
from app.core.errors import DEFAULT_MESSAGES, ERROR_STATUS, AppError, ErrorCode
from app.core.time import isoformat_utc, utc_now

__all__ = [
    "ORJSONResponse",
    "encode_json",
    "error_envelope",
    "error_response",
]


class ORJSONResponse(JSONResponse):
    """
    JSON response rendered with ``orjson``.

    Used API-wide: ``orjson`` is materially faster than the stdlib encoder on the
    large analytics and telemetry payloads this service returns, and it serialises
    ``Decimal``/``UUID``/``datetime`` without custom encoders.
    """

    media_type = "application/json"

    def render(self, content: Any) -> bytes:
        return orjson.dumps(content, option=orjson.OPT_SERIALIZE_NUMPY)


def encode_json(content: Any) -> bytes:
    """Serialise ``content`` to JSON bytes using the API's encoder settings."""
    return orjson.dumps(content, option=orjson.OPT_SERIALIZE_NUMPY)


def error_envelope(
    code: ErrorCode,
    message: str | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
    warnings: list[str] | None = None,
) -> dict[str, Any]:
    """
    Build the documented error body.

    ``request_id`` defaults to the active request's id so that every error a
    client sees is correlateable with the server log line that explains it.
    """
    error: dict[str, Any] = {
        "code": code.value,
        "message": message or DEFAULT_MESSAGES.get(code, code.value.replace("_", " ").capitalize()),
        "details": details or {},
        "request_id": request_id or get_request_id(),
        "timestamp": isoformat_utc(utc_now()),
    }
    if warnings:
        error["warnings"] = list(warnings)
    return {"error": error}


def error_response(
    error: AppError,
    *,
    request_id: str | None = None,
) -> JSONResponse:
    """Convert an :class:`AppError` into a FastAPI response."""
    body = error.to_payload(request_id or get_request_id(), isoformat_utc(utc_now()))
    headers: dict[str, str] = {}
    if error.retry_after_seconds is not None:
        headers["Retry-After"] = str(error.retry_after_seconds)
    return JSONResponse(
        status_code=error.status_code,
        content=body,
        headers=headers,
    )


def generic_error_response(
    code: ErrorCode = ErrorCode.INTERNAL_ERROR,
    *,
    status_code: int | None = None,
    message: str | None = None,
    details: dict[str, Any] | None = None,
    request_id: str | None = None,
) -> JSONResponse:
    """Build a response for a code raised outside the ``AppError`` hierarchy."""
    return JSONResponse(
        status_code=status_code or ERROR_STATUS[code],
        content=error_envelope(code, message, details, request_id),
    )


# Re-exported for callers that build a 204 without importing fastapi.status.
NO_CONTENT = status.HTTP_204_NO_CONTENT
