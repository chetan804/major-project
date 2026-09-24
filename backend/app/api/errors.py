"""
Exception handlers.

FastAPI's default handlers return ``{"detail": ...}``, which is not the contract
documented in ``docs/api/error-catalogue.md``. These handlers translate every
exception class that can escape a route into the single error envelope.

Handled here:

* :class:`AppError` — deliberately raised domain errors, honouring their own
  status code and details.
* ``RequestValidationError`` — Pydantic request validation; the field list is
  reshaped into ``details.fields`` so the frontend can attach each message to the
  correct input without parsing a string.
* ``StarletteHTTPException`` — framework-raised errors such as 404 for an unknown
  path and 405 for a wrong method, mapped to their catalogue codes.
* ``Exception`` — registered so that a failure inside the routing layer still
  produces an envelope. The catch-all *middleware* remains the primary guard for
  failures outside routing.
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.context import get_request_id
from app.core.errors import AppError, ErrorCode
from app.core.logging import get_logger
from app.core.responses import error_envelope, error_response

logger = get_logger(__name__)

__all__ = ["register_exception_handlers"]


def _field_path(location: tuple[Any, ...]) -> str:
    """
    Render a Pydantic error location as a dotted field path.

    ``("body", "constraints", 0, "max_duration")`` becomes
    ``constraints[0].max_duration``, which is directly usable by a form library.
    """
    parts: list[str] = []
    for item in location:
        if item in {"body", "query", "path", "header", "cookie"} and not parts:
            continue
        if isinstance(item, int):
            if parts:
                parts[-1] = f"{parts[-1]}[{item}]"
            else:
                parts.append(f"[{item}]")
        else:
            parts.append(str(item))
    return ".".join(parts) if parts else "body"


def _validation_details(exc: RequestValidationError) -> dict[str, Any]:
    fields = [
        {
            "field": _field_path(tuple(error.get("loc", ()))),
            "message": error.get("msg", "Invalid value"),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return {"fields": fields, "field_count": len(fields)}


def register_exception_handlers(app: FastAPI) -> None:
    """Attach the handlers to ``app``."""

    @app.exception_handler(AppError)
    async def handle_app_error(_request: Request, exc: AppError) -> JSONResponse:
        # 5xx app errors indicate a real problem worth a log line; 4xx are
        # ordinary client outcomes and are already captured by the access log.
        if exc.status_code >= 500:
            logger.error(
                "application_error",
                error_code=exc.code.value,
                status_code=exc.status_code,
            )
        else:
            logger.debug(
                "application_error",
                error_code=exc.code.value,
                status_code=exc.status_code,
            )
        return error_response(exc, request_id=get_request_id())

    @app.exception_handler(RequestValidationError)
    async def handle_validation_error(
        _request: Request, exc: RequestValidationError
    ) -> JSONResponse:
        return JSONResponse(
            status_code=400,
            content=error_envelope(
                code=ErrorCode.VALIDATION_ERROR,
                message="The request could not be validated.",
                details=_validation_details(exc),
                request_id=get_request_id(),
            ),
        )

    @app.exception_handler(StarletteHTTPException)
    async def handle_http_exception(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
        if exc.status_code == 404:
            code = ErrorCode.ENDPOINT_NOT_FOUND
            message = "The requested endpoint does not exist."
        elif exc.status_code == 405:
            code = ErrorCode.METHOD_NOT_ALLOWED
            message = "The HTTP method is not allowed for this endpoint."
        elif exc.status_code == 401:
            code = ErrorCode.AUTHENTICATION_REQUIRED
            message = "Authentication is required."
        elif exc.status_code == 403:
            code = ErrorCode.PERMISSION_DENIED
            message = "You do not have permission to perform this action."
        elif exc.status_code == 429:
            code = ErrorCode.RATE_LIMIT_EXCEEDED
            message = "Too many requests. Please retry later."
        else:
            code = ErrorCode.INTERNAL_ERROR if exc.status_code >= 500 else ErrorCode.CONFLICT
            message = "The request could not be completed."

        headers: dict[str, str] = {}
        # Preserve a WWW-Authenticate challenge, which the envelope would otherwise drop.
        if exc.status_code == 401 and exc.headers:
            for key, value in exc.headers.items():
                if key.lower() == "www-authenticate":
                    headers[key] = value

        return JSONResponse(
            status_code=exc.status_code,
            content=error_envelope(
                code=code,
                message=message,
                details={},
                request_id=get_request_id(),
            ),
            headers=headers or None,
        )

    @app.exception_handler(Exception)
    async def handle_unexpected_error(_request: Request, exc: Exception) -> JSONResponse:
        # Reached only for failures inside the routing layer that the
        # ErrorEnvelopeMiddleware has not already converted. Log with the full
        # traceback server-side; return the generic envelope to the client.
        logger.exception(
            "unhandled_route_exception",
            error_type=type(exc).__name__,
        )
        return JSONResponse(
            status_code=500,
            content=error_envelope(
                code=ErrorCode.INTERNAL_ERROR,
                details={},
                request_id=get_request_id(),
            ),
        )
