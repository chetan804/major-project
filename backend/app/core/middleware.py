"""
ASGI middleware stack.

All three middlewares are written as **pure ASGI** callables rather than
subclasses of ``BaseHTTPMiddleware``. ``BaseHTTPMiddleware`` runs the downstream
application inside a separate anyio task, which has two consequences this
application cannot accept:

1. context variables set in the middleware are not reliably visible to the
   endpoint (breaking request-id correlation and, later, the tenant context that
   every query depends on);
2. exceptions from the endpoint surface wrapped in an ``ExceptionGroup``, which
   makes the error handler's behaviour version-dependent.

Pure ASGI middleware runs in the same task and the same context, so propagation
is guaranteed. ``tests/test_request_context.py`` asserts that an endpoint can see
the request id and that the response carries it back.

Stack order (outermost first)::

    RequestContextMiddleware     request id, timing, access log, metrics
      SecurityHeadersMiddleware  hardened response headers
        CORSMiddleware           cross-origin policy
          ErrorEnvelopeMiddleware catch-all → standard error envelope
            FastAPI exception handlers (AppError, validation, HTTPException)
              router
"""

from __future__ import annotations

import time
from typing import Any

import structlog
from starlette.datastructures import Headers, MutableHeaders
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.context import (
    get_request_id,
    new_request_id,
    reset_request_id,
    reset_tenant_id,
    reset_user_id,
    sanitise_incoming_request_id,
    set_request_id,
    set_tenant_id,
    set_user_id,
)
from app.core.errors import AppError, ErrorCode
from app.core.logging import get_logger
from app.core.metrics import get_metrics
from app.core.responses import encode_json, error_envelope

logger = get_logger(__name__)

#: Paths whose access logs are suppressed at INFO level because they are polled
#: constantly by orchestrators and would otherwise dominate the log stream.
_QUIET_PATHS = frozenset({"/health", "/ready", "/metrics", "/favicon.ico"})

#: Paths excluded from latency/error metrics: probes are not user traffic and
#: including them distorts availability dashboards.
_METRIC_EXCLUDED_PATHS = frozenset({"/metrics"})


def _route_template(scope: Scope) -> str:
    """
    Return the templated route path for metric labels.

    Falls back to ``unmatched`` rather than the raw request path: using raw paths
    as metric labels lets a client create unbounded time series by requesting
    random URLs, which is a memory-exhaustion vector.
    """
    route = scope.get("route")
    if route is not None:
        template = getattr(route, "path_format", None) or getattr(route, "path", None)
        if isinstance(template, str) and template:
            return template
    return "unmatched"


class RequestContextMiddleware:
    """
    Establish request correlation, measure latency, emit the access log and
    record HTTP metrics.
    """

    def __init__(self, app: ASGIApp, *, settings: Settings) -> None:
        self.app = app
        self.header_name = settings.request_id_header
        self.header_name_bytes = settings.request_id_header.lower().encode("latin-1")
        self.metrics_enabled = settings.metrics_enabled

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request_id = (
            sanitise_incoming_request_id(Headers(scope=scope).get(self.header_name))
            or new_request_id()
        )

        token_request = set_request_id(request_id)
        # Reset per-request so a value left by a previously served request on the
        # same worker task can never leak into this one (ADR-0003).
        token_tenant = set_tenant_id(None)
        token_user = set_user_id(None)

        # structlog contextvars are cleared and re-bound so that no value from a
        # previously served request can bleed into this one.
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(
            request_id=request_id,
            method=scope.get("method"),
            path=scope.get("path"),
        )

        method = scope.get("method", "GET")
        raw_path = scope.get("path", "")
        started = time.perf_counter()
        status_code = 500
        in_progress_entered = False
        metrics = get_metrics() if self.metrics_enabled else None

        if metrics is not None and raw_path not in _METRIC_EXCLUDED_PATHS:
            metrics.http_requests_in_progress.labels(method=method).inc()
            in_progress_entered = True

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = int(message["status"])
                # Echo the request id so a user can quote it in a support request
                # and an operator can find the exact log line.
                headers = MutableHeaders(scope=message)
                headers[self.header_name] = request_id
            elif message["type"] == "http.response.body" and metrics is not None:
                body = message.get("body", b"")
                if body and raw_path not in _METRIC_EXCLUDED_PATHS:
                    metrics.http_response_size_bytes.observe(len(body))
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        finally:
            duration = time.perf_counter() - started
            route = _route_template(scope)

            if metrics is not None and raw_path not in _METRIC_EXCLUDED_PATHS:
                metrics.http_requests_total.labels(
                    method=method, route=route, status=f"{status_code // 100}xx"
                ).inc()
                metrics.http_request_duration_seconds.labels(method=method, route=route).observe(
                    duration
                )
                if in_progress_entered:
                    metrics.http_requests_in_progress.labels(method=method).dec()

            log = logger.info if raw_path not in _QUIET_PATHS else logger.debug
            # structlog merges keyword arguments into the event dict; there is no
            # stdlib-style `extra=` parameter.
            log(
                "http_request",
                method=method,
                path=raw_path,
                route=route,
                status_code=status_code,
                duration_ms=round(duration * 1000, 2),
            )

            structlog.contextvars.clear_contextvars()
            reset_request_id(token_request)
            reset_tenant_id(token_tenant)
            reset_user_id(token_user)


class SecurityHeadersMiddleware:
    """
    Attach hardening headers to every response.

    ``X-Frame-Options`` is configurable because the development preview embeds
    the application in a frame; production deployments set
    ``SECURITY_HEADERS_ENABLED`` with framing denied. That is a deliberate,
    documented trade-off rather than an oversight.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        enabled: bool = True,
        hsts_enabled: bool = False,
        frame_options: str = "DENY",
    ) -> None:
        self.app = app
        self.enabled = enabled
        self.hsts_enabled = hsts_enabled
        self.frame_options = frame_options

    def _headers(self) -> dict[str, str]:
        headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": self.frame_options,
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(self), camera=(self), microphone=()",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-site",
        }
        if self.hsts_enabled:
            headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return headers

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or not self.enabled:
            await self.app(scope, receive, send)
            return

        static_headers = self._headers()

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                for key, value in static_headers.items():
                    headers.setdefault(key, value)
            await send(message)

        await self.app(scope, receive, send_wrapper)


class ErrorEnvelopeMiddleware:
    """
    Convert any unhandled exception into the standard error envelope.

    ``AppError`` raised inside a service normally reaches the registered FastAPI
    handler. This middleware exists for the cases that handler cannot cover: an
    exception raised by a *middleware* rather than a route, and any unexpected
    exception. It is placed innermost of the custom stack so that its response
    still passes back out through CORS, the security-header middleware and the
    request-context middleware, and therefore carries the full header set.

    If the response has already started streaming, the exception is re-raised
    instead: appending a JSON error body to a partially written response would
    corrupt the response and mislead the client. The ASGI server then closes the
    connection, which is the only honest signal available at that point.
    """

    def __init__(self, app: ASGIApp, *, debug: bool = False) -> None:
        self.app = app
        self.debug = debug

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        response_started = False

        async def send_wrapper(message: Message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except AppError as exc:
            if response_started:
                raise
            # An AppError reaching this point came from outside the router, so
            # honour its declared status and envelope rather than masking it.
            logger.warning(
                "unhandled_app_error",
                error_code=exc.code.value,
                path=scope.get("path"),
            )
            await self._send_error(
                send,
                status_code=exc.status_code,
                code=exc.code,
                message=exc.message,
                details=exc.details,
                warnings=exc.warnings,
            )
        except Exception as exc:
            if response_started:
                logger.exception("exception_after_response_started")
                raise
            # Log the real cause server-side; the client receives a generic
            # message and the request id that ties the two together.
            logger.exception(
                "unhandled_exception",
                path=scope.get("path"),
                error_type=type(exc).__name__,
            )
            await self._send_error(
                send,
                status_code=500,
                code=ErrorCode.INTERNAL_ERROR,
                message=(f"{type(exc).__name__}: {exc}" if self.debug else None),
                details={"error_type": type(exc).__name__} if self.debug else {},
            )

    async def _send_error(
        self,
        send: Send,
        *,
        status_code: int,
        code: ErrorCode,
        message: str | None,
        details: dict[str, Any] | None = None,
        warnings: list[str] | None = None,
    ) -> None:
        body = encode_json(
            error_envelope(
                code=code,
                message=message,
                details=details,
                request_id=get_request_id(),
                warnings=warnings,
            )
        )
        headers: list[tuple[bytes, bytes]] = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode("ascii")),
        ]
        await send({"type": "http.response.start", "status": status_code, "headers": headers})
        await send({"type": "http.response.body", "body": body})
