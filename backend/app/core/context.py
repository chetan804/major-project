"""
Request-scoped context.

The request id, tenant id and user id live in :class:`contextvars.ContextVar`
instances so that any code — service, repository, job, adapter — can correlate
its output without threading extra parameters through every signature.

Context propagation note: the middleware that populates these is written as a
**pure ASGI** middleware rather than ``BaseHTTPMiddleware``. The latter runs the
downstream application in a separate anyio task, and context variables set
inside it do not reliably reach the endpoint. Pure ASGI middleware runs in the
same task, so propagation is guaranteed. This is verified by
``tests/test_request_context.py``.
"""

from __future__ import annotations

import contextvars
import re
import uuid

__all__ = [
    "REQUEST_ID_PATTERN",
    "current_context",
    "get_request_id",
    "get_tenant_id",
    "get_user_id",
    "new_request_id",
    "reset_request_id",
    "reset_tenant_id",
    "reset_user_id",
    "sanitise_incoming_request_id",
    "set_request_id",
    "set_tenant_id",
    "set_user_id",
]

# A client-supplied request id is echoed back in responses and written to logs,
# so it must be tightly constrained. Accepting arbitrary text would allow log
# injection and unbounded response headers.
REQUEST_ID_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{8,128}$")

_request_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "ecomind_request_id", default=None
)
_tenant_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "ecomind_tenant_id", default=None
)
_user_id: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "ecomind_user_id", default=None
)


def new_request_id() -> str:
    """Generate a fresh, collision-resistant request id."""
    return uuid.uuid4().hex


def sanitise_incoming_request_id(candidate: str | None) -> str | None:
    """
    Return ``candidate`` when it is a safe request id, otherwise ``None``.

    A malformed value is discarded (and a new id generated) rather than rejected,
    because a bad correlation header should never fail a legitimate request.
    """
    if candidate and REQUEST_ID_PATTERN.match(candidate):
        return candidate
    return None


def get_request_id() -> str:
    """Current request id, or ``"-"`` outside a request (e.g. a startup log)."""
    return _request_id.get() or "-"


def set_request_id(value: str) -> contextvars.Token[str | None]:
    return _request_id.set(value)


def reset_request_id(token: contextvars.Token[str | None]) -> None:
    _request_id.reset(token)


def get_tenant_id() -> str | None:
    """Active tenant id, or ``None`` for unauthenticated/platform contexts."""
    return _tenant_id.get()


def set_tenant_id(value: str | None) -> contextvars.Token[str | None]:
    return _tenant_id.set(value)


def reset_tenant_id(token: contextvars.Token[str | None]) -> None:
    _tenant_id.reset(token)


def get_user_id() -> str | None:
    """Authenticated user id, or ``None`` when unauthenticated."""
    return _user_id.get()


def set_user_id(value: str | None) -> contextvars.Token[str | None]:
    return _user_id.set(value)


def reset_user_id(token: contextvars.Token[str | None]) -> None:
    _user_id.reset(token)


def current_context() -> dict[str, str | None]:
    """Snapshot of the correlation identifiers, for logging and audit rows."""
    return {
        "request_id": _request_id.get(),
        "tenant_id": _tenant_id.get(),
        "user_id": _user_id.get(),
    }
