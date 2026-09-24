"""
Request-context propagation.

This is the test that justifies the pure-ASGI middleware decision. With
``BaseHTTPMiddleware`` the downstream application runs in a separate anyio task
and context variables do not reliably reach the endpoint; request-id correlation
would silently degrade, and later the tenant context that every query depends on
would go with it.

The first test below proves propagation directly, against a purpose-built ASGI
app, so a future refactor back to ``BaseHTTPMiddleware`` fails here rather than
in production.
"""

from __future__ import annotations

import pytest

from app.core.context import get_request_id, get_tenant_id, get_user_id
from app.core.middleware import RequestContextMiddleware

pytestmark = pytest.mark.api


async def test_context_reaches_downstream_application(monkeypatch) -> None:
    """
    A downstream ASGI app must observe the request id set by the middleware.

    The inner app records what it sees and returns it, so the assertion is made
    on the value the *endpoint* observed, not merely on a response header that
    the middleware could have written independently.
    """
    from app.core.config import Settings

    observed: dict[str, str | None] = {}

    async def inner_app(scope, receive, send) -> None:
        observed["request_id"] = get_request_id()
        observed["tenant_id"] = get_tenant_id()
        observed["user_id"] = get_user_id()
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/json")],
            }
        )
        await send({"type": "http.response.body", "body": b"{}"})

    settings = Settings(
        jwt_secret_key="x" * 40,
        environment="test",
        log_level="CRITICAL",
        log_format="console",
    )
    middleware = RequestContextMiddleware(inner_app, settings=settings)

    messages: list[dict] = []

    async def send(message: dict) -> None:
        messages.append(message)

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 12345),
        "http_version": "1.1",
        "root_path": "",
    }

    await middleware(scope, receive, send)

    # The propagation guarantee: the endpoint saw the id the middleware created.
    assert observed["request_id"] not in (None, "-")
    assert len(observed["request_id"]) == 32  # uuid4().hex

    # And it was echoed back on the response so a client can quote it.
    headers = dict(messages[0]["headers"])
    assert headers[b"x-request-id"].decode() == observed["request_id"]


async def test_context_is_cleared_between_requests(monkeypatch) -> None:
    """
    Nothing may survive from one request to the next.

    A leaked tenant id on a pooled worker task would be a cross-tenant breach, so
    the middleware resets the correlation variables on both entry and exit.
    """
    from app.core.config import Settings

    seen: list[str | None] = []

    async def inner_app(scope, receive, send) -> None:
        seen.append(get_tenant_id())
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b""})

    from app.core.context import set_tenant_id

    settings = Settings(
        jwt_secret_key="x" * 40, environment="test", log_level="CRITICAL", log_format="console"
    )
    middleware = RequestContextMiddleware(inner_app, settings=settings)

    # Simulate a previous request having left a tenant id behind.
    set_tenant_id("11111111-2222-3333-4444-555555555555")

    async def receive() -> dict:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: dict) -> None:
        return None

    scope = {
        "type": "http",
        "method": "GET",
        "path": "/probe",
        "headers": [],
        "query_string": b"",
        "scheme": "http",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 1),
        "http_version": "1.1",
        "root_path": "",
    }
    await middleware(scope, receive, send)

    assert seen == [None], "a tenant id from a previous request leaked into the next"


async def test_client_supplied_request_id_is_honoured(client) -> None:
    """A well-formed inbound id is preserved, so a trace spans the whole call."""
    supplied = "trace-abcdef0123456789"
    response = await client.get("/health", headers={"X-Request-ID": supplied})

    assert response.headers["x-request-id"] == supplied


async def test_malformed_request_id_is_replaced_not_rejected(client) -> None:
    """
    A bad correlation header must never fail a legitimate request.

    The value is echoed back in a response header and written to logs, so an
    unconstrained value would allow header injection and log injection. It is
    discarded and replaced instead of producing an error.
    """
    response = await client.get(
        "/health",
        headers={"X-Request-ID": "bad id with spaces and\nnewlines and <script>"},
    )

    assert response.status_code == 200
    returned = response.headers["x-request-id"]
    assert returned != "bad id with spaces and\nnewlines and <script>"
    assert len(returned) == 32
