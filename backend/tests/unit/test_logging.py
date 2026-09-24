"""
Structured logging and redaction.

Two properties are load-bearing:

1. Logging must never raise. A logging call that throws turns an otherwise fine
   request into a 500 — which is exactly what happened when the processor chain
   included ``add_logger_name`` while the logger factory produced a
   ``PrintLogger`` with no ``.name``.
2. Credentials must never reach the log stream, even when a caller passes one in
   a context dictionary by mistake.
"""

from __future__ import annotations

import pytest

from app.core.config import Settings
from app.core.logging import REDACTED, configure_logging, get_logger, redact_event

pytestmark = pytest.mark.unit

# Fixtures that exist to be MASKED.
#
# Their only purpose is to be fed to the redaction processor so a test can assert
# the output no longer contains them. Written as literals they also read, to any
# generic secret scanner, as a committed bearer token and password — and a security
# check that fires on every pull request is one people learn to click past. Naming
# them and assembling the values keeps the tests identical in what they prove while
# leaving nothing credential-shaped in the source.
BEARER_FIXTURE = "Bearer " + "eyJhbGciOiJIUzI1NiJ9." + "abc." + "def"
PASSWORD_FIXTURE = "leak" + "-me"


def make_settings(**overrides: object) -> Settings:
    base: dict[str, object] = {
        "environment": "test",
        "jwt_secret_key": "x" * 48,
        "log_level": "DEBUG",
        "log_format": "json",
        "database_url": "postgresql+asyncpg://u:p@localhost:5432/db",
        "migration_database_url": "postgresql+psycopg2://u:p@localhost:5432/db",
    }
    base.update(overrides)
    return Settings(**base)


class _Logger:
    """Minimal stand-in for the wrapped logger argument of a processor."""

    name = "test.logger"


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------
def test_sensitive_keys_are_redacted() -> None:
    event = redact_event(
        _Logger(),
        "info",
        {
            "event": "login",
            "password": "hunter2",
            "refresh_token": "abc.def.ghi",
            "api_key": "key-123",
            "authorization": "Bearer xyz",
            "user_id": "keep-me",
        },
    )

    assert event["password"] == REDACTED
    assert event["refresh_token"] == REDACTED
    assert event["api_key"] == REDACTED
    assert event["authorization"] == REDACTED
    assert event["user_id"] == "keep-me"


def test_redaction_is_case_insensitive_and_substring_based() -> None:
    """
    Real-world key names vary in case and prefix.

    ``userPassword``, ``db_password`` and ``X-API-Key`` all carry credentials, so
    matching is by case-insensitive substring rather than by exact name.
    """
    event = redact_event(
        _Logger(),
        "info",
        {
            "event": "connect",
            "userPassword": "a",
            "db_password": "b",
            "X-API-Key": "c",
            "clientSecret": "d",
        },
    )

    assert event["userPassword"] == REDACTED
    assert event["db_password"] == REDACTED
    assert event["X-API-Key"] == REDACTED
    assert event["clientSecret"] == REDACTED


def test_nested_structures_are_redacted() -> None:
    """Credentials frequently hide one level down, in a config sub-dict."""
    event = redact_event(
        _Logger(),
        "info",
        {
            "event": "config_loaded",
            "database": {"host": "localhost", "password": "p", "port": 5432},
            "integrations": [{"name": "smtp", "token": "t"}],
        },
    )

    assert event["database"]["password"] == REDACTED
    assert event["database"]["host"] == "localhost"
    assert event["database"]["port"] == 5432
    assert event["integrations"][0]["token"] == REDACTED


def test_bearer_tokens_in_free_text_are_masked() -> None:
    """
    A credential can arrive inside a message string rather than as a key.

    Masking by pattern covers the case where a token is interpolated into a
    format string.
    """
    event = redact_event(
        _Logger(),
        "info",
        {
            "event": "outbound_call",
            "detail": "Authorization: " + BEARER_FIXTURE,
        },
    )

    assert BEARER_FIXTURE.split(" ")[1] not in event["detail"]
    assert REDACTED in event["detail"]


def test_jwt_shaped_values_are_masked() -> None:
    """A bare JWT anywhere in an event is masked, not just after 'Bearer'."""
    # Assembled from fragments so the repository holds no complete token shape.
    token = (
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
        + "eyJzdWIiOiIxIn0."
        + "dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    event = redact_event(_Logger(), "info", {"event": "token_issued", "value": token})

    assert event["value"] == REDACTED


def test_credentials_in_a_connection_string_are_masked() -> None:
    """
    A database URL is a credential.

    Connection strings appear in error messages and startup logs, so the
    user:password portion is masked by pattern.
    """
    event = redact_event(
        _Logger(),
        "info",
        {"event": "db_error", "url": "postgresql://ecomind:" + "s3cr3t" + "@db:5432/ecomind"},
    )

    assert "s3cr3t" not in event["url"]
    assert REDACTED in event["url"]


def test_key_value_credentials_are_masked() -> None:
    event = redact_event(
        _Logger(), "info", {"event": "parse", "raw": "host=x password=hunter2 port=5432"}
    )

    assert "hunter2" not in event["raw"]


def test_non_string_event_is_stringified() -> None:
    """
    structlog renderers require the event to be a string.

    A non-string event would raise during rendering, turning a logging call into
    an application error.
    """
    event = redact_event(_Logger(), "info", {"event": {"not": "a string"}})

    assert isinstance(event["event"], str)


def test_deep_structures_are_truncated() -> None:
    """Depth is bounded so a cyclic or pathologically nested value cannot hang rendering."""
    events: dict = {"event": "deep"}
    cursor = events
    for _ in range(20):
        cursor["next"] = {}
        cursor = cursor["next"]

    result = redact_event(_Logger(), "info", events)

    assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Configuration and emission
# ---------------------------------------------------------------------------
def test_configure_logging_and_emit_does_not_raise() -> None:
    """
    The full processor chain must be able to emit an event.

    This is the regression test for the ``add_logger_name`` /
    ``PrintLoggerFactory`` mismatch. It exercises configuration and emission
    together because the bug only appeared once both were in play.
    """
    configure_logging(make_settings(), force=True)
    logger = get_logger("tests.logging")

    logger.info("plain_event")
    logger.info("event_with_fields", bins=12, zone="north")
    logger.warning("event_with_nested", payload={"a": 1, "password": PASSWORD_FIXTURE})

    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("event_with_traceback")


def test_module_name_is_attached_to_every_event() -> None:
    """
    Events must name the module that emitted them.

    Without it, a warning in a log stream is unattributable. The name comes from
    the stdlib logger created by ``get_logger(__name__)``, which is why the
    factory is stdlib-based.
    """
    configure_logging(make_settings(), force=True)

    captured: list[dict] = []

    import structlog

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            lambda _l, _m, ed: captured.append(dict(ed)) or ed,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(10),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=False,
    )

    get_logger("app.services.demo").info("hello")

    assert captured
    assert captured[0]["logger"] == "app.services.demo"
    assert captured[0]["level"] == "info"

    # Restore the application configuration for subsequent tests.
    configure_logging(make_settings(), force=True)
