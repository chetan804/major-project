"""
Structured logging.

Output is structured (JSON in production, human-readable console in
development) and always carries the request id, so a user-reported
``request_id`` from an error response leads directly to the relevant log lines.

A redaction processor runs on **every** event before rendering. It removes
credential-shaped keys and masks bearer tokens, so a secret cannot reach the log
stream even if a caller passes one in a context dictionary by mistake. This is
the logging half of REQ-SEC-006 and is asserted by
``tests/test_no_secret_leakage.py``.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Any

import structlog
from structlog.types import EventDict, Processor, WrappedLogger

from app.core.config import Settings
from app.core.context import current_context

__all__ = ["REDACTED", "configure_logging", "get_logger", "redact_event"]

REDACTED = "[redacted]"

#: Fragments that mark a key as sensitive. Matched as substrings of the
#: *normalised* key (see :func:`_normalise_key`), so ``db_password``,
#: ``userPassword``, ``X-API-Key`` and ``client_secret`` are all caught.
#:
#: The fragments themselves are written without separators, because normalisation
#: strips ``-``, ``_``, ``.`` and spaces. Matching raw fragments against raw keys
#: would miss ``x-api-key`` (the fragment ``api_key`` does not appear in it) —
#: which is exactly the gap that let an API key reach the log stream before this
#: was corrected.
_SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "password",
    "passwd",
    "secret",
    "token",
    "authorization",
    "apikey",
    "privatekey",
    "credential",
    "sessionid",
    "cookie",
)


def _normalise_key(key: str) -> str:
    """
    Fold a key to a comparable form by removing separators and lowercasing.

    Header names (``X-API-Key``), snake_case settings (``db_password``) and
    camelCase attributes (``clientSecret``) must all match the same fragment list.
    """
    return re.sub(r"[-_.\s]", "", key).lower()


#: Patterns that mask credential material embedded in free text.
_VALUE_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}"), r"\1 " + REDACTED),
    # A JSON Web Token: three base64url segments separated by dots.
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), REDACTED),
    # key=value style credentials inside a connection string or message.
    (
        re.compile(r"(?i)\b(password|secret|token|api_key)=([^\s;&\"']+)"),
        r"\1=" + REDACTED,
    ),
    # Credentials embedded in a URL: scheme://user:password@host
    (re.compile(r"(?i)(://[^:/\s]+):([^@\s]+)@"), r"\1:" + REDACTED + "@"),
)

_MAX_DEPTH = 6


def _is_sensitive_key(key: str) -> bool:
    normalised = _normalise_key(key)
    return any(fragment in normalised for fragment in _SENSITIVE_KEY_FRAGMENTS)


def _redact_value(value: Any) -> Any:
    if isinstance(value, str):
        redacted = value
        for pattern, replacement in _VALUE_PATTERNS:
            redacted = pattern.sub(replacement, redacted)
        return redacted
    return value


def _redact(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact a structure, bounded in depth to avoid cycles."""
    if depth >= _MAX_DEPTH:
        return "[truncated]"
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        for key, item in value.items():
            if isinstance(key, str) and _is_sensitive_key(key):
                out[key] = REDACTED
            else:
                out[key] = _redact(item, depth=depth + 1)
        return out
    if isinstance(value, (list, tuple, set)):
        return [_redact(item, depth=depth + 1) for item in value]
    return _redact_value(value)


def redact_event(_logger: WrappedLogger, _method_name: str, event_dict: EventDict) -> EventDict:
    """
    structlog processor that removes credential material from an event.

    Also drops foreign ``event`` values that are not strings, because structlog's
    renderers expect a string message and a non-string would raise during
    rendering — turning a logging call into an application error.
    """
    event = event_dict.get("event")
    if event is not None and not isinstance(event, str):
        event_dict["event"] = str(event)
    redacted = _redact(dict(event_dict))
    assert isinstance(redacted, dict)  # noqa: S101 - guarantees processor contract
    return redacted


def add_correlation_context(
    _logger: WrappedLogger, _method_name: str, event_dict: EventDict
) -> EventDict:
    """
    Attach the request/tenant/user correlation ids to every event.

    Only non-null values are added, so a startup log is not cluttered with
    ``"tenant_id": null`` while a request-scoped log always carries its ids.
    """
    for key, value in current_context().items():
        if value is not None:
            event_dict.setdefault(key, value)
    return event_dict


def _shared_processors(settings: Settings) -> list[Processor]:
    if settings.log_format == "json":
        renderer: Processor = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer(colors=sys.stderr.isatty(), pad_event_to=30)
    return [
        structlog.contextvars.merge_contextvars,
        structlog.stdlib.add_log_level,
        # `add_logger_name` reads `logger.name`, which only exists on a stdlib
        # logger — the factory is stdlib-based for exactly this reason (see
        # configure_logging). Using PrintLoggerFactory here would raise
        # AttributeError on every log call.
        structlog.stdlib.add_logger_name,
        structlog.processors.TimeStamper(fmt="iso", utc=True),
        add_correlation_context,
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        redact_event,
        renderer,
    ]


def configure_logging(settings: Settings, *, force: bool = False) -> None:
    """
    Configure structlog and the stdlib logging bridge.

    Idempotent unless ``force=True``, so calling it from the application lifespan
    and again from a test fixture cannot duplicate handlers.

    The logger factory is ``structlog.stdlib.LoggerFactory`` rather than
    ``PrintLoggerFactory``: it routes through the stdlib logging machinery this
    function configures, which (a) supplies the ``logger.name`` that
    ``add_logger_name`` requires and (b) lets uvicorn's own log records share one
    output path and one format with application logs.
    """
    if structlog.is_configured() and not force:
        return

    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    # `force=True` clears handlers installed by an embedding process (uvicorn,
    # celery) so the application owns the output format.
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=level,
        force=True,
    )
    # uvicorn installs its own handlers; clear them so their records propagate to
    # the root handler above and every line shares one format.
    for noisy in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(noisy)
        logger.handlers.clear()
        logger.propagate = True

    structlog.configure(
        processors=_shared_processors(settings),
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Return a bound logger; ``name`` is normally ``__name__``."""
    logger: structlog.stdlib.BoundLogger = structlog.get_logger(name)
    return logger
