"""Cursor integrity/expiry and defensive audit serialization."""

from __future__ import annotations

import base64
import json
import secrets
from datetime import UTC, datetime

import pytest

from app.core.audit_cursor import AuditCursor, AuditPosition
from app.core.audit_privacy import safe_audit_data
from app.core.errors import InputValidationError
from app.core.time import utc_now

pytestmark = pytest.mark.unit


def test_cursor_roundtrip_expiration_scope_and_key_binding(monkeypatch):
    now = utc_now()
    codec = AuditCursor(secrets.token_urlsafe(32), "tenant:filters")
    position = AuditPosition(now, 123, int(now.timestamp()) + 10)
    token = codec.encode(position)
    assert codec.decode(token) == position
    with pytest.raises(InputValidationError):
        AuditCursor(codec.key.decode(), "other:filters").decode(token)
    with pytest.raises(InputValidationError):
        AuditCursor(secrets.token_urlsafe(32), codec.scope).decode(token)
    monkeypatch.setattr(
        "app.core.audit_cursor.utc_now", lambda: datetime.fromtimestamp(position.expires, tz=UTC)
    )
    with pytest.raises(InputValidationError):
        codec.decode(token)


@pytest.mark.parametrize("token", ["", "malformed", ".", "a.b.c", "x" * 2049, "a.☃"])
def test_invalid_cursor_has_uniform_safe_error(token):
    with pytest.raises(InputValidationError, match="Invalid or expired audit cursor"):
        AuditCursor(secrets.token_urlsafe(32), "scope").decode(token)


@pytest.mark.parametrize(
    "timestamp,row_id",
    [
        ("2026-09-29", 1),
        ("invalid", 1),
        (None, 1),
        ("2026-09-29T00:00:00Z", True),
        ("2026-09-29T00:00:00Z", -1),
    ],
)
def test_signed_but_malformed_cursor_is_rejected(timestamp, row_id):
    codec = AuditCursor(secrets.token_urlsafe(32), "scope")
    raw = json.dumps([1, "scope", timestamp, row_id, int(utc_now().timestamp()) + 60])
    payload = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
    with pytest.raises(InputValidationError):
        codec.decode(payload + "." + codec._signature(payload))


def test_audit_redaction_covers_nested_long_keys_and_bodies_without_mutation():
    secret = secrets.token_urlsafe(32)
    long_key = "x" * 250 + "password"
    data = {
        "db_password": secret,
        "nested": {"accessToken": secret},
        long_key: secret,
        "request.body": {"value": secret},
        "text": "Bearer " + secret,
        "count": 7,
        "changes": {"name": "safe"},
    }
    result = safe_audit_data(data)
    assert secret not in json.dumps(result)
    assert result[long_key[:200]] == "[redacted]"
    assert result["count"] == 7
    assert result["changes"] == {"name": "safe"}
    assert data["db_password"] == secret


def test_audit_metadata_size_and_depth_are_bounded():
    data = {str(i): {str(j): ["x" * 4000] * 150 for j in range(150)} for i in range(150)}
    result = safe_audit_data(data)
    assert len(result) <= 100
    assert "[truncated]" in json.dumps(result)
    assert len(json.dumps(result)) < 2_100_000
    assert safe_audit_data({"text": "x" * 4000})["text"] == "x" * 2000 + "[truncated]"
