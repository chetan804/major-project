"""Versioned, expiring, tenant/filter-bound cursors; never authorization grants."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
from dataclasses import dataclass
from datetime import datetime

from app.core.errors import InputValidationError
from app.core.time import utc_now


@dataclass(frozen=True)
class AuditPosition:
    created_at: datetime
    id: int
    expires: int


class AuditCursor:
    def __init__(self, secret: str, scope: str) -> None:
        self.key = secret.encode()
        self.scope = scope

    def _signature(self, payload: str) -> str:
        return hmac.new(
            self.key, b"audit-cursor:v1:" + payload.encode(), hashlib.sha256
        ).hexdigest()

    def encode(self, position: AuditPosition) -> str:
        raw = json.dumps(
            [1, self.scope, position.created_at.isoformat(), position.id, position.expires]
        )
        payload = base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")
        return payload + "." + self._signature(payload)

    def decode(self, token: str) -> AuditPosition:
        try:
            if len(token) > 2048:
                raise ValueError
            payload, signature = token.split(".")
            if not hmac.compare_digest(signature, self._signature(payload)):
                raise ValueError
            version, scope, timestamp, row_id, expires = json.loads(
                base64.b64decode(payload + "=" * (-len(payload) % 4), altchars=b"-_", validate=True)
            )
            if type(version) is not int or version != 1 or scope != self.scope:
                raise ValueError
            if type(row_id) is not int or not 0 < row_id <= 2147483647:
                raise ValueError
            if type(expires) is not int or expires <= utc_now().timestamp():
                raise ValueError
            when = datetime.fromisoformat(timestamp)
            if when.tzinfo is None or when.utcoffset() is None:
                raise ValueError
            return AuditPosition(when, row_id, expires)
        except (ValueError, TypeError, UnicodeError, OverflowError) as exc:
            raise InputValidationError(
                message="Invalid or expired audit cursor.", field="cursor"
            ) from exc
