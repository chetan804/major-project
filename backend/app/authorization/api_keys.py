"""Device-key format and explicit delegation policy, not the human role catalogue.

apikeys.write delegates only these machine capabilities. It deliberately does not
turn every permission held by a human into a durable integration credential.
"""

from __future__ import annotations

import re
import secrets
from datetime import timedelta

API_KEY_SCOPES = frozenset({"bins.telemetry.ingest"})
DEFAULT_KEY_TTL = timedelta(days=90)
MAX_KEY_TTL = timedelta(days=365)
KEY_PATTERN = re.compile(r"[A-Za-z0-9_-]{12}\.[A-Za-z0-9_-]{43}", re.ASCII)


def generate_api_key() -> tuple[str, str]:
    """72-bit public lookup prefix plus an independent 256-bit secret."""
    prefix = secrets.token_urlsafe(9)
    return prefix, f"{prefix}.{secrets.token_urlsafe(32)}"


def api_key_prefix(value: str) -> str | None:
    return value[:12] if KEY_PATTERN.fullmatch(value) else None
