"""RFC 6238 parameters and replay-aware counter matching; no application state."""

from __future__ import annotations

import base64
import re
import secrets
from datetime import datetime

from cryptography.hazmat.primitives import constant_time, hashes
from cryptography.hazmat.primitives.twofactor.totp import TOTP


def new_seed() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode()


def generate_code(seed: str, counter: int) -> str:
    key = base64.b32decode(seed, casefold=False)
    if len(key) != 20 or counter < 0:
        raise ValueError("Invalid TOTP parameters")
    return TOTP(key, 6, hashes.SHA1(), 30).generate(counter * 30).decode()  # noqa: S303 - RFC 6238 HMAC, not collision-based hashing


def match_counter(
    seed: str, code: str, now: datetime, last_counter: int | None = None
) -> int | None:
    if not re.fullmatch(r"[0-9]{6}", code, flags=re.ASCII):
        return None
    current = int(now.timestamp()) // 30
    matches = [
        counter
        for counter in range(max(0, current - 1), current + 2)
        if constant_time.bytes_eq(generate_code(seed, counter).encode(), code.encode())
    ]
    eligible = [counter for counter in matches if last_counter is None or counter > last_counter]
    return max(eligible) if eligible else None
