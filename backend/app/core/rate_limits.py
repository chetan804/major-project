"""Security counters are not the fail-open optimization cache.

Redis uses one MULTI transaction for INCR + EXPIRE NX + TTL. The window starts
with its first request, and later hits never extend it. Memory is a bounded,
single-process development adapter, explicitly reported as simulated.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from collections.abc import Callable
from typing import Any, Protocol

from app.core.config import Settings
from app.core.errors import DependencyUnavailableError, RateLimitError


class Counter(Protocol):
    async def hit(self, key: str, window: int) -> tuple[int, int]: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


class MemoryCounter:
    def __init__(self, max_keys: int = 10000, clock: Callable[[], float] = time.monotonic) -> None:
        self.entries: dict[str, tuple[int, float]] = {}
        self.max_keys = max_keys
        self.clock = clock

    async def hit(self, key: str, window: int) -> tuple[int, int]:
        # No await inside this critical section; atomic within this event loop.
        now = self.clock()
        count, expiry = self.entries.get(key, (0, now + window))
        if expiry <= now:
            count, expiry = 0, now + window
        if key not in self.entries and len(self.entries) >= self.max_keys:
            self.entries = {k: v for k, v in self.entries.items() if v[1] > now}
            if len(self.entries) >= self.max_keys:
                raise RuntimeError("Rate counter capacity reached")
        self.entries[key] = count + 1, expiry
        return count + 1, max(1, math.ceil(expiry - now))

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        self.entries.clear()


class RedisCounter:
    def __init__(self, client: Any) -> None:
        self.client = client

    async def hit(self, key: str, window: int) -> tuple[int, int]:
        async with self.client.pipeline(transaction=True) as pipe:
            pipe.incr(key)
            pipe.expire(key, window, nx=True)
            pipe.ttl(key)
            count, _, ttl = await pipe.execute()
        if int(ttl) < 0:
            raise RuntimeError("Rate counter has no expiry")
        return int(count), max(1, int(ttl))

    async def ping(self) -> bool:
        # Probe the actual atomic counter operation, including Redis 7 EXPIRE NX,
        # not merely socket liveness. An incompatible server is not ready.
        _, ttl = await self.hit("ecomind:auth-rate:health", 5)
        return ttl > 0

    async def close(self) -> None:
        await self.client.aclose()


class AuthRateLimiter:
    def __init__(self, counter: Counter, secret: str, enabled: bool = True) -> None:
        self.counter = counter
        self.secret = secret.encode()
        self.enabled = enabled

    async def check(
        self, scope: str, identifiers: tuple[str, ...], limit: int, window: int
    ) -> None:
        if not self.enabled:
            return
        digest = hmac.new(
            self.secret, json.dumps([scope, *identifiers]).encode(), hashlib.sha256
        ).hexdigest()
        key = f"ecomind:auth-rate:v1:{digest}"
        try:
            count, retry = await self.counter.hit(key, window)
        except Exception as exc:
            # Do not log backend exceptions; they may carry addresses/credentials.
            raise DependencyUnavailableError("auth_rate_limits", retry_after_seconds=5) from exc
        if count > limit:
            raise RateLimitError(limit=limit, window_seconds=window, retry_after_seconds=retry)

    async def healthy(self) -> bool:
        if not self.enabled:
            return True
        try:
            return await self.counter.ping()
        except Exception:
            return False

    async def close(self) -> None:
        await self.counter.close()


def build_limiter(settings: Settings) -> AuthRateLimiter:
    counter: Counter
    if settings.redis_adapter == "redis":
        from redis.asyncio import Redis

        counter = RedisCounter(
            Redis.from_url(
                settings.redis_url,
                socket_timeout=2,
                socket_connect_timeout=2,
                decode_responses=True,
            )
        )
    else:
        counter = MemoryCounter(settings.auth_rate_limit_max_keys)
    return AuthRateLimiter(counter, settings.jwt_secret_key, settings.rate_limit_enabled)
