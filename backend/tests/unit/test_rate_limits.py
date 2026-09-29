"""Fixed-window atomicity, bounded memory, privacy and fail-closed behavior."""

from __future__ import annotations

import asyncio
import secrets

import pytest
from fakeredis.aioredis import FakeRedis

from app.core.errors import DependencyUnavailableError, RateLimitError
from app.core.rate_limits import AuthRateLimiter, MemoryCounter, RedisCounter

pytestmark = pytest.mark.unit


async def test_memory_window_does_not_slide_and_resets_at_expiry():
    now = [100.0]
    counter = MemoryCounter(clock=lambda: now[0])
    assert await counter.hit("key", 10) == (1, 10)
    now[0] = 105
    assert await counter.hit("key", 10) == (2, 5)
    now[0] = 110
    assert await counter.hit("key", 10) == (1, 10)


@pytest.mark.parametrize("kind", ["memory", "redis"])
async def test_concurrent_checks_enforce_exact_limit(kind):
    counter = MemoryCounter() if kind == "memory" else RedisCounter(FakeRedis())
    limiter = AuthRateLimiter(counter, secrets.token_urlsafe(32))
    try:
        results = await asyncio.gather(
            *[limiter.check("login", ("tenant", "email"), 7, 60) for _ in range(25)],
            return_exceptions=True,
        )
        assert sum(r is None for r in results) == 7
        assert sum(isinstance(r, RateLimitError) for r in results) == 18
        assert all(r is None or 1 <= r.retry_after_seconds <= 60 for r in results)
    finally:
        await limiter.close()


async def test_counter_keys_are_hmac_digests_and_scoped():
    counter = MemoryCounter()
    limiter = AuthRateLimiter(counter, secrets.token_urlsafe(32))
    await limiter.check("login", ("tenant-a", "private@example.test"), 1, 60)
    await limiter.check("login", ("tenant-b", "private@example.test"), 1, 60)
    await limiter.check("reset", ("tenant-a", "private@example.test"), 1, 60)
    assert len(counter.entries) == 3
    assert all("private" not in key and "tenant" not in key for key in counter.entries)
    with pytest.raises(RateLimitError):
        await limiter.check("login", ("tenant-a", "private@example.test"), 1, 60)


async def test_memory_capacity_fails_closed_without_evicting_live_limits():
    now = [10.0]
    counter = MemoryCounter(max_keys=1, clock=lambda: now[0])
    limiter = AuthRateLimiter(counter, secrets.token_urlsafe(32))
    await limiter.check("login", ("one",), 1, 10)
    with pytest.raises(DependencyUnavailableError):
        await limiter.check("login", ("two",), 1, 10)
    with pytest.raises(RateLimitError):
        await limiter.check("login", ("one",), 1, 10)
    now[0] += 10
    await limiter.check("login", ("two",), 1, 10)


async def test_redis_sets_expiry_atomically_and_does_not_extend_it():
    client = FakeRedis()
    counter = RedisCounter(client)
    try:
        assert (await counter.hit("key", 60))[0] == 1
        await client.expire("key", 10)
        count, ttl = await counter.hit("key", 60)
        assert count == 2
        assert 1 <= ttl <= 10
        await client.delete("key")
        assert (await counter.hit("key", 60))[0] == 1
        await client.persist("key")
        assert (await counter.hit("key", 60))[1] > 0
    finally:
        await counter.close()
