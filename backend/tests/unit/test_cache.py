"""
Cache behaviour.

The property under test is availability, not performance: the cache must never
be able to fail a request. Every backend error has to degrade to a miss, be
counted, and be visible through the health probe so the degradation is
observable rather than silent (master directive, section 67).
"""

from __future__ import annotations

import pytest

from app.core.cache import (
    Cache,
    CacheHealth,
    FakeRedisCacheBackend,
    NullCache,
    tenant_cache_key,
    user_cache_key,
)

pytestmark = pytest.mark.unit


class FailingBackend:
    """A backend that raises on every operation, to prove failures are contained."""

    name = "failing"
    is_simulated = False

    def __init__(self) -> None:
        self.calls = 0

    async def get_raw(self, key: str) -> bytes | None:
        self.calls += 1
        raise ConnectionError("backend is down")

    async def set_raw(self, key: str, value: bytes, ttl_seconds: int | None) -> None:
        self.calls += 1
        raise ConnectionError("backend is down")

    async def delete_raw(self, *keys: str) -> int:
        self.calls += 1
        raise ConnectionError("backend is down")

    async def delete_prefix_raw(self, prefix: str) -> int:
        self.calls += 1
        raise ConnectionError("backend is down")

    async def ping(self) -> bool:
        self.calls += 1
        return False

    async def close(self) -> None:
        return None


# ---------------------------------------------------------------------------
# Key construction
# ---------------------------------------------------------------------------
def test_tenant_cache_keys_embed_the_tenant_id() -> None:
    """
    A tenant-owned value must never be cached under a tenant-free key.

    Caching across tenants is a disclosure, so the helper makes the tenant id
    structurally part of the key (ADR-0003).
    """
    key = tenant_cache_key("11111111-1111-1111-1111-111111111111", "analytics", "overview")

    assert "11111111-1111-1111-1111-111111111111" in key
    assert key.startswith("ecomind:v1:t:")
    assert key.endswith("analytics:overview")


def test_keys_for_different_tenants_cannot_collide() -> None:
    a = tenant_cache_key("tenant-a", "bins", "summary")
    b = tenant_cache_key("tenant-b", "bins", "summary")

    assert a != b


def test_user_keys_include_both_tenant_and_user() -> None:
    """
    Per-user data is scoped by tenant *and* user.

    Two users in different tenants can share a user id only if the tenant id is
    absent, so both are included.
    """
    key = user_cache_key("tenant-a", "user-1", "preferences")

    assert "tenant-a" in key
    assert "user-1" in key
    assert user_cache_key("tenant-a", "user-1", "preferences") != user_cache_key(
        "tenant-b", "user-1", "preferences"
    )


# ---------------------------------------------------------------------------
# Round trip
# ---------------------------------------------------------------------------
async def test_values_round_trip_through_the_fake_backend() -> None:
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)
    payload = {"bins": [{"id": "b1", "fill": "72.50"}], "count": 3, "flag": True}

    assert await cache.set("k", payload) is True
    assert await cache.get("k") == payload

    await cache.close()


async def test_missing_key_returns_none() -> None:
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)

    assert await cache.get("never-written") is None

    await cache.close()


async def test_numeric_strings_survive_the_round_trip() -> None:
    """
    Decimals travel as JSON strings, not floats.

    A measured weight serialised as a float would lose exactness, which section 7
    forbids. The convention is that callers serialise ``Decimal`` to ``str``, and
    this test pins that convention.
    """
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)
    payload = {"weight_kg": "12500.375", "fill_percentage": "72.50"}

    await cache.set("decimal", payload)
    assert await cache.get("decimal") == payload

    await cache.close()


async def test_unserialisable_values_are_skipped_not_raised() -> None:
    """
    Caching is best-effort: an unserialisable object is a programming error that
    must not become a request failure.
    """
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)

    assert await cache.set("bad", object()) is False
    assert await cache.get("bad") is None

    await cache.close()


async def test_invalidate_prefix_removes_only_matching_keys() -> None:
    """
    Explicit invalidation on mutation (section 42).

    Keys outside the prefix must survive, or a mutation in one tenant would
    invalidate another tenant's cache — a performance bug that hides an isolation
    problem.
    """
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)
    await cache.set("ecomind:v1:t:a:bins:1", {"v": 1})
    await cache.set("ecomind:v1:t:a:bins:2", {"v": 2})
    await cache.set("ecomind:v1:t:b:bins:1", {"v": 3})

    deleted = await cache.invalidate_prefix("ecomind:v1:t:a:bins:")

    assert deleted == 2
    assert await cache.get("ecomind:v1:t:a:bins:1") is None
    assert await cache.get("ecomind:v1:t:b:bins:1") == {"v": 3}

    await cache.close()


# ---------------------------------------------------------------------------
# Failure containment
# ---------------------------------------------------------------------------
async def test_backend_failure_degrades_to_a_miss() -> None:
    """
    A dead cache must not fail a request.

    Every operation returns the "no data" outcome and records the failure, so the
    caller behaves exactly as it would on a cold cache.
    """
    backend = FailingBackend()
    cache = Cache(backend=backend, default_ttl_seconds=60)  # type: ignore[arg-type]

    assert await cache.get("k") is None
    assert await cache.set("k", {"v": 1}) is False
    assert await cache.delete("k") == 0
    assert await cache.invalidate_prefix("p") == 0

    assert backend.calls == 4


async def test_health_reports_unreachable_backend_without_raising() -> None:
    """The readiness probe must be able to report a broken cache, not crash on it."""
    cache = Cache(backend=FailingBackend(), default_ttl_seconds=60)  # type: ignore[arg-type]

    health = await cache.health()

    assert isinstance(health, CacheHealth)
    assert health.reachable is False
    assert health.backend == "failing"


async def test_health_payload_marks_simulated_backends() -> None:
    """The ``fakeredis`` adapter must declare itself simulated in the health payload."""
    cache = Cache(backend=FakeRedisCacheBackend(), default_ttl_seconds=60)

    payload = (await cache.health()).as_dict()

    assert payload["status"] == "ok"
    assert payload["backend"] == "fakeredis"
    assert payload["is_simulated"] is True

    await cache.close()


async def test_null_cache_never_stores_anything() -> None:
    """
    The no-op backend is the pre-initialisation fallback.

    It must be genuinely inert rather than a hidden in-memory store, which would
    make "caching is disabled" indistinguishable from "cache miss".
    """
    cache = Cache(backend=NullCache(), default_ttl_seconds=60)

    assert await cache.set("k", {"v": 1}) is True  # no error
    assert await cache.get("k") is None  # but nothing is retained
    assert (await cache.health()).reachable is True


async def test_close_failure_is_swallowed() -> None:
    """Shutdown must be robust: a failing close cannot prevent the rest of teardown."""

    class CloseFailsBackend(FailingBackend):
        async def close(self) -> None:
            raise RuntimeError("cannot close")

    cache = Cache(backend=CloseFailsBackend(), default_ttl_seconds=60)  # type: ignore[arg-type]
    await cache.close()  # must not raise
