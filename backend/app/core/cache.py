"""
Cache abstraction.

The cache is an **optimisation, never a dependency** (master directive, section
42 and the failure-handling table in section 67): if it is unavailable, requests
must still succeed. :class:`Cache` therefore converts every backend failure into
a logged warning plus a miss, and exposes the failures through :meth:`health` so
that ``/ready`` can report a degraded cache without failing the request path.

Backends
--------
``RedisCacheBackend``
    A real Redis server, used in production and whenever one is reachable.
``FakeRedisCacheBackend``
    An in-process, Redis-compatible adapter (``fakeredis``) for development and
    tests. It is explicitly flagged ``is_simulated=True`` and surfaced in
    ``/health`` so it can never be mistaken for real infrastructure (ADR-0013).
``NullCache``
    A no-op backend, used when caching is deliberately disabled.

Tenant safety
-------------
Keys for tenant-owned data must be built with :func:`tenant_cache_key`, which
embeds the tenant id. Caching a tenant-owned value under a tenant-free key is a
cross-tenant disclosure waiting to happen (ADR-0003), so the helper is the
supported entry point and its absence from a call site is visible in review.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Protocol

import orjson

from app.core.config import Settings
from app.core.errors import DependencyUnavailableError
from app.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "Cache",
    "CacheBackend",
    "CacheHealth",
    "get_cache",
    "init_cache",
    "reset_cache",
    "tenant_cache_key",
    "user_cache_key",
]

KEY_PREFIX = "ecomind:v1"


def tenant_cache_key(tenant_id: str, *parts: str) -> str:
    """Build a cache key for tenant-owned data."""
    return ":".join((KEY_PREFIX, "t", str(tenant_id), *(str(part) for part in parts)))


def user_cache_key(tenant_id: str, user_id: str, *parts: str) -> str:
    """Build a cache key for data scoped to one user inside one tenant."""
    return ":".join(
        (KEY_PREFIX, "t", str(tenant_id), "u", str(user_id), *(str(part) for part in parts))
    )


class CacheBackend(Protocol):
    """Minimal async key/value contract implemented by every backend."""

    name: str
    is_simulated: bool

    async def get_raw(self, key: str) -> bytes | None: ...
    async def set_raw(self, key: str, value: bytes, ttl_seconds: int | None) -> None: ...
    async def delete_raw(self, *keys: str) -> int: ...
    async def delete_prefix_raw(self, prefix: str) -> int: ...
    async def ping(self) -> bool: ...
    async def close(self) -> None: ...


# ---------------------------------------------------------------------------
# Backends
# ---------------------------------------------------------------------------
class NullCache:
    """A backend that stores nothing. Used when caching is disabled."""

    name = "null"
    is_simulated = False

    async def get_raw(self, key: str) -> bytes | None:
        return None

    async def set_raw(self, key: str, value: bytes, ttl_seconds: int | None) -> None:
        return None

    async def delete_raw(self, *keys: str) -> int:
        return 0

    async def delete_prefix_raw(self, prefix: str) -> int:
        return 0

    async def ping(self) -> bool:
        return True

    async def close(self) -> None:
        return None


class _RedisLikeBackend:
    """
    Shared implementation for the real Redis client and the fakeredis adapter.

    Both expose the same command surface, so the only difference is which client
    object is injected and what the backend reports about itself.
    """

    name = "redis"
    is_simulated = False

    def __init__(self, client: Any, *, name: str, is_simulated: bool) -> None:
        self._client = client
        self.name = name
        self.is_simulated = is_simulated

    async def get_raw(self, key: str) -> bytes | None:
        value: Any = await self._client.get(key)
        if value is None:
            return None
        if isinstance(value, str):  # a client configured with decode_responses
            return value.encode("utf-8")
        return bytes(value)

    async def set_raw(self, key: str, value: bytes, ttl_seconds: int | None) -> None:
        if ttl_seconds and ttl_seconds > 0:
            await self._client.set(key, value, ex=ttl_seconds)
        else:
            await self._client.set(key, value)

    async def delete_raw(self, *keys: str) -> int:
        if not keys:
            return 0
        deleted: int = await self._client.delete(*keys)
        return int(deleted)

    async def delete_prefix_raw(self, prefix: str) -> int:
        """
        Delete every key beginning with ``prefix``.

        Uses ``SCAN`` rather than ``KEYS``: ``KEYS`` blocks the server for the
        duration of a full keyspace walk, which on a production instance is an
        availability incident.
        """
        deleted = 0
        batch: list[str] = []
        async for raw_key in self._client.scan_iter(match=f"{prefix}*", count=500):
            key = raw_key.decode("utf-8") if isinstance(raw_key, bytes) else str(raw_key)
            batch.append(key)
            if len(batch) >= 500:
                deleted += int(await self._client.delete(*batch))
                batch.clear()
        if batch:
            deleted += int(await self._client.delete(*batch))
        return deleted

    async def ping(self) -> bool:
        try:
            result = await self._client.ping()
        except Exception:
            return False
        return bool(result)

    async def close(self) -> None:
        try:
            await self._client.aclose()
        except AttributeError:  # pragma: no cover - older client
            # redis-py 5+ renamed close() to aclose(); a pinned older client
            # only has close(). Both are awaited, so no type ignore is needed.
            await self._client.close()


class RedisCacheBackend(_RedisLikeBackend):
    """Real Redis, via ``redis.asyncio``. Connects lazily on first command."""

    def __init__(self, url: str, *, socket_timeout_seconds: float = 2.0) -> None:
        from redis import asyncio as aioredis  # imported lazily: keeps import cost off startup

        client = aioredis.Redis.from_url(
            url,
            socket_timeout=socket_timeout_seconds,
            socket_connect_timeout=socket_timeout_seconds,
            health_check_interval=30,
        )
        super().__init__(client, name="redis", is_simulated=False)


class FakeRedisCacheBackend(_RedisLikeBackend):
    """
    In-process Redis-compatible adapter for development and tests.

    ``fakeredis`` is a development-only dependency (``requirements/dev.txt``), so
    the import is deferred and its absence produces an actionable error rather
    than an ImportError at module import time.
    """

    def __init__(self) -> None:
        try:
            from fakeredis import aioredis as fake_aioredis
        except ModuleNotFoundError as exc:  # pragma: no cover - environment guard
            raise DependencyUnavailableError(
                dependency="cache",
                message=(
                    "REDIS_ADAPTER=fakeredis requires the 'fakeredis' package, which "
                    "is a development-only dependency. Install "
                    "backend/requirements/dev.txt or point REDIS_URL at a real Redis "
                    "server and set REDIS_ADAPTER=redis."
                ),
            ) from exc
        client = fake_aioredis.FakeRedis(decode_responses=True)
        super().__init__(client, name="fakeredis", is_simulated=True)


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class CacheHealth:
    """Result of a cache health probe, shaped for the ``/ready`` payload."""

    backend: str
    is_simulated: bool
    reachable: bool
    latency_ms: float | None = None
    consecutive_failures: int = 0
    detail: str | None = None

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "status": "ok" if self.reachable else "unavailable",
            "backend": self.backend,
            "is_simulated": self.is_simulated,
        }
        if self.latency_ms is not None:
            payload["latency_ms"] = round(self.latency_ms, 3)
        if self.consecutive_failures:
            payload["consecutive_failures"] = self.consecutive_failures
        if self.detail:
            payload["detail"] = self.detail
        return payload


# ---------------------------------------------------------------------------
# Facade
# ---------------------------------------------------------------------------
@dataclass
class Cache:
    """
    Failure-tolerant facade over a :class:`CacheBackend`.

    Values are stored as ``orjson``-serialised JSON. Every public method
    swallows backend errors, logs a structured warning and degrades to a miss,
    which is what keeps the cache from becoming an availability dependency.
    """

    backend: CacheBackend
    default_ttl_seconds: int = 60
    _consecutive_failures: int = field(default=0, init=False)

    @property
    def name(self) -> str:
        return self.backend.name

    @property
    def is_simulated(self) -> bool:
        return self.backend.is_simulated

    async def get(self, key: str) -> Any | None:
        """Return the cached value, or ``None`` on a miss or backend failure."""
        try:
            raw = await self.backend.get_raw(key)
            self._consecutive_failures = 0
        except Exception as exc:
            self._record_failure("get", key, exc)
            return None
        if raw is None:
            return None
        try:
            return orjson.loads(raw)
        except orjson.JSONDecodeError:
            # A corrupt entry is worse than a miss: drop it and continue.
            logger.warning("cache_corrupt_entry", key=key)
            await self.delete(key)
            return None

    async def set(self, key: str, value: Any, ttl_seconds: int | None = None) -> bool:
        """Store a JSON-serialisable value. Returns ``True`` on success."""
        try:
            payload = orjson.dumps(value)
        except TypeError:
            # Unserialisable values are a programming error, not a runtime
            # failure: log and skip caching rather than raising into the request.
            logger.warning("cache_value_not_serialisable", key=key, value_type=type(value).__name__)
            return False
        try:
            await self.backend.set_raw(key, payload, ttl_seconds or self.default_ttl_seconds)
            self._consecutive_failures = 0
            return True
        except Exception as exc:
            self._record_failure("set", key, exc)
            return False

    async def delete(self, *keys: str) -> int:
        if not keys:
            return 0
        try:
            deleted = await self.backend.delete_raw(*keys)
            self._consecutive_failures = 0
            return deleted
        except Exception as exc:
            self._record_failure("delete", ",".join(keys), exc)
            return 0

    async def invalidate_prefix(self, prefix: str) -> int:
        """
        Invalidate every key under ``prefix``.

        Cache invalidation is explicit, never time-based guesswork (section 42):
        a mutation calls this with the tenant-scoped prefix it affects.
        """
        try:
            deleted = await self.backend.delete_prefix_raw(prefix)
            self._consecutive_failures = 0
            return deleted
        except Exception as exc:
            self._record_failure("invalidate_prefix", prefix, exc)
            return 0

    async def health(self) -> CacheHealth:
        """Probe the backend for the readiness endpoint."""
        started = time.perf_counter()
        try:
            reachable = await self.backend.ping()
            latency_ms = (time.perf_counter() - started) * 1000
        except Exception as exc:
            return CacheHealth(
                backend=self.backend.name,
                is_simulated=self.backend.is_simulated,
                reachable=False,
                consecutive_failures=self._consecutive_failures,
                detail=type(exc).__name__,
            )
        return CacheHealth(
            backend=self.backend.name,
            is_simulated=self.backend.is_simulated,
            reachable=reachable,
            latency_ms=latency_ms,
            consecutive_failures=self._consecutive_failures,
            detail=None if reachable else "ping returned false",
        )

    async def close(self) -> None:
        try:
            await self.backend.close()
        except Exception as exc:
            logger.warning("cache_close_failed", error=type(exc).__name__)

    def _record_failure(self, operation: str, key: str, exc: Exception) -> None:
        self._consecutive_failures += 1
        # Log the first failure of a streak at warning level and subsequent ones
        # at debug: a prolonged outage must not flood the log stream.
        log = logger.warning if self._consecutive_failures == 1 else logger.debug
        log(
            "cache_operation_failed",
            operation=operation,
            key_prefix=key[:64],
            cache_backend=self.backend.name,
            error=type(exc).__name__,
            consecutive_failures=self._consecutive_failures,
        )


# ---------------------------------------------------------------------------
# Process-wide instance
# ---------------------------------------------------------------------------
_INSTANCE: Cache | None = None

#: A shared no-op cache returned before initialisation and after reset. Reusing
#: one instance keeps `get_cache()` allocation-free on a hot path.
_NULL_CACHE = Cache(backend=NullCache())


def init_cache(settings: Settings, *, force: bool = False) -> Cache:
    """
    Build the cache from settings and store it process-wide.

    Idempotent unless ``force=True``; tests use the force path to bind a fresh
    in-process backend per run.
    """
    global _INSTANCE

    if _INSTANCE is not None and not force:
        return _INSTANCE

    if settings.redis_adapter == "fakeredis":
        backend: CacheBackend = FakeRedisCacheBackend()
    else:
        backend = RedisCacheBackend(settings.redis_url)

    _INSTANCE = Cache(backend=backend, default_ttl_seconds=settings.cache_ttl_seconds)
    logger.debug(
        "cache_initialised",
        cache_backend=_INSTANCE.name,
        is_simulated=_INSTANCE.is_simulated,
    )
    return _INSTANCE


def get_cache() -> Cache:
    """
    Return the process-wide cache.

    Falls back to a no-op cache when nothing has been initialised (for example
    when a service function is imported and called directly by a test), so a
    missing cache degrades to "no caching" rather than raising.
    """
    return _INSTANCE if _INSTANCE is not None else _NULL_CACHE


def reset_cache() -> None:
    """Drop the process-wide cache. Used only by tests."""
    global _INSTANCE
    _INSTANCE = None
