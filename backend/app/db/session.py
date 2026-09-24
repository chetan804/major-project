"""
Database engine and session lifecycle.

One :class:`Database` instance owns the async engine and session factory for the
process. The application lifespan creates it; tests create their own bound to an
isolated database, which is why the engine is injectable rather than a
module-level global created at import time.

Transaction policy
------------------
The API's request-scoped dependency yields a session and never commits
implicitly: a service decides where a transaction boundary belongs. This matters
because several operations must be atomic across contexts — completing a
collection writes a collection event, a waste load, an audit row and an outbox
event, and a partial write of those four would corrupt operational records.

Pool policy
-----------
``pool_pre_ping`` guards against a connection killed by a network device or an
idle timeout, which otherwise surfaces as a spurious 500 on the first request
after an idle period. ``pool_recycle`` bounds connection age below typical
managed-PostgreSQL idle limits. Tests may request ``NullPool`` so that no
connection is retained across pytest's per-test event loops.
"""

from __future__ import annotations

import re
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit, urlunsplit

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool

from app.core.logging import get_logger

logger = get_logger(__name__)

__all__ = [
    "MINIMUM_POSTGRES_VERSION_NUM",
    "Database",
    "DatabaseHealth",
    "get_database",
    "init_database",
    "reset_database",
    "safe_database_url",
]

#: gen_random_uuid() became a built-in in PostgreSQL 13; below that the schema
#: would require the pgcrypto extension, which is not available everywhere
#: (see docs/environment.md). Checked at startup and reported by /ready.
MINIMUM_POSTGRES_VERSION_NUM = 130000

_URL_PASSWORD_PATTERN = re.compile(r"(?i)(://[^:/@\s]+):[^@/\s]*@")


def safe_database_url(url: str) -> str:
    """
    Render a database URL with any password removed.

    Used in logs, health output and error messages. A connection string is a
    credential, and credentials must not reach logs (REQ-SEC-006).
    """
    if "://" not in url:
        return url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _URL_PASSWORD_PATTERN.sub(r"\1:[redacted]@", url)
    if parts.password is None:
        return url
    userinfo = parts.username or ""
    host = parts.hostname or ""
    if parts.port:
        host = f"{host}:{parts.port}"
    netloc = f"{userinfo}:[redacted]@{host}" if userinfo else host
    return urlunsplit((parts.scheme, netloc, parts.path, parts.query, parts.fragment))


def _pool_metric(pool: object, attribute: str) -> int | None:
    """
    Read an integer metric from a SQLAlchemy pool.

    In SQLAlchemy 2.x these metrics are **methods** (``QueuePool.size()``,
    ``QueuePool.checkedout()``), not attributes, and ``NullPool`` does not expose
    all of them. A bare ``getattr`` therefore returns a bound method, which
    silently breaks JSON serialisation of the health payload. Calling when
    callable, and tolerating absence, keeps this correct across pool types.
    """
    raw = getattr(pool, attribute, None)
    if raw is None:
        return None
    try:
        value = raw() if callable(raw) else raw
    except Exception:
        return None
    return int(value) if isinstance(value, (int, float)) else None


@dataclass(slots=True)
class DatabaseHealth:
    """Result of a database probe, shaped for the ``/ready`` payload."""

    reachable: bool
    latency_ms: float | None = None
    server_version: str | None = None
    server_version_num: int | None = None
    pool_size: int | None = None
    pool_checked_out: int | None = None
    detail: str | None = None

    @property
    def supported(self) -> bool:
        """Whether the server meets the minimum version for this schema."""
        if self.server_version_num is None:
            return False
        return self.server_version_num >= MINIMUM_POSTGRES_VERSION_NUM

    def as_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {"status": "ok" if self.reachable else "unavailable"}
        if self.server_version:
            payload["server_version"] = self.server_version
        if self.latency_ms is not None:
            payload["latency_ms"] = round(self.latency_ms, 3)
        # The pool block is always present so the response shape is stable for
        # consumers. A pool type that does not expose these metrics (NullPool, used
        # in tests and behind an external pooler) reports null rather than
        # omitting the key, which would otherwise force every consumer to handle
        # two different shapes.
        if self.reachable:
            payload["pool"] = {
                "size": self.pool_size,
                "checked_out": self.pool_checked_out,
                "metrics_available": self.pool_size is not None,
            }
        if self.reachable and not self.supported:
            payload["status"] = "degraded"
            payload["detail"] = (
                f"PostgreSQL {MINIMUM_POSTGRES_VERSION_NUM // 10000}+ is required "
                "(gen_random_uuid is a built-in from version 13)."
            )
        elif self.detail:
            payload["detail"] = self.detail
        return payload


class Database:
    """Owns the async engine and session factory."""

    def __init__(
        self,
        url: str,
        *,
        pool_size: int = 10,
        max_overflow: int = 20,
        pool_recycle_seconds: int = 1800,
        echo: bool = False,
        use_null_pool: bool = False,
    ) -> None:
        self.url = url
        self.safe_url = safe_database_url(url)

        engine_kwargs: dict[str, Any] = {
            "echo": echo,
            "pool_pre_ping": True,
            # The default asyncpg statement cache can conflict with PgBouncer in
            # transaction mode; disabling it keeps the driver usable behind the
            # pooling layers production deployments commonly add.
            "connect_args": {"statement_cache_size": 0},
        }
        if use_null_pool:
            engine_kwargs["poolclass"] = NullPool
        else:
            engine_kwargs["pool_size"] = pool_size
            engine_kwargs["max_overflow"] = max_overflow
            engine_kwargs["pool_recycle"] = pool_recycle_seconds

        self._engine: AsyncEngine = create_async_engine(url, **engine_kwargs)
        # expire_on_commit=False so an object stays usable after commit without
        # triggering a lazy refresh; the API serialises from Pydantic schemas
        # built inside the transaction, so this avoids surprise extra queries.
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=False,
        )

    @property
    def engine(self) -> AsyncEngine:
        return self._engine

    def session(self) -> AsyncSession:
        """Create a new session. The caller owns its lifecycle."""
        return self._session_factory()

    @asynccontextmanager
    async def session_scope(self) -> AsyncIterator[AsyncSession]:
        """
        Transactional scope: commit on success, roll back on any exception.

        Long-running operations such as route optimisation must not run inside
        this scope — they would hold a connection and a transaction open for the
        duration of the solve. They read, close the transaction, compute, then
        write in a second short transaction.
        """
        session = self._session_factory()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()

    async def health(self, *, timeout_seconds: float = 3.0) -> DatabaseHealth:
        """
        Probe the database.

        Never raises: a readiness endpoint that can itself fail is useless, so
        every failure mode is converted into an unavailable :class:`DatabaseHealth`.
        """
        started = time.perf_counter()
        try:
            async with self._engine.connect() as connection:
                row = (
                    await connection.execute(
                        text(
                            "SELECT current_setting('server_version') AS version, "
                            "current_setting('server_version_num')::int AS version_num"
                        )
                    )
                ).one()
            latency_ms = (time.perf_counter() - started) * 1000
        except SQLAlchemyError as exc:
            return DatabaseHealth(reachable=False, detail=type(exc).__name__)
        except Exception as exc:
            return DatabaseHealth(reachable=False, detail=type(exc).__name__)

        pool = self._engine.pool
        return DatabaseHealth(
            reachable=True,
            latency_ms=latency_ms,
            server_version=str(row.version),
            server_version_num=int(row.version_num),
            pool_size=_pool_metric(pool, "size"),
            pool_checked_out=_pool_metric(pool, "checkedout"),
        )

    async def dispose(self) -> None:
        """Close the pool. Called during application shutdown."""
        await self._engine.dispose()


# ---------------------------------------------------------------------------
# Process-wide instance
# ---------------------------------------------------------------------------
_INSTANCE: Database | None = None


def init_database(
    url: str,
    *,
    pool_size: int = 10,
    max_overflow: int = 20,
    pool_recycle_seconds: int = 1800,
    echo: bool = False,
    use_null_pool: bool = False,
    force: bool = False,
) -> Database:
    """
    Create and publish the process-wide database, or return the existing one.

    ``force=True`` replaces any existing instance, which tests use to bind an
    isolated database on a NullPool. The previous instance is *not* disposed
    here because disposal is asynchronous and this function is synchronous;
    callers that replace an instance dispose it themselves.
    """
    global _INSTANCE
    if _INSTANCE is not None and not force:
        return _INSTANCE
    _INSTANCE = Database(
        url,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_recycle_seconds=pool_recycle_seconds,
        echo=echo,
        use_null_pool=use_null_pool,
    )
    logger.debug("database_initialised", database=safe_database_url(url))
    return _INSTANCE


def get_database() -> Database:
    """
    Return the process-wide database.

    Raises a ``RuntimeError`` rather than lazily creating one: a lazily created
    engine would read the URL from whatever environment happened to be set,
    which in a test process could silently point at the development database.
    """
    if _INSTANCE is None:
        raise RuntimeError(
            "Database is not initialised. The application lifespan calls "
            "init_database(); tests must call it in a fixture."
        )
    return _INSTANCE


def reset_database() -> None:
    """Drop the process-wide database reference. Used only by tests."""
    global _INSTANCE
    _INSTANCE = None
