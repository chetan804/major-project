"""
Shared FastAPI dependencies.

A dependency is the only sanctioned way for a route to obtain infrastructure.
Routes never construct an engine, a cache client or an HTTP client themselves:
doing so would bypass the lifecycle managed by the application and make the
resource impossible to substitute in tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.cache import Cache, get_cache
from app.core.config import Settings, get_settings
from app.db.session import Database, get_database

__all__ = ["CacheDep", "DatabaseDep", "SessionDep", "SettingsDep", "get_session"]


def get_settings_dep(request: Request) -> Settings:
    """
    The :class:`Settings` the running application was built with.

    Resolution order, and why it is this way round:

    1. ``request.app.state.settings`` — set by :func:`app.main.create_app`. This is
       the object the app was actually constructed and wired with, so every route
       observes exactly one configuration.
    2. the process-wide cached settings — only for an app instance that was never
       given an explicit object.

    Reading a process-global cache first, as an earlier revision did, meant an app
    built with explicit settings (the test harness, a CLI, a future multi-tenant
    worker) silently served routes from ambient configuration instead. That is not
    a test inconvenience: it is the same class of defect as a request being served
    under another tenant's context, so it is corrected at the dependency rather
    than worked around in the tests. ``tests/architecture/test_route_inventory.py``
    and ``tests/test_health.py`` both fail if this regresses.
    """
    settings = getattr(request.app.state, "settings", None)
    if isinstance(settings, Settings):
        return settings
    return get_settings()


def get_database_dep(request: Request) -> Database:
    """
    The :class:`Database` bound to this application's lifespan.

    Falls back to the process-wide singleton so the function remains usable
    outside a request (a startup hook or a script), but a request always receives
    the handle the app itself opened — never one opened from ambient environment.
    """
    database = getattr(request.app.state, "database", None)
    if isinstance(database, Database):
        return database
    return get_database()


def get_cache_dep(request: Request) -> Cache:
    """The :class:`Cache` bound to this application's lifespan, else the singleton."""
    cache = getattr(request.app.state, "cache", None)
    if isinstance(cache, Cache):
        return cache
    return get_cache()


async def get_session(request: Request) -> AsyncIterator[AsyncSession]:
    """
    Yield a request-scoped database session.

    The session is **not** committed here. Transaction boundaries belong to the
    service performing the operation, because several operations must be atomic
    across bounded contexts (for example: completing a collection writes a
    collection event, a waste load, an audit row and an outbox event, and a
    partial write of those would corrupt operational records).

    An exception escaping the request rolls the transaction back, so a failed
    request can never leave a half-applied write behind. Long-running work —
    route optimisation, forecasting, report generation — must not hold this
    session open while it computes; it reads, closes the transaction, computes,
    then writes in a second short transaction.
    """
    database = get_database_dep(request)
    session = database.session()
    try:
        yield session
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DatabaseDep = Annotated[Database, Depends(get_database_dep)]
CacheDep = Annotated[Cache, Depends(get_cache_dep)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]
