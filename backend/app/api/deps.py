"""
Shared FastAPI dependencies.

A dependency is the only sanctioned way for a route to obtain infrastructure.
Routes never construct an engine, a cache client or an HTTP client themselves:
doing so would bypass the lifecycle managed by the application and make the
resource impossible to substitute in tests.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Awaitable, Callable
from datetime import datetime
from typing import Annotated
from uuid import UUID

from fastapi import Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.context import Actor
from app.authorization.resolution import resolve_permissions
from app.authorization.tokens import decode_access_token
from app.core.cache import Cache, get_cache
from app.core.config import Settings, get_settings
from app.core.errors import (
    AuthenticationError,
    AuthenticationStateChangedError,
    ErrorCode,
    PermissionDeniedError,
)
from app.core.logging import get_logger
from app.db.rls import apply_tenant_context
from app.db.session import Database, get_database
from app.models._enums import TenantStatus, UserStatus
from app.models.identity import Session, Tenant, User

__all__ = [
    "AuthenticatedActor",
    "CacheDep",
    "CurrentActor",
    "DatabaseDep",
    "SessionDep",
    "SettingsDep",
    "TenantSessionDep",
    "get_current_actor",
    "get_session",
    "get_tenant_session",
    "require_authenticated",
    "require_permission",
]


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


async def get_session(
    database: Annotated[Database, Depends(get_database_dep)],
) -> AsyncIterator[AsyncSession]:
    """
    Yield a request-scoped database session.

    The session is **not** committed here. Transaction boundaries belong to the
    service performing the operation, because several operations must be atomic
    across bounded contexts (for example: completing a collection writes a
    collection event, a waste load, an audit row and an outbox event, and a
    partial write of those would corrupt operational records).

    Ordinary exceptions roll back. AuthenticationStateChangedError is the sole
    exception: a completed security denial must persist counters, audit records
    and replay revocations even though its HTTP response is an error.
    Long-running work — route optimisation, forecasting, report generation — must not hold this
    session open while it computes; it reads, closes the transaction, computes,
    then writes in a second short transaction.
    """
    session = database.session()
    try:
        yield session
    except AuthenticationStateChangedError:
        # A denied login/replayed refresh is still a completed security event.
        # Rolling it back would disable lockout and resurrect stolen sessions.
        await session.commit()
        raise
    except Exception:
        await session.rollback()
        raise
    finally:
        await session.close()


SettingsDep = Annotated[Settings, Depends(get_settings_dep)]
DatabaseDep = Annotated[Database, Depends(get_database_dep)]
CacheDep = Annotated[Cache, Depends(get_cache_dep)]
SessionDep = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------------------------------------------------------
# Authentication and tenant binding
# ---------------------------------------------------------------------------
# These live in the API layer rather than in ``app.authorization`` because they
# are HTTP concerns: they read headers, they are resolved by FastAPI's dependency
# system, and they would otherwise force the authorization layer (which sits
# *below* services in the dependency order enforced by
# ``tests/architecture/test_import_rules.py``) to import from the API layer above
# it. The authorization rules themselves stay in ``app.authorization``; only the
# plumbing that hands them to a request lives here.
#
# The chain for a protected route is:
#
# ``get_current_actor``
#     reads the ``Authorization`` header, verifies the token, loads the live
#     session, resolves the user's roles and permissions, and returns an
#     :class:`~app.authorization.context.Actor`;
# ``require_permission(...)``
#     a dependency factory that denies the request unless the actor holds every
#     listed code;
# ``get_tenant_session``
#     a session whose transaction is bound to the actor's tenant, so PostgreSQL
#     row-level security is the last line of defence rather than the only one.
#
# Routes declare the permissions they need as a dependency rather than checking a
# role: a role is a tenant-editable bundle, so a check written against a role name
# stops working the first time an administrator reorganises their roles
# (``rbac.md`` §1). ``tests/architecture/test_route_inventory.py`` fails if a
# non-public route declares nothing.

logger = get_logger(__name__)


def _now() -> datetime:
    from app.core.time import utc_now

    return utc_now()


async def get_current_actor(
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> Actor:
    """
    Authenticate the request from its bearer token.

    The token is verified without touching the database, but the *session* it
    names is checked live, which is what makes revocation immediate: a signed
    token is not enough on its own.

    Failure messages are deliberately uniform for "no token", "bad token" and
    "unknown user". Distinguishing them would tell an attacker whether an email
    address exists.
    """
    header = request.headers.get("Authorization")
    if not header:
        raise AuthenticationError(
            code=ErrorCode.AUTHENTICATION_REQUIRED,
            message="Authentication required.",
        )
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        raise AuthenticationError(
            code=ErrorCode.AUTHENTICATION_REQUIRED,
            message="Authentication required.",
        )

    claims = decode_access_token(
        token.strip(),
        secret_key=settings.jwt_secret_key,
        algorithm=settings.jwt_algorithm,
    )

    if claims.session_id is None:
        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID,
            message="Access token is not valid.",
        )

    # The signed tenant claim is verified before any tenant-scoped query. RLS
    # and explicit predicates must both agree on the token's entire identity.
    await apply_tenant_context(session, claims.tenant_id)
    tenant = await session.get(Tenant, claims.tenant_id)
    if (
        tenant is None
        or tenant.deleted_at is not None
        or tenant.status not in (TenantStatus.ACTIVE, TenantStatus.TRIAL)
    ):
        raise AuthenticationError(
            code=ErrorCode.ACCOUNT_SUSPENDED, message="This account cannot sign in."
        )
    live_session = (
        await session.execute(
            select(Session).where(
                Session.id == claims.session_id,
                Session.tenant_id == claims.tenant_id,
                Session.user_id == claims.subject,
            )
        )
    ).scalar_one_or_none()
    if live_session is None or live_session.revoked_at is not None:
        raise AuthenticationError(
            code=ErrorCode.SESSION_REVOKED,
            message="Session is no longer valid. Sign in again.",
        )
    if live_session.expires_at <= _now():
        raise AuthenticationError(
            code=ErrorCode.SESSION_REVOKED,
            message="Session has expired. Sign in again.",
        )

    user = (
        await session.execute(
            select(User).where(
                User.id == claims.subject,
                User.tenant_id == claims.tenant_id,
                User.deleted_at.is_(None),
            )
        )
    ).scalar_one_or_none()
    if user is None:
        raise AuthenticationError(
            code=ErrorCode.AUTHENTICATION_REQUIRED,
            message="Authentication required.",
        )
    if user.status is not UserStatus.ACTIVE:
        raise AuthenticationError(
            code=ErrorCode.ACCOUNT_SUSPENDED
            if user.status is UserStatus.SUSPENDED
            else ErrorCode.ACCOUNT_LOCKED,
            message="This account cannot sign in.",
        )
    if user.locked_until is not None and user.locked_until > _now():
        raise AuthenticationError(
            code=ErrorCode.ACCOUNT_LOCKED,
            message="This account is temporarily locked.",
        )

    role_codes, permission_codes = await resolve_permissions(
        session, claims.tenant_id, claims.subject
    )
    actor = Actor(
        user_id=user.id,
        tenant_id=claims.tenant_id,
        email=user.email,
        full_name=user.full_name,
        permissions=permission_codes,
        roles=role_codes,
        session_id=live_session.id,
        auth_type="USER",
        is_platform_operator=claims.tenant_id == _platform_tenant_id(),
    )
    request.state.actor = actor
    return actor


def _platform_tenant_id() -> UUID:
    from app.db.base import PLATFORM_SCOPE_ID

    return PLATFORM_SCOPE_ID


async def require_authenticated(actor: Annotated[Actor, Depends(get_current_actor)]) -> Actor:
    """Any authenticated actor, regardless of permissions."""
    return actor


# ``require_authenticated`` and ``get_current_actor`` are authentication, not
# authorization: they prove *who* is calling without asserting what they may do.
# Marking them lets ``tests/architecture/test_route_inventory.py`` tell a route
# that is protected by a bearer token from one that is genuinely unprotected,
# instead of forcing every authenticated route to declare a permission it does not
# actually need.
require_authenticated.__ecomind_requires_authentication__ = True  # type: ignore[attr-defined]
get_current_actor.__ecomind_requires_authentication__ = True  # type: ignore[attr-defined]


def require_permission(*codes: str) -> Callable[[Actor], Awaitable[Actor]]:
    """
    A dependency that denies the request unless every code in ``codes`` is held.

    Returned as a callable so a route can declare exactly what it needs in one
    line, and so the declared set is readable in the route signature — which is
    what ``tests/architecture/test_route_inventory.py`` inspects.

    All codes are required, not any of them: a route that accepts several codes
    is usually two routes that were merged, and merging them makes the permission
    model impossible to reason about.
    """

    async def _dependency(actor: Annotated[Actor, Depends(get_current_actor)]) -> Actor:
        missing = [code for code in codes if not actor.has_permission(code)]
        if missing:
            logger.info(
                "authorization denied",
                user_id=str(actor.user_id),
                tenant_id=str(actor.tenant_id),
                missing=missing,
            )
            raise PermissionDeniedError(
                message="You do not have permission to perform this action.",
                required_permissions=list(codes),
            )
        return actor

    # The declared set is attached to the dependency object rather than inferred
    # from the closure. ``tests/architecture/test_route_inventory.py`` reads it to
    # prove that no mounted operation is unprotected, and a closure is opaque to
    # that check — the endpoint would look unclassified and fail the build.
    _dependency.__ecomind_permissions__ = list(codes)  # type: ignore[attr-defined]
    return _dependency


async def get_tenant_session(
    actor: Annotated[Actor, Depends(get_current_actor)],
    session: SessionDep,
) -> AsyncIterator[AsyncSession]:
    """
    A session whose transaction is bound to the actor's tenant.

    Binding the tenant is what activates the row-level security policies: without
    it, every tenant-scoped table would return zero rows (the policy fails
    closed), which is a safe failure but a broken one. With it, a repository that
    forgets its ``WHERE tenant_id = ...`` is still confined by the database.

    The binding is transaction-local (``set_config(..., true)``), so it cannot
    leak into the next request that reuses the pooled connection.
    """
    await apply_tenant_context(session, actor.tenant_id)
    # The parent get_session dependency owns commit/rollback/close. Rolling back
    # here first would erase durable authentication-denial writes on unwinding.
    yield session


#: The authenticated actor for a request.
#:
#: ``Depends`` is explicit rather than a bare callable inside ``Annotated``, and
#: that is not stylistic. FastAPI treats ``Annotated[Actor, some_callable]`` as a
#: *request field* annotated with a Pydantic type, not as a dependency: the actor
#: would then be parsed from the request body and every route would appear to have
#: no authentication at all. ``tests/architecture/test_route_inventory.py`` fails
#: the build on exactly that shape, which is how this was caught.
CurrentActor = Annotated[Actor, Depends(get_current_actor)]

#: An actor that must at least be authenticated, with no permission required.
AuthenticatedActor = Annotated[Actor, Depends(require_authenticated)]

#: A session whose transaction is already bound to the actor's tenant.
TenantSessionDep = Annotated[AsyncSession, Depends(get_tenant_session)]
