"""
Authorization checks used by the service layer.

These duplicate the router's permission check, and that duplication is the point.
``rbac.md`` §3 names three independent enforcement points — the router, the
service and the database policy — because a check that exists in only one of them
protects only one way in. A service is reachable from a router today, but also
from a background job, a worker and a future entry point, and it must not depend
on its caller having remembered to check.

The functions here are deliberately small and total: they either return or raise,
so a caller cannot forget to handle a result.
"""

from __future__ import annotations

from collections.abc import Iterable
from uuid import UUID

from app.authorization.context import Actor
from app.core.errors import NotFoundError, PermissionDeniedError

__all__ = [
    "ensure_any_permission",
    "ensure_own_or_permission",
    "ensure_permission",
    "ensure_tenant_match",
]


def ensure_permission(actor: Actor, code: str) -> None:
    """Raise unless ``actor`` holds ``code``."""
    actor.require_permission(code)


def ensure_any_permission(actor: Actor, codes: Iterable[str]) -> None:
    """Raise unless ``actor`` holds at least one of ``codes``."""
    required = tuple(codes)
    if not actor.has_any_permission(*required):
        raise PermissionDeniedError(
            message="None of the required permissions are held.",
            required_permissions=list(required),
        )


def ensure_own_or_permission(
    actor: Actor,
    *,
    owner_user_id: UUID | None,
    permission: str,
    own_permission: str | None = None,
) -> None:
    """
    Allow an action on the actor's own record, or on any record with ``permission``.

    This is how the ``.own`` permission family works (``rbac.md`` §2): a driver may
    complete *their* collection without being able to complete anyone else's. The
    broad permission is checked first, because a dispatcher who also happens to be
    assigned a stop should not be constrained to the narrow path.

    ``owner_user_id`` of ``None`` means "unowned record", which only the broad
    permission can reach — otherwise any caller would own every unassigned record.
    """
    if actor.has_permission(permission):
        return
    if own_permission and owner_user_id is not None and owner_user_id == actor.user_id:
        if actor.has_permission(own_permission):
            return
        raise PermissionDeniedError(
            message=f"Permission required: {own_permission}",
            required_permissions=[own_permission],
        )
    raise PermissionDeniedError(
        message=f"Permission required: {permission}",
        required_permissions=[permission],
    )


def ensure_tenant_match(
    actor: Actor,
    tenant_id: UUID | str | None,
    *,
    resource_type: str,
    resource_id: str | None = None,
) -> None:
    """
    Refuse to act on a row that belongs to another tenant.

    The failure is a **404**, not a 403. A 403 would confirm that the record
    exists, which turns a permission error into an enumeration oracle for
    another tenant's data (ADR-0003). ``NotFoundError`` is deliberately the same
    error a genuinely absent record raises, so the two are indistinguishable from
    outside.

    A ``None`` tenant id is treated as a mismatch rather than as "no restriction":
    an unowned row is one the caller cannot have come by legitimately.
    """
    if tenant_id is None or str(tenant_id) != str(actor.tenant_id):
        raise NotFoundError(resource_type=resource_type, resource_id=resource_id)
