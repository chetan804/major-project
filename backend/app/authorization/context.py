"""
The authenticated actor: who is calling, in which tenant, with what permissions.

Authorization in EcoMind-AI compares **permission codes**, never role names
(``rbac.md`` §1). A role is a bundle that a tenant may edit, so a check written
against a role name would silently stop working the first time an administrator
reorganised their roles — and would fail *open* for a custom role that happens
to share a name with something else.

The actor is built once per request by :mod:`app.authorization.dependencies` and
carried through the service layer. It is deliberately a value object with no
database handle: a service that needs data takes a repository, not the request.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal
from uuid import UUID

from app.authorization.permissions import PERMISSIONS, PLATFORM_PERMISSION_CODES
from app.core.errors import PermissionDeniedError

__all__ = [
    "SYSTEM_ACTOR",
    "Actor",
    "AuthType",
    "platform_actor",
]

AuthType = Literal["USER", "API_KEY", "SYSTEM"]


@dataclass(frozen=True, slots=True)
class Actor:
    """
    An authenticated principal, scoped to exactly one tenant.

    ``permissions`` is the resolved set the caller holds *right now*. It is
    resolved from the role grants at authentication time and is not cached across
    requests: a revoked grant must take effect on the next request, not whenever
    a cache happens to expire.
    """

    user_id: UUID
    tenant_id: UUID
    email: str
    full_name: str
    permissions: frozenset[str] = field(default_factory=frozenset)
    roles: frozenset[str] = field(default_factory=frozenset)
    session_id: UUID | None = None
    auth_type: AuthType = "USER"
    is_platform_operator: bool = False

    # -- checks --------------------------------------------------------------
    def has_permission(self, code: str) -> bool:
        """
        Whether the actor holds ``code``.

        An unknown code is ``False`` rather than an error. Authorization must fail
        closed: a typo in a route's declared permission would otherwise raise a
        500 on every request instead of denying access, and a missing catalogue
        entry can never be a reason to allow something.
        """
        if code not in PERMISSIONS:
            return False
        return code in self.permissions

    def has_any_permission(self, *codes: str) -> bool:
        """Whether the actor holds at least one of ``codes``."""
        return any(self.has_permission(code) for code in codes)

    def has_all_permissions(self, *codes: str) -> bool:
        """Whether the actor holds every one of ``codes``."""
        return all(self.has_permission(code) for code in codes)

    def require_permission(self, code: str) -> None:
        """
        Raise :class:`PermissionDeniedError` unless the actor holds ``code``.

        The service layer calls this on every mutation. It duplicates the router's
        check on purpose: the two are independent enforcement points
        (``rbac.md`` §3), so a service reached by a job, a worker or a future
        entry point is still guarded.
        """
        if not self.has_permission(code):
            raise PermissionDeniedError(
                message=f"Permission required: {code}",
                required_permissions=[code],
            )

    def require_any_permission(self, *codes: str) -> None:
        if not self.has_any_permission(*codes):
            raise PermissionDeniedError(
                message="None of the required permissions are held.",
                required_permissions=list(codes),
            )

    def describe(self) -> dict[str, object]:
        """
        A safe summary for logs and for ``created_by`` attribution.

        Contains no credential material and no token: this dict is what an audit
        row is allowed to know about its actor.
        """
        return {
            "user_id": str(self.user_id),
            "tenant_id": str(self.tenant_id),
            "email": self.email,
            "roles": sorted(self.roles),
            "auth_type": self.auth_type,
        }


def platform_actor(
    *,
    tenant_id: UUID,
    permissions: frozenset[str] | set[str],
    email: str = "platform@ecomind.internal",
    full_name: str = "Platform operator",
    user_id: UUID | None = None,
) -> Actor:
    """
    The actor used by platform tooling and provisioning.

    Platform operators live in the platform tenant (id
    ``00000000-0000-0000-0000-000000000000``), which is a real tenant row rather
    than a ``NULL`` — a null tenant id is invisible under row-level security, so
    such a user could never authenticate at all.
    """
    return Actor(
        user_id=user_id or tenant_id,
        tenant_id=tenant_id,
        email=email,
        full_name=full_name,
        permissions=frozenset(permissions),
        roles=frozenset({"PLATFORM_OPERATOR"}),
        auth_type="SYSTEM",
        is_platform_operator=True,
    )


#: The actor used by migrations, CLI seeding and background jobs.
#:
#: It is a real actor with a real, bounded permission set — the platform-scoped
#: catalogue plus tenant administration — rather than an implicit bypass. A
#: "bypass everything" system actor would be the one place where every rule this
#: codebase enforces stops applying, and the first thing an attacker would try
#: to reach. It exists so that provisioning writes audit rows naming an author,
#: not so that a job can skip a check.
SYSTEM_ACTOR = Actor(
    user_id=UUID("00000000-0000-0000-0000-000000000000"),
    tenant_id=UUID("00000000-0000-0000-0000-000000000000"),
    email="system@ecomind.internal",
    full_name="EcoMind system",
    permissions=frozenset(PLATFORM_PERMISSION_CODES)
    | frozenset({"tenants.manage", "users.write", "roles.write", "audit.read"}),
    roles=frozenset({"SYSTEM"}),
    auth_type="SYSTEM",
    is_platform_operator=True,
)
