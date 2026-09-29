"""Fail-closed startup inventory of the *mounted* HTTP surface (ADR-0023).

Do not use OpenAPI for authorization discovery: hidden routes exist. FastAPI's
included-router contexts are version-sensitive; unsupported surfaces fail closed.
No application routes may be registered after startup.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from fastapi.dependencies.utils import get_parameterless_sub_dependant
from fastapi.params import Depends
from starlette.routing import Mount, WebSocketRoute

from app.api.deps import get_current_actor
from app.authorization.permissions import PERMISSION_CODES

PUBLIC_SYSTEM: dict[tuple[str, str], str] = {
    ("GET", "/health"): "Liveness, with no tenant data.",
    ("GET", "/ready"): "Dependency readiness for the orchestrator.",
    ("GET", "/metrics"): "Prometheus; ingress must restrict this in production.",
    ("GET", "/openapi.json"): "Machine-readable API contract.",
    ("GET", "/docs"): "Interactive API contract.",
    ("GET", "/docs/oauth2-redirect"): "Framework-generated documentation helper.",
}
PUBLIC_AUTH: dict[tuple[str, str], str] = {
    ("POST", "/auth/login"): "Exchange credentials for a first session.",
    ("POST", "/auth/refresh"): "The opaque refresh token is the credential.",
    ("POST", "/auth/password-reset"): "Neutral public recovery request.",
    ("POST", "/auth/password-reset/confirm"): "An expiring one-time token authorizes reset.",
    ("POST", "/auth/email/verify-request"): "Invited users have no bearer session yet.",
    ("POST", "/auth/email/verify-confirm"): "An expiring one-time token proves mailbox ownership.",
}
SELF_SERVICE: dict[tuple[str, str], str] = {
    ("GET", "/users/me/permissions"): "Only the authenticated caller's resolved grants.",
    ("GET", "/auth/me"): "Authenticated caller's own profile.",
    ("PATCH", "/auth/me"): "Closed own-profile fields; not role or account administration.",
    ("POST", "/auth/me/password"): "Own password change with current password verification.",
    ("POST", "/auth/logout"): "Revoke the caller's session.",
    ("POST", "/auth/logout-all"): "Revoke the caller's sessions.",
    ("GET", "/auth/sessions"): "Only the caller's sessions.",
    ("DELETE", "/auth/sessions/{session_id}"): "Ownership checked before revocation.",
}
PERMISSION_MARKER = "__ecomind_permissions__"


@dataclass(frozen=True)
class RouteSurface:
    path: str
    methods: frozenset[str]
    dependencies: tuple[Any, ...]
    include_in_schema: bool
    route: Any


def mounted_surface(app: Any) -> Iterator[RouteSurface]:
    for entry in app.routes:
        if isinstance(entry, (Mount, WebSocketRoute)):
            raise RuntimeError(
                "Route policy does not support mounts or WebSockets; review authorization first."
            )
        contexts = getattr(entry, "effective_route_contexts", None)
        entries = contexts() if callable(contexts) else (entry,)
        for context in entries:
            route = getattr(context, "original_route", context)
            path = getattr(context, "path", None)
            methods = getattr(context, "methods", None)
            if not path or not methods or isinstance(route, (Mount, WebSocketRoute)):
                raise RuntimeError(
                    "Uninspectable route; refusing to omit it from authorization policy."
                )
            yield RouteSurface(
                path=path,
                methods=frozenset(methods),
                dependencies=tuple(getattr(context, "dependencies", ()) or ()),
                include_in_schema=bool(getattr(context, "include_in_schema", True)),
                route=route,
            )


def permission_dependencies(surface: RouteSurface) -> tuple[bool, list[Any]]:
    """Read real dependency nodes, including Depends attached at include time."""
    authenticated = False
    guards: list[Any] = []
    seen: set[int] = set()

    def visit(node: Any, *, root: bool = False) -> None:
        nonlocal authenticated
        if node is None or id(node) in seen:
            return
        seen.add(id(node))
        call = getattr(node, "call", None)
        # Endpoint attributes are not dependency declarations.
        if not root and call is not None:
            authenticated |= call is get_current_actor
            if hasattr(call, PERMISSION_MARKER) and call not in guards:
                guards.append(call)
        for child in getattr(node, "dependencies", ()) or ():
            visit(child)

    visit(getattr(surface.route, "dependant", None), root=True)
    # Keep built trees alive, otherwise ids can be reused between iterations.
    trees = [
        get_parameterless_sub_dependant(depends=dependency, path=surface.path)
        if isinstance(dependency, Depends)
        else dependency
        for dependency in surface.dependencies
    ]
    for tree in trees:
        visit(tree)
    return authenticated, guards


def policy_exceptions(prefix: str) -> tuple[dict[tuple[str, str], str], dict[tuple[str, str], str]]:
    public = {
        **PUBLIC_SYSTEM,
        **{(method, prefix + path): reason for (method, path), reason in PUBLIC_AUTH.items()},
    }
    own = {(method, prefix + path): reason for (method, path), reason in SELF_SERVICE.items()}
    return public, own


def validate_route_policy(app: Any, prefix: str) -> list[RouteSurface]:
    public, own = policy_exceptions(prefix)
    known = set(PERMISSION_CODES)
    seen: set[tuple[str, str]] = set()
    present: set[tuple[str, str]] = set()
    problems: list[str] = []
    surfaces = list(mounted_surface(app))
    for surface in surfaces:
        authenticated, guards = permission_dependencies(surface)
        codes: set[str] = set()
        for guard in guards:
            declared = getattr(guard, PERMISSION_MARKER)
            if (
                not isinstance(declared, (list, tuple))
                or not declared
                or not all(isinstance(code, str) for code in declared)
            ):
                problems.append(f"Malformed permission declaration: {surface.path}")
            else:
                codes.update(declared)
        unknown = codes - known
        if unknown:
            problems.append(f"Unknown permissions on {surface.path}: {sorted(unknown)}")
        for method in sorted(surface.methods):
            # Only an inherited HEAD gets a GET exception, not standalone HEAD.
            policy_method = "GET" if method == "HEAD" and "GET" in surface.methods else method
            operation = (policy_method, surface.path)
            present.add(operation)
            canonical = (method, re.sub(r"\{[^}:]+", "{parameter", surface.path))
            if canonical in seen:
                problems.append(f"Duplicate operation: {method} {surface.path}")
            seen.add(canonical)
            if operation in public:
                if codes or authenticated:
                    problems.append(f"Public exception no longer matches: {operation}")
            elif operation in own:
                if not authenticated:
                    problems.append(f"Self-service operation lacks authentication: {operation}")
            elif not codes or not authenticated:
                problems.append(
                    f"Operation needs authentication and declared permissions: {operation}"
                )
    stale = (public.keys() | own.keys()) - present
    if stale:
        problems.append(f"Stale route-policy exceptions: {sorted(stale)}")
    if problems:
        raise RuntimeError("Unsafe API route policy; refusing startup:\n" + "\n".join(problems))
    return surfaces
