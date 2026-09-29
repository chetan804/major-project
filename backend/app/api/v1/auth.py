"""
Authentication endpoints.

Six operations are public by written decision and appear in
``tests/architecture/test_route_inventory.py::PUBLIC_ROUTES``: login, refresh and
both password-reset operations and both email-verification operations. There is no other way to obtain a first token, so
protecting them would make the API unusable rather than safe.

Everything else requires a bearer token, and the administrative routes additionally
require a permission declared on the route — which is what lets
``tests/architecture/test_route_inventory.py`` prove that no mounted operation is
unprotected.

Note what login does *not* do: it never reports whether an email address exists,
and it returns the same error for an unknown account and a wrong password.
"""

from __future__ import annotations

from uuid import UUID

from fastapi import APIRouter, Depends, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import (
    AuthenticatedActor,
    CurrentActor,
    SessionDep,
    SettingsDep,
    require_permission,
)
from app.api.rate_limits import account_limit
from app.api.schemas.common import Page, PageMeta
from app.api.schemas.identity import (
    EmailVerificationConfirmRequest,
    EmailVerificationRequest,
    LoginRequest,
    MeResponse,
    PasswordChangeRequest,
    PasswordResetConfirmRequest,
    PasswordResetRequest,
    ProfileUpdateRequest,
    RefreshRequest,
    SessionResponse,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
)
from app.authorization.context import SYSTEM_ACTOR, Actor
from app.authorization.tokens import hash_token
from app.core.config import Settings
from app.core.errors import NotFoundError
from app.models.identity import Tenant, User
from app.repositories.identity import (
    AuditLogRepository,
    SessionRepository,
    TenantRepository,
    UserRepository,
)
from app.services.auth import AuthService
from app.services.auth_delivery import AuthDelivery

router = APIRouter(prefix="/auth", tags=["auth"])


def _service_for(
    settings: Settings,
    session: AsyncSession,
    actor: Actor | None,
) -> AuthService:
    """
    Build the auth service for a request.

    The repositories are constructed per call because a repository is bound to a
    tenant, and the tenant is only known once the caller is identified. On the
    public routes ``actor`` is ``None`` and the caller passes the tenant explicitly.
    """
    tenant_id = actor.tenant_id if actor is not None else SYSTEM_ACTOR.tenant_id
    return AuthService(
        settings=settings,
        users=UserRepository(session, tenant_id),
        sessions=SessionRepository(session, tenant_id),
        audit=AuditLogRepository(session, tenant_id),
        tenants=TenantRepository(session),
    )


def _client_ip(request: Request) -> str | None:
    """
    The caller's address, for the audit trail.

    Read from the connection rather than ``X-Forwarded-For``, because a forwarded
    header is client-controlled: trusting it would let anyone write any address into
    the audit log. Behind a proxy the proxy is configured to overwrite that header,
    and the application still records the address it actually saw.
    """
    return request.client.host if request.client else None


def _user_agent(request: Request) -> str | None:
    agent = request.headers.get("User-Agent")
    return agent[:400] if agent else None


def _me_response(user: User, actor: Actor) -> MeResponse:
    """Build the ``/auth/me`` body from a user row and the request's actor."""
    return MeResponse(
        id=user.id,
        email=user.email,
        full_name=user.full_name,
        phone=user.phone,
        status=user.status.value,
        email_verified_at=user.email_verified_at,
        last_login_at=user.last_login_at,
        preferred_timezone=user.preferred_timezone,
        preferred_locale=user.preferred_locale,
        created_at=user.created_at,
        updated_at=user.updated_at,
        tenant_id=user.tenant_id,
        roles=sorted(actor.roles),
        permissions=sorted(actor.permissions),
    )


@router.post(
    "/login", response_model=TokenResponse, summary="Exchange credentials for a token pair"
)
async def login(
    payload: LoginRequest,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> TokenResponse:
    """Sign in. Public by design: there is no other way to obtain a first token."""
    await account_limit(request, settings, "login", payload.tenant_slug, payload.email)
    service = _service_for(settings, session, actor=None)
    result = await service.authenticate(
        email=payload.email,
        password=payload.password,
        tenant_slug=payload.tenant_slug,
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await session.commit()
    return TokenResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=int(settings.access_token_expire_minutes * 60),
        refresh_expires_in=int(settings.refresh_token_expire_days * 86400),
        session_id=result.session_id,
    )


@router.post(
    "/refresh", response_model=TokenResponse, summary="Exchange a refresh token for a new pair"
)
async def refresh(
    payload: RefreshRequest,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> TokenResponse:
    """
    Rotate a token pair.

    The refresh token carries an untrusted tenant routing hint plus random
    secret material. Its full hash must match within that tenant under RLS.
    No bearer token is needed. Reuse revokes the whole rotation family.
    """
    service = _service_for(settings, session, actor=None)
    await account_limit(request, settings, "refresh", hash_token(payload.refresh_token))
    result = await service.refresh(payload.refresh_token)
    await session.commit()
    return TokenResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=int(settings.access_token_expire_minutes * 60),
        refresh_expires_in=int(settings.refresh_token_expire_days * 86400),
        session_id=result.session_id,
    )


def _recovery_response(settings: Settings) -> dict[str, str]:
    return {
        "status": "accepted",
        "message": "If this account is eligible, a code has been queued for delivery. Only the latest code is valid.",
        "delivery_status": "queued_if_eligible",
        "delivery_mode": "local_mailbox" if settings.email_provider == "console" else "smtp",
    }


@router.post(
    "/password-reset", status_code=status.HTTP_202_ACCEPTED, summary="Request a password reset code"
)
async def request_password_reset(
    payload: PasswordResetRequest, request: Request, settings: SettingsDep, session: SessionDep
) -> dict[str, str]:
    # Check delivery configuration before resolving the account so configuration
    # outages and unknown accounts cannot produce distinguishable responses.
    await account_limit(request, settings, "recovery_request", payload.tenant_slug, payload.email)
    AuthDelivery(session, settings).cipher()
    tenant = await TenantRepository(session).get_by_slug(payload.tenant_slug.strip().lower())
    if tenant is not None:
        await _service_for(settings, session, None).request_password_reset_in(
            tenant, email=payload.email
        )
    await session.commit()
    return _recovery_response(settings)


@router.post(
    "/email/verify-request",
    status_code=status.HTTP_202_ACCEPTED,
    summary="Request email verification (including invited accounts)",
)
async def request_email_verification(
    payload: EmailVerificationRequest, request: Request, settings: SettingsDep, session: SessionDep
) -> dict[str, str]:
    await account_limit(request, settings, "recovery_request", payload.tenant_slug, payload.email)
    AuthDelivery(session, settings).cipher()
    tenant = await TenantRepository(session).get_by_slug(payload.tenant_slug.strip().lower())
    if tenant is not None:
        await _service_for(settings, session, None).request_email_verification_in(
            tenant, email=payload.email
        )
    await session.commit()
    return _recovery_response(settings)


@router.post("/email/verify-confirm", summary="Consume a single-use verification code")
async def confirm_email_verification(
    payload: EmailVerificationConfirmRequest,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> dict[str, str]:
    await account_limit(
        request, settings, "recovery_confirm", payload.tenant_slug, hash_token(payload.token)
    )
    tenant = await TenantRepository(session).get_by_slug(payload.tenant_slug.strip().lower())
    if tenant is None:
        from app.core.errors import AuthenticationError, ErrorCode

        raise AuthenticationError(
            code=ErrorCode.TOKEN_INVALID, message="Verification code is not valid."
        )
    await _service_for(settings, session, None).confirm_email_verification_in(
        tenant, token=payload.token
    )
    await session.commit()
    return {"status": "ok", "message": "Email verified. You may now sign in."}


@router.post(
    "/password-reset/confirm",
    status_code=status.HTTP_200_OK,
    summary="Complete a password reset",
)
async def confirm_password_reset(
    payload: PasswordResetConfirmRequest,
    request: Request,
    settings: SettingsDep,
    session: SessionDep,
) -> dict[str, str]:
    """
    Apply a reset token.

    Every existing session for that user is revoked as a side effect: whoever asked
    for the reset may be doing so because someone else is signed in.
    """
    await account_limit(
        request, settings, "recovery_confirm", payload.tenant_slug, hash_token(payload.token)
    )
    tenants = TenantRepository(session)
    tenant = await tenants.get_by_slug(payload.tenant_slug.strip().lower())
    if tenant is None:
        from app.core.errors import AuthenticationError, ErrorCode

        raise AuthenticationError(code=ErrorCode.TOKEN_INVALID, message="Reset token is not valid.")
    service = _service_for(settings, session, actor=None)
    await service.confirm_password_reset_in(
        tenant,
        token=payload.token,
        new_password=payload.new_password,
    )
    await session.commit()
    return {"status": "ok", "message": "Password updated. Sign in with your new password."}


@router.get("/me", response_model=MeResponse, summary="The authenticated caller")
async def me(
    actor: AuthenticatedActor,
    session: SessionDep,
) -> MeResponse:
    """Who am I, and what may I do? Answered from the live role grants."""
    user = await UserRepository(session, actor.tenant_id).get_active(actor.user_id)
    if user is None:
        raise NotFoundError(resource_type="user", resource_id=str(actor.user_id))
    return _me_response(user, actor)


@router.patch("/me", response_model=MeResponse, summary="Update the caller's own profile")
async def update_profile(
    payload: ProfileUpdateRequest,
    actor: AuthenticatedActor,
    session: SessionDep,
) -> MeResponse:
    """
    Change the caller's own name, phone or preferences.

    Email and status are deliberately not editable here: changing an email address
    is a verified operation, and letting a user set their own status would let a
    suspended user re-activate themselves.
    """
    users = UserRepository(session, actor.tenant_id)
    user = await users.get_active(actor.user_id)
    if user is None:
        raise NotFoundError(resource_type="user", resource_id=str(actor.user_id))
    await users.update(user, **payload.model_dump(exclude_unset=True))
    await session.commit()
    return _me_response(user, actor)


@router.post("/me/password", status_code=status.HTTP_200_OK, summary="Change the caller's password")
async def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    actor: AuthenticatedActor,
    settings: SettingsDep,
    session: SessionDep,
) -> dict[str, str]:
    """
    Change a password and revoke every other session.

    Revoking the others is the point: a password change is what a user does when
    they suspect their account is compromised.
    """
    service = _service_for(settings, session, actor)
    await account_limit(
        request, settings, "password_change", str(actor.tenant_id), str(actor.user_id)
    )
    await service.change_password(
        current_password=payload.current_password,
        new_password=payload.new_password,
        actor=actor,
        keep_current_session=actor.session_id,
    )
    await session.commit()
    return {"status": "ok", "message": "Password changed. Other sessions were signed out."}


@router.post(
    "/logout", status_code=status.HTTP_204_NO_CONTENT, summary="Revoke the current session"
)
async def logout(
    actor: AuthenticatedActor,
    settings: SettingsDep,
    session: SessionDep,
) -> Response:
    """Sign out of this device. The access token stops working immediately."""
    service = _service_for(settings, session, actor)
    if actor.session_id is not None:
        await service.logout(actor.session_id, actor=actor)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/logout-all", status_code=status.HTTP_200_OK, summary="Revoke every session")
async def logout_all(
    actor: AuthenticatedActor,
    settings: SettingsDep,
    session: SessionDep,
) -> dict[str, object]:
    """Sign out everywhere, sparing the device making the request."""
    service = _service_for(settings, session, actor)
    revoked = await service.logout_all(
        actor.user_id, actor=actor, except_session_id=actor.session_id
    )
    await session.commit()
    return {"status": "ok", "revoked_sessions": revoked}


@router.get("/sessions", response_model=Page[SessionResponse], summary="The caller's sessions")
async def list_sessions(
    actor: AuthenticatedActor,
    session: SessionDep,
) -> Page[SessionResponse]:
    """
    The devices currently signed in as this user.

    Session tokens are never returned — only their metadata — so this endpoint
    cannot be used to harvest a credential.
    """
    rows = await SessionRepository(session, actor.tenant_id).list_for_user(actor.user_id)
    return Page(
        items=[
            SessionResponse(
                id=row.id,
                issued_at=row.issued_at,
                last_used_at=row.last_used_at,
                expires_at=row.expires_at,
                revoked_at=row.revoked_at,
                user_agent=row.user_agent,
            )
            for row in rows
        ],
        meta=PageMeta.build(page=1, page_size=max(len(rows), 1), total_items=len(rows)),
    )


@router.delete(
    "/sessions/{session_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Revoke one of the caller's sessions",
)
async def revoke_session(
    session_id: UUID,
    actor: AuthenticatedActor,
    settings: SettingsDep,
    session: SessionDep,
) -> Response:
    """
    Sign out one device.

    A session belonging to another user is a 404 rather than a 403, so the endpoint
    cannot be used to enumerate which session identifiers exist.
    """
    target = await SessionRepository(session, actor.tenant_id).get(session_id)
    if target is None or target.user_id != actor.user_id:
        raise NotFoundError(resource_type="session", resource_id=str(session_id))
    service = _service_for(settings, session, actor)
    await service.logout(session_id, actor=actor)
    await session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Invite a user into the caller's tenant",
    dependencies=[Depends(require_permission("users.write"))],
)
async def create_user(
    payload: UserCreateRequest,
    request: Request,
    actor: CurrentActor,
    settings: SettingsDep,
    session: SessionDep,
) -> UserResponse:
    """
    Create a user in the caller's own tenant.

    The permission is declared on the route, which is the first of the three
    enforcement points ``rbac.md`` §3 requires; the repository adds the second by
    refusing to create a row in any other tenant.
    """
    service = _service_for(settings, session, actor)
    result = await service.register(
        email=payload.email,
        password=payload.password,
        full_name=payload.full_name,
        phone=payload.phone,
        actor=actor,
        ip_address=_client_ip(request),
        user_agent=_user_agent(request),
    )
    await session.commit()
    return UserResponse(
        id=result.id,
        email=result.email,
        full_name=result.full_name,
        phone=result.phone,
        status=result.status.value,
        email_verified_at=result.email_verified_at,
        last_login_at=result.last_login_at,
        created_at=result.created_at,
        updated_at=result.updated_at,
        roles=[],
    )


# ``Tenant`` is imported for the type of the rows the reset endpoints resolve; the
# reference keeps the import honest without a runtime dependency on the class.
_TENANT_TYPE = Tenant
