"""IP budgets before body parsing; account budgets before database lookups."""

from __future__ import annotations

from fastapi import Request
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.config import Settings
from app.core.errors import AppError
from app.core.rate_limits import AuthRateLimiter
from app.core.responses import error_response


def limiter_for(request: Request) -> AuthRateLimiter:
    return request.app.state.auth_rate_limiter  # type: ignore[no-any-return]


async def account_limit(
    request: Request, settings: Settings, action: str, *identifiers: str
) -> None:
    recovery = action == "recovery_request"
    await limiter_for(request).check(
        action,
        tuple(s.strip().lower() for s in identifiers),
        settings.recovery_account_limit if recovery else settings.auth_account_limit,
        settings.recovery_window_seconds if recovery else settings.auth_account_window_seconds,
    )


class AuthRateLimitMiddleware:
    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        self.app = app
        self.settings = settings

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http" and scope["method"] == "POST":
            prefix = self.settings.api_v1_prefix + "/auth"
            path = scope["path"].rstrip("/")
            group = None
            limit, window = self.settings.auth_ip_limit, 60
            if path in {
                prefix + "/login",
                prefix + "/refresh",
                prefix + "/me/password",
                self.settings.api_v1_prefix + "/platform/auth/step-up",
            } or path in {
                self.settings.api_v1_prefix + "/platform/auth/mfa" + suffix
                for suffix in ("/enrollment", "/enrollment/confirm", "/recovery-codes")
            }:
                group = "credentials"
            elif path == self.settings.api_v1_prefix + "/platform/operators" or path.startswith(
                self.settings.api_v1_prefix + "/platform/operators/"
            ):
                group = "platform_operators"
            elif path in {prefix + "/password-reset", prefix + "/email/verify-request"}:
                group = "recovery_request"
                limit, window = (
                    self.settings.recovery_ip_limit,
                    self.settings.recovery_window_seconds,
                )
            elif path in {prefix + "/password-reset/confirm", prefix + "/email/verify-confirm"}:
                group = "recovery_confirm"
            if group is not None:
                # Forwarded headers are NOT parsed here. Trusted proxy handling
                # belongs to the ASGI server/reverse proxy, not client input.
                ip = scope.get("client", (None,))[0] if scope.get("client") else "unknown"
                limiter: AuthRateLimiter = scope["app"].state.auth_rate_limiter
                try:
                    await limiter.check("ip:" + group, (str(ip),), limit, window)
                except AppError as exc:
                    response = error_response(exc)
                    response.headers["Cache-Control"] = "no-store"
                    await response(scope, receive, send)
                    return

        async def send_private(message: Message) -> None:
            if (
                message["type"] == "http.response.start"
                and scope["type"] == "http"
                and (
                    scope["path"].startswith(self.settings.api_v1_prefix + "/auth/")
                    or scope["path"].startswith(self.settings.api_v1_prefix + "/platform/operators")
                    or scope["path"].startswith(self.settings.api_v1_prefix + "/platform/auth/mfa")
                    or scope["path"].rstrip("/")
                    == self.settings.api_v1_prefix + "/platform/auth/step-up"
                )
            ):
                message["headers"] = [
                    (k, v) for k, v in message.get("headers", []) if k.lower() != b"cache-control"
                ] + [(b"cache-control", b"no-store")]
            await send(message)

        await self.app(scope, receive, send_private)
