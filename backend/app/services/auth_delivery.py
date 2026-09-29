"""Transactional credential queue and bounded, tenant-scoped delivery batches."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from uuid import UUID, uuid4

from cryptography.fernet import Fernet, InvalidToken
from sqlalchemy import or_, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.authorization.tokens import hash_token
from app.core.config import Settings
from app.core.errors import DependencyUnavailableError, NotFoundError
from app.core.time import utc_now
from app.db.rls import apply_tenant_context
from app.integrations.auth_mail import Mail, MailTransport
from app.models._enums import TenantStatus, UserStatus
from app.models.auth_mail import AuthMail
from app.models.identity import Tenant, User
from app.repositories.identity import AuditLogRepository


class AuthDelivery:
    def __init__(self, session: AsyncSession, settings: Settings) -> None:
        self.session = session
        self.settings = settings

    def cipher(self) -> Fernet:
        if not self.settings.auth_delivery_enabled:
            raise DependencyUnavailableError(
                "auth_delivery", message="Account recovery delivery is not configured."
            )
        try:
            return Fernet(self.settings.auth_mail_encryption_key.encode())
        except (ValueError, TypeError) as exc:
            raise DependencyUnavailableError(
                "auth_delivery", message="Account recovery delivery is not configured."
            ) from exc

    async def enqueue(
        self, user: User, tenant: Tenant, purpose: str, token: str, expires_at: datetime
    ) -> None:
        if user.tenant_id != tenant.id:
            raise NotFoundError(resource_type="user")
        cipher = self.cipher()
        # Caller holds the user row lock. Supersede undelivered messages of the
        # same purpose in the same transaction as replacing the credential hash.
        await self.session.execute(
            update(AuthMail)
            .where(
                AuthMail.tenant_id == tenant.id,
                AuthMail.user_id == user.id,
                AuthMail.purpose == purpose,
                AuthMail.status == "PENDING",
            )
            .values(status="CANCELLED", encrypted_payload=None, last_error="superseded")
        )
        payload = {"token": token, "recipient": user.email, "tenant_slug": tenant.slug}
        encrypted = cipher.encrypt(json.dumps(payload).encode()).decode()
        self.session.add(
            AuthMail(
                id=uuid4(),
                tenant_id=tenant.id,
                user_id=user.id,
                purpose=purpose,
                encrypted_payload=encrypted,
                expires_at=expires_at,
                next_attempt_at=utc_now(),
            )
        )
        await self.session.flush()

    async def deliver_batch(
        self, tenant_id: UUID, transport: MailTransport, *, limit: int = 25
    ) -> dict[str, int]:
        """Hold only outbox locks while sending; NEVER acquire a user lock here.

        Issuers lock user then update outbox. Locking in reverse order here would
        deadlock. A concurrent supersession may deliver an already-invalid code;
        confirmation always checks the current user hash, so it cannot revive it.
        The caller commits; a crash after SMTP acceptance can cause a duplicate
        with the same Message-ID (at-least-once, not exactly-once delivery).
        """
        if not 1 <= limit <= 100:
            raise ValueError("Batch limit must be between 1 and 100")
        cipher = self.cipher()
        await apply_tenant_context(self.session, tenant_id)
        now = utc_now()
        rows = (
            (
                await self.session.execute(
                    select(AuthMail)
                    .where(
                        AuthMail.tenant_id == tenant_id,
                        AuthMail.status == "PENDING",
                        or_(AuthMail.next_attempt_at <= now, AuthMail.expires_at <= now),
                    )
                    .order_by(AuthMail.created_at, AuthMail.id)
                    .limit(limit)
                    .with_for_update(skip_locked=True)
                )
            )
            .scalars()
            .all()
        )
        counts = {"sent": 0, "retry": 0, "failed": 0, "cancelled": 0}
        tenant = await self.session.get(Tenant, tenant_id)
        for row in rows:
            user = (
                await self.session.execute(
                    select(User).where(User.id == row.user_id, User.tenant_id == tenant_id)
                )
            ).scalar_one_or_none()
            payload: dict[str, str] | None = None
            if row.encrypted_payload is not None:
                try:
                    payload = json.loads(cipher.decrypt(row.encrypted_payload.encode()))
                except (InvalidToken, ValueError, TypeError):
                    row.status, row.last_error = "FAILED", "payload_unreadable"
            if row.status != "FAILED" and not self._eligible(row, user, tenant, payload, utc_now()):
                row.status, row.last_error = "CANCELLED", "expired_or_invalidated"
            if row.status == "PENDING" and payload is not None:
                token = payload["token"]
                purpose_label = (
                    "Password reset" if row.purpose == "PASSWORD_RESET" else "Email verification"
                )
                endpoint = (
                    "/password-reset/confirm"
                    if row.purpose == "PASSWORD_RESET"
                    else "/email/verify-confirm"
                )
                mail = Mail(
                    id=row.id,
                    tenant_id=tenant_id,
                    recipient=payload["recipient"],
                    subject=f"EcoMind: {purpose_label}",
                    body=(
                        f"{purpose_label} code: {token}\nTenant: {payload['tenant_slug']}\n"
                        f"Expires at: {row.expires_at.isoformat()}\n\n"
                        f"Submit tenant_slug and token to POST {self.settings.api_v1_prefix}/auth{endpoint}.\n"
                        + ("Also supply new_password.\n" if row.purpose == "PASSWORD_RESET" else "")
                        + "Only the most recently requested code works. Ignore this message if you did not request it.\n"
                    ),
                )
                row.attempts += 1
                try:
                    await transport.send(mail)
                except Exception:
                    # No exception string: SMTP errors may echo the body/address.
                    row.last_error = "transport_failure"
                    if row.attempts >= self.settings.auth_mail_max_attempts:
                        row.status = "FAILED"
                    else:
                        row.next_attempt_at = utc_now() + timedelta(
                            seconds=min(30 * 2 ** (row.attempts - 1), 1800)
                        )
                else:
                    row.status, row.sent_at, row.last_error = "SENT", utc_now(), None
            key = {
                "SENT": "sent",
                "FAILED": "failed",
                "CANCELLED": "cancelled",
                "PENDING": "retry",
            }[row.status]
            counts[key] += 1
            if row.status != "PENDING":
                row.encrypted_payload = None
            await AuditLogRepository(self.session, tenant_id).record(
                action="auth_mail." + key,
                actor=_DeliveryActor(),
                resource_type="auth_mail",
                resource_id=str(row.id),
                metadata={
                    "purpose": row.purpose,
                    "attempts": row.attempts,
                    "provider": "local_mailbox"
                    if self.settings.email_provider == "console"
                    else "smtp",
                },
            )
        await self.session.flush()
        return counts

    @staticmethod
    def _eligible(
        row: AuthMail,
        user: User | None,
        tenant: Tenant | None,
        payload: dict[str, str] | None,
        now: datetime,
    ) -> bool:
        if (
            row.expires_at <= now
            or user is None
            or user.deleted_at is not None
            or tenant is None
            or tenant.deleted_at is not None
            or tenant.status not in (TenantStatus.ACTIVE, TenantStatus.TRIAL)
            or not isinstance(payload, dict)
            or not all(
                isinstance(payload.get(k), str) for k in ("token", "recipient", "tenant_slug")
            )
        ):
            return False
        if payload["recipient"] != user.email or payload["tenant_slug"] != tenant.slug:
            return False
        if row.purpose == "PASSWORD_RESET":
            return (
                user.status == UserStatus.ACTIVE
                and user.password_reset_expires_at is not None
                and user.password_reset_expires_at > now
                and user.password_reset_token_hash == hash_token(payload["token"])
            )
        return (
            user.status in (UserStatus.ACTIVE, UserStatus.INVITED)
            and user.email_verified_at is None
            and user.email_verification_expires_at is not None
            and user.email_verification_expires_at > now
            and user.email_verification_token_hash == hash_token(payload["token"])
        )


class _DeliveryActor:
    user_id = None
    auth_type = "SYSTEM"
