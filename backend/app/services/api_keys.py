"""Human-administered tenant integration credentials with one-time secret disclosure."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError

from app.authorization.api_keys import (
    API_KEY_SCOPES,
    DEFAULT_KEY_TTL,
    MAX_KEY_TTL,
    generate_api_key,
)
from app.authorization.tokens import hash_token
from app.core.errors import (
    ConflictError,
    InputValidationError,
    NotFoundError,
    PermissionDeniedError,
)
from app.core.time import utc_now
from app.models.identity import ApiKey
from app.repositories.base import PaginationResult
from app.services.identity import IdentityService


@dataclass(frozen=True, repr=False)
class IssuedApiKey:
    row: ApiKey
    plaintext: str


class ApiKeyService(IdentityService):
    def _require(self, permission: str) -> None:
        super()._require(permission)
        if self.actor.auth_type != "USER":
            raise PermissionDeniedError(message="Key administration requires a human account.")

    @staticmethod
    def _scopes(scopes: list[str]) -> list[str]:
        if (
            not scopes
            or len(scopes) > 32
            or len(scopes) != len(set(scopes))
            or not set(scopes).issubset(API_KEY_SCOPES)
        ):
            raise InputValidationError(
                message="Choose unique scopes from the API-key scope catalogue.", field="scopes"
            )
        return sorted(scopes)

    @staticmethod
    def _expiry(value: datetime | None) -> datetime:
        now = utc_now()
        if value is None:
            return now + DEFAULT_KEY_TTL
        if (
            value.tzinfo is None
            or value.utcoffset() is None
            or not now < value <= now + MAX_KEY_TTL
        ):
            raise InputValidationError(
                message="Key expiry must be timezone-aware, in the future and at most 365 days away.",
                field="expires_at",
            )
        return value

    async def _key(self, key_id: UUID, *, lock: bool = False) -> ApiKey:
        query = select(ApiKey).where(ApiKey.tenant_id == self.actor.tenant_id, ApiKey.id == key_id)
        if lock:
            query = query.with_for_update().execution_options(populate_existing=True)
        row = (await self.session.execute(query)).scalar_one_or_none()
        if row is None:
            raise NotFoundError(resource_type="API key", resource_id=str(key_id))
        return row

    async def scope_catalogue(self) -> list[str]:
        await self._write("apikeys.read")
        return sorted(API_KEY_SCOPES)

    async def list_keys(
        self, *, page: int = 1, page_size: int = 25, state: str = "active"
    ) -> PaginationResult:
        await self._write("apikeys.read")
        if (
            not 1 <= page <= 10000
            or not 1 <= page_size <= 100
            or state not in {"active", "expired", "revoked", "all"}
        ):
            raise InputValidationError(message="Invalid key query.")
        query = select(ApiKey).where(ApiKey.tenant_id == self.actor.tenant_id)
        if state == "active":
            query = query.where(ApiKey.revoked_at.is_(None), ApiKey.expires_at > utc_now())
        elif state == "expired":
            query = query.where(ApiKey.revoked_at.is_(None), ApiKey.expires_at <= utc_now())
        elif state == "revoked":
            query = query.where(ApiKey.revoked_at.is_not(None))
        total = int(
            (
                await self.session.execute(select(func.count()).select_from(query.subquery()))
            ).scalar_one()
        )
        rows = list(
            (
                await self.session.execute(
                    query.order_by(ApiKey.created_at.desc(), ApiKey.id.desc())
                    .limit(page_size)
                    .offset((page - 1) * page_size)
                )
            ).scalars()
        )
        await self.audit.record(
            action="api_key.list",
            actor=self.actor,
            resource_type="api_key",
            metadata={"state": state, "returned_ids": [str(row.id) for row in rows]},
        )
        return PaginationResult(rows, page=page, page_size=page_size, total=total)

    async def get_key(self, key_id: UUID) -> ApiKey:
        await self._write("apikeys.read")
        row = await self._key(key_id)
        await self.audit.record(
            action="api_key.read",
            actor=self.actor,
            resource_type="api_key",
            resource_id=str(row.id),
        )
        return row

    async def _issue(
        self,
        *,
        name: str,
        scopes: list[str],
        expires_at: datetime,
        rotation_of_id: UUID | None = None,
    ) -> IssuedApiKey:
        prefix, plaintext = generate_api_key()
        row = ApiKey(
            tenant_id=self.actor.tenant_id,
            name=name,
            key_prefix=prefix,
            key_hash=hash_token(plaintext),
            scopes=scopes,
            expires_at=expires_at,
            created_by=self.actor.user_id,
            rotation_of_id=rotation_of_id,
        )
        self.session.add(row)
        try:
            await self.session.flush()
        except IntegrityError as exc:
            # Caller rolls back the complete transaction, including rotation.
            # Never include SQL/parameters or credential material in the error.
            raise ConflictError(message="Key issuance conflicted; retry the request.") from exc
        return IssuedApiKey(row, plaintext)

    async def create_key(
        self, *, name: str, scopes: list[str], expires_at: datetime | None = None
    ) -> IssuedApiKey:
        await self._write("apikeys.write")
        if not name.strip() or len(name.strip()) > 200:
            raise InputValidationError(
                message="Key name must contain 1 to 200 characters.", field="name"
            )
        issued = await self._issue(
            name=name.strip(), scopes=self._scopes(scopes), expires_at=self._expiry(expires_at)
        )
        await self.audit.record(
            action="api_key.create",
            actor=self.actor,
            resource_type="api_key",
            resource_id=str(issued.row.id),
            metadata={
                "scopes": issued.row.scopes,
                "expires_at": issued.row.expires_at.isoformat() if issued.row.expires_at else None,
            },
        )
        return issued

    async def rotate_key(
        self, key_id: UUID, *, scopes: list[str] | None = None, expires_at: datetime | None = None
    ) -> IssuedApiKey:
        await self._write("apikeys.write")
        old = await self._key(key_id, lock=True)
        if old.revoked_at is not None or (
            old.expires_at is not None and old.expires_at <= utc_now()
        ):
            raise ConflictError(message="Revoked or expired keys cannot be rotated.")
        chosen = self._scopes(scopes if scopes is not None else old.scopes)
        if not set(chosen).issubset(old.scopes):
            raise PermissionDeniedError(
                message="Rotation cannot expand key scopes; create a separately authorized key."
            )
        issued = await self._issue(
            name=old.name,
            scopes=chosen,
            expires_at=self._expiry(expires_at if expires_at is not None else old.expires_at),
            rotation_of_id=old.id,
        )
        old.revoked_at = utc_now()
        await self.audit.record(
            action="api_key.rotate",
            actor=self.actor,
            resource_type="api_key",
            resource_id=str(old.id),
            metadata={"replacement_id": str(issued.row.id), "scopes": chosen},
        )
        return issued

    async def revoke_key(self, key_id: UUID) -> None:
        await self._write("apikeys.write")
        row = await self._key(key_id, lock=True)
        changed = row.revoked_at is None
        if changed:
            row.revoked_at = utc_now()
        await self.audit.record(
            action="api_key.revoke",
            actor=self.actor,
            resource_type="api_key",
            resource_id=str(row.id),
            metadata={"changed": changed},
        )
