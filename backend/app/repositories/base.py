"""
The repository layer: the only place a query is written.

Every repository constrains by tenant. That is layer 2 of the three-layer tenant
isolation described in ``app/db/rls.py`` (schema, query, policy), and it exists
because layer 3 — PostgreSQL row-level security — is the safety net, not the
mechanism. A query that relies on the policy to filter would work in production
and leak in any connection that runs as a superuser or as the table owner, which
is exactly the situation a developer is in locally.

A repository is therefore never constructed without a tenant. ``PlatformRepository``
exists for the deliberately global reference tables (``app.db.rls.GLOBAL_TABLES``),
and it says so in its docstring rather than being a special case of the tenant
repository with the filter switched off.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any, Generic, TypeVar, cast
from uuid import UUID

from sqlalchemy import Select, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.errors import InputValidationError, NotFoundError
from app.db.base import Base

__all__ = ["BaseRepository", "PaginationResult", "PlatformRepository"]

#: The entity a repository is responsible for.
#:
#: Bounded to ``Base`` so a repository cannot be instantiated for something that
#: is not a mapped table. The bound deliberately stops there: the *columns* are
#: not part of it, because an ORM column is runtime metadata produced by the
#: mapper (``User.email`` is an ``InstrumentedAttribute``), not a class attribute
#: a type checker can see. Declaring ``model`` as ``Any`` below keeps that single
#: fact in one documented place instead of scattering ``# type: ignore`` across
#: every query in this module -- while ``ModelT`` still makes every *return* type
#: precise, which is what callers actually depend on.
ModelT = TypeVar("ModelT", bound=Base)


#: The columns every list endpoint may sort by, unless a repository narrows them.
#: Sorting is allow-listed rather than accepted from the client: an arbitrary
#: sort field is both an information-disclosure channel (a client can binary-search
#: a column that is not in the response) and a way to force a sequential scan.
DEFAULT_SORT_FIELDS: tuple[str, ...] = ("created_at", "updated_at", "id")


class PaginationResult(Sequence[Any]):
    """
    A page of rows plus the total, so a client can page without a second request.

    Subclasses ``Sequence`` rather than being a bare tuple so that a route can
    return it straight to the response model without unpacking it, and so
    ``len()`` means "rows on this page" rather than "total rows" — the two are
    different numbers and conflating them produces an off-by-one in the last page
    of every paginated view.
    """

    __slots__ = ("items", "page", "page_size", "total")

    def __init__(self, items: list[Any], *, page: int, page_size: int, total: int) -> None:
        self.items = items
        self.page = page
        self.page_size = page_size
        self.total = total

    def __getitem__(self, index: Any) -> Any:
        return self.items[index]

    def __len__(self) -> int:
        return len(self.items)

    @property
    def total_pages(self) -> int:
        if self.page_size <= 0:  # pragma: no cover - validated upstream
            return 0
        return (self.total + self.page_size - 1) // self.page_size


class BaseRepository(Generic[ModelT]):
    """
    Tenant-scoped data access for one entity.

    Subclasses declare ``model`` and, when they need it, ``selectin_loads`` — the
    relationships that must be eagerly loaded to avoid a query per row. Everything
    else is shared so that pagination, sorting, filtering and 404 behaviour are
    identical across every endpoint in the API.
    """

    model: Any

    #: Relationships loaded eagerly. Empty by default: loading a relationship the
    #: caller does not need is a query that runs on every request.
    selectin_loads: tuple[Any, ...] = ()

    #: Columns a list endpoint may sort by.
    sortable_fields: tuple[str, ...] = DEFAULT_SORT_FIELDS

    #: The name used in a 404 message. Defaults to the table name.
    resource_name: str = ""

    def __init__(self, session: AsyncSession, tenant_id: UUID) -> None:
        self.session = session
        self.tenant_id = tenant_id

    # -- query construction --------------------------------------------------
    def _base_query(self) -> Select:
        """A ``SELECT`` constrained to this repository's tenant."""
        query = select(self.model).where(self.model.tenant_id == self.tenant_id)
        for loader in self.selectin_loads:
            query = query.options(loader)
        return query

    def _resource_name(self) -> str:
        return self.resource_name or self.model.__tablename__

    # -- reads ---------------------------------------------------------------
    async def get(self, entity_id: UUID) -> ModelT | None:
        """One row, or ``None``. Never raises for "not visible to this tenant"."""
        result = await self.session.execute(self._base_query().where(self.model.id == entity_id))
        return result.scalar_one_or_none()

    async def get_or_404(self, entity_id: UUID) -> ModelT:
        """
        One row, or a 404.

        The 404 is shared with "does not exist": a caller may not distinguish
        another tenant's row from an absent one (ADR-0003), so this raises the
        same error in both cases rather than a 403 that would confirm the row's
        existence.
        """
        entity = await self.get(entity_id)
        if entity is None:
            raise NotFoundError(resource_type=self._resource_name(), resource_id=str(entity_id))
        return entity

    async def exists(self, entity_id: UUID) -> bool:
        return (await self.get(entity_id)) is not None

    async def count(self, filters: Mapping[str, Any] | None = None) -> int:
        query = (
            select(func.count())
            .select_from(self.model)
            .where(self.model.tenant_id == self.tenant_id)
        )
        query = self._apply_filters(query, filters)
        return int((await self.session.execute(query)).scalar_one())

    async def list(
        self,
        *,
        page: int = 1,
        page_size: int = 25,
        sort: Sequence[str] = (),
        filters: Mapping[str, Any] | None = None,
    ) -> PaginationResult:
        """
        One page of rows, with the total count.

        Sorting is applied from an allow-list, and a request for an unlisted field
        is a 400 rather than a silently ignored parameter: a client that asks to
        sort by a field and gets a different order has been misled about what it
        received.
        """
        if page < 1:
            raise InputValidationError(message="page must be 1 or greater.", field="page")
        if page_size < 1 or page_size > 100:
            raise InputValidationError(
                message="page_size must be between 1 and 100.", field="page_size"
            )

        query = self._base_query()
        query = self._apply_filters(query, filters)
        query = self._apply_sort(query, sort)

        total = await self.count(filters)
        result = await self.session.execute(query.limit(page_size).offset((page - 1) * page_size))
        return PaginationResult(
            list(result.scalars().unique().all()),
            page=page,
            page_size=page_size,
            total=total,
        )

    def _apply_sort(self, query: Select, sort: Sequence[str]) -> Select:
        """
        Apply ``sort`` (``-created_at`` for descending, ``created_at`` for ascending).

        The leading ``-`` is the API convention (``rest-api.md`` §1). An unknown
        field is rejected: see :meth:`list`.
        """
        for token in sort:
            descending = token.startswith("-")
            field = token[1:] if descending else token
            if field not in self.sortable_fields:
                raise InputValidationError(
                    message=(
                        f"Cannot sort by {field!r}. Sortable fields: "
                        f"{', '.join(self.sortable_fields)}."
                    ),
                    field="sort",
                )
            column = getattr(self.model, field)
            query = query.order_by(column.desc() if descending else column.asc())
        return query

    def _apply_filters(self, query: Select, filters: Mapping[str, Any] | None) -> Select:
        """
        Apply typed equality filters.

        Only exact matches on named columns are supported. A repository that needs
        a range or a substring match overrides this method and documents the extra
        filters, so the supported filter set is always discoverable from the
        repository rather than from whatever the query happens to accept.
        """
        if not filters:
            return query
        for field, value in filters.items():
            if value is None:
                continue
            if not hasattr(self.model, field):
                raise InputValidationError(message=f"Cannot filter by {field!r}.", field=field)
            query = query.where(getattr(self.model, field) == value)
        return query

    # -- writes --------------------------------------------------------------
    async def create(self, **values: Any) -> ModelT:
        """
        Insert a row owned by this repository's tenant.

        The tenant id is set here rather than accepted from the caller, so a
        service cannot create a row in another tenant by passing a tenant id — the
        repository simply ignores the value and uses its own.
        """
        values.pop("tenant_id", None)
        entity = cast(ModelT, self.model(tenant_id=self.tenant_id, **values))
        self.session.add(entity)
        await self.session.flush()
        return entity

    async def update(self, entity: ModelT, **values: Any) -> ModelT:
        """
        Apply ``values`` to ``entity``.

        The tenant id is refused, for the same reason ``create`` sets it: an update
        is the other half of the "move a row between tenants" attack, and a
        repository that silently accepted it would make the RLS ``WITH CHECK``
        clause the only thing standing in the way.
        """
        if "tenant_id" in values:
            raise InputValidationError(message="tenant_id cannot be changed.", field="tenant_id")
        if "id" in values:
            raise InputValidationError(message="id cannot be changed.", field="id")
        for field, value in values.items():
            if not hasattr(entity, field):
                raise InputValidationError(message=f"Unknown field {field!r}.", field=field)
            setattr(entity, field, value)
        await self.session.flush()
        return entity

    async def soft_delete(self, entity: ModelT) -> None:
        """
        Mark a row deleted without removing it.

        Operational records are evidence: a collection that happened, a load that
        was weighed, a chain-of-custody entry. Hard-deleting them would let an
        operator rewrite history, so deletion is a ``deleted_at`` stamp that the
        base query filters out.
        """
        if hasattr(entity, "deleted_at"):
            from app.core.time import utc_now

            entity.deleted_at = utc_now()
            await self.session.flush()
            return
        await self.session.delete(entity)
        await self.session.flush()


class PlatformRepository(Generic[ModelT]):
    """
    Data access for a deliberately global table.

    Used for the reference tables listed in ``app.db.rls.GLOBAL_TABLES`` — the
    permission catalogue, the waste taxonomy, the model registry. These are not
    tenant data, so filtering them by tenant would return nothing.

    This is a separate class rather than a flag on ``BaseRepository`` on purpose:
    "no tenant filter" is the single most dangerous setting in this codebase, and
    it should have to be chosen explicitly by naming this class.
    """

    model: Any
    selectin_loads: tuple[Any, ...] = ()
    sortable_fields: tuple[str, ...] = DEFAULT_SORT_FIELDS
    resource_name: str = ""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    def _base_query(self) -> Select:
        query = select(self.model)
        for loader in self.selectin_loads:
            query = query.options(loader)
        return query

    def _resource_name(self) -> str:
        return self.resource_name or self.model.__tablename__

    async def get(self, entity_id: UUID) -> ModelT | None:
        result = await self.session.execute(self._base_query().where(self.model.id == entity_id))
        return result.scalar_one_or_none()

    async def get_or_404(self, entity_id: UUID) -> ModelT:
        entity = await self.get(entity_id)
        if entity is None:
            raise NotFoundError(resource_type=self._resource_name(), resource_id=str(entity_id))
        return entity

    async def get_by_code(self, code: str) -> ModelT | None:
        result = await self.session.execute(self._base_query().where(self.model.code == code))
        return result.scalar_one_or_none()

    async def list(self, *, page: int = 1, page_size: int = 25) -> PaginationResult:
        total = int(
            (await self.session.execute(select(func.count()).select_from(self.model))).scalar_one()
        )
        result = await self.session.execute(
            self._base_query().limit(page_size).offset((page - 1) * page_size)
        )
        return PaginationResult(
            list(result.scalars().unique().all()),
            page=page,
            page_size=page_size,
            total=total,
        )
