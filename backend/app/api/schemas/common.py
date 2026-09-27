"""
Shared API schemas.

Two rules shape everything in this module:

* **An ORM entity is never returned from a router.** Routers return these schemas,
  which name exactly the fields the client may see. That is what stops a password
  hash, an internal flag or another tenant's identifier from reaching the wire by
  accident — a schema cannot accidentally serialise a column it does not declare.
* **``extra="forbid"`` on every request model.** A client that sends an unknown
  field has misunderstood the contract, and silently ignoring the field would let
  that misunderstanding persist in production. Rejecting it surfaces the mistake at
  the point it is made.
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "MAX_PAGE_SIZE",
    "ORMModel",
    "Page",
    "PageMeta",
    "RequestModel",
    "Timestamped",
    "UuidPath",
]

#: The largest page a client may request. ``page_size`` above this is a 400 rather
#: than a silently clamped value: a client that asks for 10000 rows has a bug, and
#: clamping it would hide the bug behind a response that looks correct.
MAX_PAGE_SIZE = 100

T = TypeVar("T")


class RequestModel(BaseModel):
    """Base for every request body: unknown fields are rejected."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ORMModel(BaseModel):
    """
    Base for every response schema built from an ORM entity.

    ``from_attributes=True`` is what lets a route do ``Schema.model_validate(row)``
    instead of hand-copying fields, and it is the reason a response schema is safe:
    only the declared fields are read, so adding a column to a table cannot leak it.
    """

    model_config = ConfigDict(from_attributes=True)


class Timestamped(ORMModel):
    """The creation and modification timestamps every auditable row carries."""

    created_at: datetime
    updated_at: datetime


class PageMeta(BaseModel):
    """
    Pagination metadata.

    ``total_items`` and ``total_pages`` are reported alongside the page so a client
    can render "page 3 of 12" without a second request. The count query is the
    reason ``page_size`` is capped: an uncapped count over a large table is a
    denial-of-service vector dressed up as a convenience.
    """

    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=MAX_PAGE_SIZE)
    total_items: int = Field(ge=0)
    total_pages: int = Field(ge=0)

    @classmethod
    def build(cls, *, page: int, page_size: int, total_items: int) -> PageMeta:
        total_pages = (total_items + page_size - 1) // page_size if page_size else 0
        return cls(page=page, page_size=page_size, total_items=total_items, total_pages=total_pages)


class Page(BaseModel, Generic[T]):
    """
    A page of results in the documented envelope.

    ``items`` rather than a bare list so the envelope can grow — ``meta`` already
    carries the pagination block, and a client written against the list alone would
    break the moment anything else was added.
    """

    items: list[T]
    meta: PageMeta


#: A path parameter that is a UUID. Annotated so every router validates it the
#: same way, and so a malformed id is a 422 from the framework rather than a 500
#: from a database cast deep inside a service.
UuidPath = Annotated[UUID, Field(description="Resource identifier.")]


def as_uuid(value: Any) -> UUID | None:
    """Coerce a value to a UUID, or ``None`` when it cannot be one."""
    if value is None:
        return None
    try:
        return UUID(str(value))
    except (ValueError, TypeError):
        return None
