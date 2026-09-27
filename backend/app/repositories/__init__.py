"""
Data access.

Repositories are the only modules that write SQL or ORM queries. Everything above
them — services, routers, jobs — works with entities and value objects, which is
what makes the tenant rule enforceable: there is exactly one kind of class that
can query, and every one of it takes a tenant id.
"""

from app.repositories.base import BaseRepository, PaginationResult, PlatformRepository

__all__ = ["BaseRepository", "PaginationResult", "PlatformRepository"]
