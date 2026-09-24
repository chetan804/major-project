"""
Database layer: declarative base, shared mixins, column types and the async
engine/session lifecycle.

``app/db`` must not import from ``app.api``, ``app.services`` or
``app.repositories``: models are the bottom of the persistence stack.
"""
