"""
Business logic.

A service owns a use case and its transaction boundary. It is the only layer that
decides *whether* an operation is allowed beyond the caller's permissions — the
business rules live here rather than in a router, so they hold whichever way in the
operation was reached. Services never import from the API layer.
"""

__all__: list[str] = []
