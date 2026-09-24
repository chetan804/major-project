"""
Cross-cutting infrastructure: configuration, errors, logging, context, cache,
metrics, time and middleware.

Nothing in this package may import from ``app.api``, ``app.services`` or
``app.models`` — it is the bottom of the dependency graph, and a violation is
caught by ``tests/architecture/test_import_rules.py``.
"""
