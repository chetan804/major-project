"""
ORM model package.

Every module in this package defines SQLAlchemy entities against
``app.db.base.Base``. Phase 1 establishes the package and its discovery helper;
tables arrive with the phase that owns them (Phase 2 onwards — see
``docs/database/erd.md`` Appendix A for the plan-versus-implemented table).

Discovery is automatic rather than a hand-maintained import list. A forgotten
entry in a manual list is not a cosmetic problem: Alembic autogenerate would
compare the database against incomplete metadata and could emit a migration that
**drops** a table the developer simply had not registered. Scanning the package
removes that failure mode entirely.
"""

from __future__ import annotations

from importlib import import_module
from pathlib import Path

__all__ = ["import_all_models", "model_module_names"]


def model_module_names() -> list[str]:
    """
    Names of the model modules in this package, in a deterministic order.

    Private modules (leading underscore) and ``__init__`` are excluded, so a
    helper file can live alongside the models without being imported as one.
    """
    package_dir = Path(__file__).resolve().parent
    return sorted(
        path.stem
        for path in package_dir.glob("*.py")
        if path.stem != "__init__" and not path.stem.startswith("_")
    )


def import_all_models() -> list[str]:
    """
    Import every model module so that ``Base.metadata`` is complete.

    Called by ``migrations/env.py`` before autogenerate and by the test suite
    before creating a schema. Returns the modules that were imported, which the
    migration environment logs so an operator can see what autogenerate actually
    considered.
    """
    names = model_module_names()
    for name in names:
        import_module(f"{__name__}.{name}")
    return names
