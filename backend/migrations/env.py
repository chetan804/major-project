"""
Alembic migration environment.

Reads the migration URL from application settings (never from ``alembic.ini``)
and targets ``Base.metadata`` for autogenerate. Model modules are imported
automatically before autogenerate runs — see
:func:`app.models.import_all_models` for why that discovery is automatic rather
than a hand-maintained list.
"""

from __future__ import annotations

import os
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context
from sqlalchemy import engine_from_config, pool

# Make `app` importable when Alembic is invoked from the backend/ directory.
BACKEND_ROOT = Path(__file__).resolve().parent.parent
if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

from app.core.config import get_settings  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.db.session import safe_database_url  # noqa: E402
from app.models import import_all_models  # noqa: E402

config = context.config

if config.config_file_name is not None:
    fileConfig(config.config_file_name, disable_existing_loggers=False)

settings = get_settings()

#: The URL Alembic connects with. Synchronous by design (see alembic.ini).
#:
#: ``ALEMBIC_DATABASE_URL`` takes precedence over application settings so that
#: tooling can migrate a specific database without rewriting configuration — the
#: test suite uses this to migrate its own isolated database, and an operator can
#: target a recovery instance without touching `.env`.
migration_url = os.environ.get("ALEMBIC_DATABASE_URL") or settings.migration_database_url
config.set_main_option("sqlalchemy.url", migration_url)

# Import every model module so that `Base.metadata` is complete. Without this,
# autogenerate would compare the database against an empty metadata and produce a
# migration that drops every table.
imported = import_all_models()
print(
    f"[alembic] models loaded: {', '.join(imported) if imported else '(none yet)'}",
    file=sys.stderr,
)
print(
    f"[alembic] target: {safe_database_url(migration_url)}",
    file=sys.stderr,
)

target_metadata = Base.metadata


def _include_object(obj, name, type_, reflected, compare_to) -> bool:
    """
    Decide whether an object participates in autogenerate.

    Two exclusions:

    * tables owned by another Alembic revision graph (none today, but this keeps
      a future shared database from being clobbered);
    * foreign tables, which must never be dropped by a generated migration.
    """
    if type_ == "table" and getattr(obj, "info", {}).get("skip_autogenerate"):
        return False
    return not (type_ == "table" and name.startswith("pg_"))


def run_migrations_offline() -> None:
    """
    Emit SQL to stdout instead of executing it.

    Used to review the exact statements a migration will run — the practical way
    to satisfy "no destructive database migrations without explicit safeguards"
    (section 16) before touching a real environment.
    """
    context.configure(
        url=migration_url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
        include_object=_include_object,
        include_schemas=False,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Connect and apply migrations."""
    section = config.get_section(config.config_ini_section, {})
    connectable = engine_from_config(
        section,
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Report a changed column type or server default instead of ignoring
            # it; a silently ignored change is a schema drift nobody notices.
            compare_type=True,
            compare_server_default=True,
            include_object=_include_object,
            include_schemas=False,
            # Emit a value-free transaction per migration so a failure mid-way
            # leaves the database at the previous revision rather than partially
            # migrated where the engine supports it.
            transaction_per_migration=True,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
