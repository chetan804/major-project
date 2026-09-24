#!/usr/bin/env python
"""
EcoMind-AI — local PostgreSQL cluster manager.

Manages a real PostgreSQL server for development and testing using the bundled
binaries shipped by the ``pgserver`` package (see ADR-0002 in
``docs/architecture/decisions.md`` for why a real engine is required and why no
SQLite substitute is used).

The cluster listens on a **unix socket inside the data directory** rather than a
TCP port. Nothing is exposed to the network, and no port can collide with
another service in a sandbox.

Subcommands
-----------
``start``      Ensure the cluster exists and is running; print status.
``stop``       Stop the cluster (data is preserved).
``status``     Report whether the cluster is running, with pid and data dir.
``url``        Print the SQLAlchemy async URL (``postgresql+asyncpg://``).
``sync-url``   Print the SQLAlchemy sync URL (``postgresql+psycopg2://``) for
               Alembic, which runs synchronously.
``psql``       Run a SQL string or ``-f <file>``; ``-c`` is optional.
``ensure``     Start if needed, then print the async URL (used by CI scripts).

Environment
-----------
``PGDATA_DIR``   Data directory (default: ``<repo>/.runtime/pgdata``).
``PGDATABASE``   Database name (default: ``ecomind``).
``PGUSER``       Role name (default: ``postgres``; the superuser of the cluster).

Implementation note: ``pgserver.get_server()`` accepts a ``cleanup_mode``.
The default ``'stop'`` stops the server when the last handle in a process is
released, which would make the development database vanish between commands.
This script always requests ``cleanup_mode=None`` so the daemon outlives the
process that started it, and a later invocation re-attaches to the same
postmaster. Verified behaviour: a second process receives the same pid and can
read data written by the first.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PGDATA = REPO_ROOT / ".runtime" / "pgdata"

# Import failure is reported as a clear, actionable message rather than a
# traceback, because this script is the first thing a new contributor runs.
try:
    import pgserver
except ModuleNotFoundError:  # pragma: no cover - environment guard
    sys.stderr.write(
        "error: the 'pgserver' package is not installed in this interpreter.\n"
        "       Run ./scripts/bootstrap.sh, or:\n"
        "         .venv/bin/python -m pip install -r backend/requirements/dev.txt\n"
    )
    raise SystemExit(2) from None


def pgdata_dir() -> Path:
    """Resolve the cluster data directory, honouring ``PGDATA_DIR``."""
    return Path(os.environ.get("PGDATA_DIR") or DEFAULT_PGDATA).expanduser().resolve()


def database_name() -> str:
    return os.environ.get("PGDATABASE", "ecomind")


def role_name() -> str:
    return os.environ.get("PGUSER", "postgres")


def _server():
    """
    Return a handle to the cluster, starting it if necessary.

    ``cleanup_mode=None`` is deliberate: it prevents the daemon from being
    stopped when this process exits, which is what makes the database usable
    across separate command invocations.
    """
    data = pgdata_dir()
    if not data.parent.exists():
        data.parent.mkdir(parents=True, exist_ok=True)
    return pgserver.get_server(data, cleanup_mode=None)


def _socket_dir() -> str:
    """The directory holding the unix socket, parsed from the server URI."""
    uri = _server().get_uri()
    # Format: postgresql://<user>:@/<db>?host=<socket_dir>
    _, _, host_part = uri.partition("host=")
    return host_part.strip() or str(pgdata_dir())


def _ensure_database() -> None:
    """
    Create the application database if it does not exist.

    The cluster's default database is ``postgres``; the application uses its own
    database so that dropping/recreating it during tests cannot affect the
    cluster's maintenance database.
    """
    server = _server()
    db = database_name()
    if not db.isidentifier():
        raise ValueError(f"invalid database name: {db!r}")
    # `WHERE EXISTS` yields zero rows when the database is absent, and psql
    # prints "(0 rows)" — an unambiguous signal that avoids relying on the
    # side effect of a failed CREATE DATABASE (which prints to stderr).
    check = server.psql(
        "SELECT 'present' WHERE EXISTS "
        f"(SELECT 1 FROM pg_database WHERE datname = '{db}');"
    )
    if "0 rows" in check:
        # CREATE DATABASE cannot run inside a transaction block, but psql -c
        # executes statements outside one, so this is safe here.
        server.psql(f'CREATE DATABASE "{db}";')


def sqlalchemy_url(driver: str) -> str:
    """
    Build a SQLAlchemy URL using a unix socket.

    Both asyncpg and psycopg2 accept ``host=/path`` to mean "connect over the
    unix socket in this directory", which is how SQLAlchemy passes it through.
    """
    socket_dir = _socket_dir()
    return (
        f"postgresql+{driver}://{role_name()}@/{database_name()}"
        f"?host={socket_dir}"
    )


# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------
def cmd_start(_: argparse.Namespace) -> int:
    server = _server()
    _ensure_database()
    print(f"data directory : {pgdata_dir()}")
    print(f"postmaster pid : {server.get_pid()}")
    print(f"socket         : {_socket_dir()}")
    print(f"database       : {database_name()}")
    print(f"async url      : {sqlalchemy_url('asyncpg')}")
    print("status         : running")
    return 0


def cmd_stop(_: argparse.Namespace) -> int:
    data = pgdata_dir()
    if not data.exists():
        print(f"no cluster at {data}; nothing to stop")
        return 0
    # A fresh handle with cleanup_mode='stop' stops the running daemon.
    handle = pgserver.get_server(data, cleanup_mode="stop")
    handle.cleanup()
    print(f"stopped cluster at {data} (data preserved)")
    return 0


def _pid_alive(pid: int) -> bool:
    """
    Report whether ``pid`` is a live PostgreSQL postmaster.

    Checks the process name as well as existence, because PIDs are recycled and
    a stale ``postmaster.pid`` must not be reported as a running cluster.
    """
    try:
        import psutil  # shipped as a pgserver dependency
    except ModuleNotFoundError:  # pragma: no cover
        try:
            os.kill(pid, 0)
        except (ProcessLookupError, PermissionError):
            return False
        return True
    try:
        return psutil.Process(pid).name() in {"postgres", "postmaster"}
    except Exception:  # noqa: BLE001 - any psutil failure means "not our server"
        return False


def cmd_status(_: argparse.Namespace) -> int:
    """
    Report cluster state **without starting anything**.

    This deliberately does not call ``pgserver.get_server()``, which starts a
    server when one is not running; a status probe must never mutate state.
    """
    data = pgdata_dir()
    if not data.exists():
        print(f"status: not initialised ({data} does not exist)")
        return 1

    pid_file = data / "postmaster.pid"
    if not pid_file.exists():
        print(f"status: stopped\n data directory: {data}")
        return 1

    try:
        lines = pid_file.read_text(errors="replace").splitlines()
    except OSError as exc:
        print(f"status: unknown (cannot read postmaster.pid: {exc})")
        return 1

    if not lines or not lines[0].strip().isdigit():
        print(f"status: stopped\n detail: malformed postmaster.pid\n data directory: {data}")
        return 1

    pid = int(lines[0])
    if not _pid_alive(pid):
        print(
            f"status: stopped\n"
            f" detail: stale postmaster.pid (pid {pid} is not a running postmaster)\n"
            f" data directory: {data}"
        )
        return 1

    print("status: running")
    print(f" postmaster pid: {pid}")
    print(f" data directory: {data}")
    if len(lines) >= 5:
        print(f" socket: {lines[4]}")
    return 0


def cmd_url(_: argparse.Namespace) -> int:
    _ensure_database()
    print(sqlalchemy_url("asyncpg"))
    return 0


def cmd_sync_url(_: argparse.Namespace) -> int:
    _ensure_database()
    print(sqlalchemy_url("psycopg2"))
    return 0


def cmd_ensure(_: argparse.Namespace) -> int:
    _server()
    _ensure_database()
    print(sqlalchemy_url("asyncpg"))
    return 0


def cmd_psql(args: argparse.Namespace) -> int:
    server = _server()
    _ensure_database()
    if args.file:
        path = Path(args.file)
        if not path.exists():
            sys.stderr.write(f"error: no such file: {path}\n")
            return 2
        sql = path.read_text()
    elif args.sql:
        sql = args.sql
    else:
        # Interactive mode: hand over to the real psql binary.
        binary = Path(pgserver.__file__).parent / "pginstall" / "bin" / "psql"
        env = {**os.environ, "PGDATABASE": database_name(), "PGHOST": _socket_dir()}
        return subprocess.call([str(binary), "-d", database_name()], env=env)
    print(server.psql(sql))
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="pg_server.py",
        description="Manage the EcoMind-AI development PostgreSQL cluster.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("start", help="start the cluster (idempotent)").set_defaults(
        func=cmd_start
    )
    sub.add_parser("stop", help="stop the cluster, preserving data").set_defaults(
        func=cmd_stop
    )
    sub.add_parser("status", help="report cluster state").set_defaults(func=cmd_status)
    sub.add_parser("url", help="print the async SQLAlchemy URL").set_defaults(
        func=cmd_url
    )
    sub.add_parser("sync-url", help="print the sync SQLAlchemy URL (Alembic)").set_defaults(
        func=cmd_sync_url
    )
    sub.add_parser("ensure", help="start if needed and print the URL").set_defaults(
        func=cmd_ensure
    )

    psql = sub.add_parser("psql", help="run SQL against the cluster")
    psql.add_argument("sql", nargs="?", help="SQL string to execute")
    psql.add_argument("-f", "--file", help="execute SQL from a file")
    psql.set_defaults(func=cmd_psql)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
