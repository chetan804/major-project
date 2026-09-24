"""
Test fixtures.

Design commitments (see ``docs/testing/testing-strategy.md``):

**Real PostgreSQL, always.** The suite runs against a genuine PostgreSQL 16
server provisioned with the bundled binaries. There is no SQLite fallback and no
mocked repository: constraints, ``NUMERIC`` precision, ``gen_random_uuid()`` and
row-level security must behave exactly as they do in production, or a passing
test proves nothing (ADR-0002).

**Isolated database per session.** Migrations run once into a dedicated
``ecomind_test`` database, which is dropped and recreated at the start of a run.
Tests therefore cannot see development data, and a test that corrupts state
cannot poison the next run.

**Loop-scoped lifetime handled explicitly.** ``pytest-asyncio`` gives each test
its own event loop. An asyncpg connection is bound to the loop that created it,
so a process-wide connection pool would raise "attached to a different loop" on
the second test. The database fixture therefore binds the application to a
``NullPool`` engine for the duration of a single test and disposes it afterwards,
so no connection is ever reused across loops.
"""

from __future__ import annotations

import os
import re
import secrets
import subprocess
import sys
from collections.abc import AsyncIterator, Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BACKEND_ROOT = Path(__file__).resolve().parents[1]
SCRIPTS_ROOT = REPO_ROOT / "scripts"

# The cluster manager is shared with `bootstrap.sh` rather than reimplemented
# here: one implementation of "start a real PostgreSQL" (master directive,
# rules 4 and 5).
sys.path.insert(0, str(SCRIPTS_ROOT))
import pg_server  # noqa: E402

# ---------------------------------------------------------------------------
# Test environment
# ---------------------------------------------------------------------------
TEST_DATABASE_NAME = "ecomind_test"

#: A signing key for tests that is generated per run.
#:
#: It satisfies ``Settings``' minimum-length rule and nothing else: no token in the
#: suite is ever signed with it, and no test depends on its value. Generating it
#: keeps a credential-shaped literal out of the repository, so a reader never has to
#: work out whether this one is safe and neither does a secret scanner.
TEST_JWT_SECRET = "test-" + secrets.token_urlsafe(48)

#: Guards the one place a database name is interpolated into SQL (below).
assert re.fullmatch(r"[a-z_][a-z0-9_]*", TEST_DATABASE_NAME), TEST_DATABASE_NAME
TEST_USER = "postgres"


def _async_url(sync_or_none: str | None = None) -> str:
    return f"postgresql+asyncpg://{TEST_USER}@/{TEST_DATABASE_NAME}?host={_socket_dir()}"


def _sync_url() -> str:
    return f"postgresql+psycopg2://{TEST_USER}@/{TEST_DATABASE_NAME}?host={_socket_dir()}"


def _socket_dir() -> str:
    return pg_server._socket_dir()


def _psql(sql: str) -> str:
    """Run SQL against the cluster's maintenance database."""
    return pg_server._server().psql(sql)


def _psql_test_db(sql: str) -> str:
    """
    Run SQL against the *test* database.

    Roles are cluster-wide but schema privileges are per-database, so a GRANT must
    reach ``ecomind_test`` rather than the maintenance database. ``psql`` is driven
    through stdin, so the ``\\connect`` metacommand reaches the right database
    without needing a second connection helper.
    """
    return pg_server._server().psql(f'\\connect "{TEST_DATABASE_NAME}"\n{sql}')


def _run_migrations(sync_url: str) -> None:
    """
    Apply migrations to the test database via the Alembic CLI.

    A subprocess is used rather than the in-process Alembic API because
    ``env.py`` is written for a synchronous engine and calling
    ``command.upgrade`` from inside an async test session nests event loops.
    """
    env = {
        **os.environ,
        "ALEMBIC_DATABASE_URL": sync_url,
        # A valid secret so settings validation cannot fail the fixture. Generated
        # rather than written out: the value is never used to sign anything, and
        # keeping it out of the source means it can never be mistaken for one that
        # is, nor copied out of the repository.
        "JWT_SECRET_KEY": TEST_JWT_SECRET,
        "ENVIRONMENT": "test",
    }
    result = subprocess.run(
        [sys.executable, "-m", "alembic", "upgrade", "head"],
        cwd=BACKEND_ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            "Applying migrations to the test database failed.\n"
            f"stdout:\n{result.stdout}\n\nstderr:\n{result.stderr}"
        )


# ---------------------------------------------------------------------------
# Session-scoped: PostgreSQL
# ---------------------------------------------------------------------------
@pytest.fixture(scope="session", autouse=True)
def postgres_cluster() -> Iterator[str]:
    """
    Ensure a real PostgreSQL cluster is running, and yield its socket directory.

    ``autouse`` so that a developer running a single test file still gets a
    working database without remembering to start one first.
    """
    socket_dir = pg_server._socket_dir()
    yield socket_dir


@pytest.fixture(scope="session")
def test_database_sync_url(test_database_url: str) -> str:
    """
    The synchronous URL for the test database.

    Exposed as a fixture so tests that must drive Alembic (which is synchronous)
    receive it through the normal dependency mechanism rather than importing
    ``conftest`` directly.
    """
    return _sync_url()


@pytest.fixture(scope="session")
def test_database_url(postgres_cluster: str) -> Iterator[str]:
    """
    Drop, recreate and migrate an isolated test database.

    Recreated rather than reused so a run always starts from a known schema, and
    migrated rather than built with ``metadata.create_all`` so the tests exercise
    the same DDL that production receives.
    """
    # Terminate any lingering connections so DROP DATABASE cannot fail.
    _psql(
        # The database name is a module-level constant, asserted to be a plain
        # identifier below, so it cannot carry SQL. psql offers no bind
        # parameters for -c, which is why the value is interpolated.
        "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "  # noqa: S608
        f"WHERE datname = '{TEST_DATABASE_NAME}' AND pid <> pg_backend_pid();"
    )
    _psql(f'DROP DATABASE IF EXISTS "{TEST_DATABASE_NAME}";')
    _psql(f'CREATE DATABASE "{TEST_DATABASE_NAME}";')

    sync_url = _sync_url()
    _run_migrations(sync_url)

    yield _async_url()


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@pytest.fixture
def test_settings(test_database_url: str) -> Iterator:
    """
    A :class:`Settings` instance bound to the test database.

    Constructed explicitly rather than read from the environment so that a
    developer's local ``.env`` can never redirect the suite at their development
    database.
    """
    from app.core.config import Settings

    settings = Settings(
        environment="test",
        debug=False,
        database_url=test_database_url,
        migration_database_url=_sync_url(),
        jwt_secret_key=TEST_JWT_SECRET,
        # fakeredis keeps the suite hermetic: no Redis server is required, and
        # the backend reports itself as simulated wherever it is surfaced.
        redis_adapter="fakeredis",
        job_runner="inline",
        log_level="WARNING",
        log_format="console",
        metrics_enabled=True,
        storage_provider="local",
        email_provider="console",
        routing_provider="local_haversine",
        weather_provider="local_synthetic",
        llm_provider="local",
    )
    # Reject a misconfigured test fixture loudly rather than letting the app
    # start in a state that a production deploy would refuse.
    problems = settings.validate_for_startup()
    assert not problems, f"test settings are invalid: {problems}"
    yield settings


# ---------------------------------------------------------------------------
# Database binding
# ---------------------------------------------------------------------------
@pytest.fixture
async def database(test_settings) -> AsyncIterator:
    """
    Bind the application to the test database on a NullPool engine.

    The application's lifespan calls ``init_database`` with ``force=False``, so
    binding the resource here *before* the app starts means the lifespan adopts
    this instance instead of creating a pooled one. That is what keeps
    connections from being reused across pytest's per-test event loops.

    If the lifespan is ever changed to ``force=True``, this ordering silently
    stops applying and tests will begin failing with cross-loop errors — which is
    why the behaviour is stated here rather than left implicit.
    """
    from app.db.session import init_database, reset_database

    instance = init_database(
        test_settings.database_url,
        pool_size=5,
        max_overflow=0,
        use_null_pool=True,
        force=True,
    )
    try:
        yield instance
    finally:
        await instance.dispose()
        reset_database()


@pytest.fixture
async def db_session(database) -> AsyncIterator:
    """A raw async session for tests that assert directly against the database."""
    session = database.session()
    try:
        yield session
    finally:
        await session.close()


# ---------------------------------------------------------------------------
# Row-level security
# ---------------------------------------------------------------------------
#: A non-superuser login role, used to make RLS observable in tests.
RLS_TEST_ROLE = "ecomind_rls_test"


@pytest.fixture(scope="session")
def rls_role(test_database_url: str) -> Iterator[str]:
    """
    A non-superuser login role that row-level security policies apply to.

    This fixture exists because of a measured property of PostgreSQL: **a
    superuser bypasses row-level security even with ``FORCE ROW LEVEL SECURITY``
    set.** Measured against this cluster, on a table with RLS enabled, forced, and
    carrying the generated policy:

        connected as ``postgres``   ->  SELECT returns rows for both tenants
        connected as a plain role   ->  SELECT returns rows for the bound tenant

    The suite connects as ``postgres`` to create and migrate the database, so a
    test that enabled RLS and queried the table would read every tenant's rows and
    could only pass if the policy were broken. It would be a test that fails when
    the security control works.

    The role is given ``LOGIN`` rather than being entered with ``SET ROLE``. A
    ``SET ROLE`` is session state, and SQLAlchemy returns the connection to the
    pool on ``rollback()`` — so the very first ``rollback()`` inside a test
    silently restores the superuser, and the policy stops applying part-way
    through. Binding the role into the connection URL makes every connection,
    including ones checked out later, the correct role.

    The same property is a production requirement, not a test artefact: the
    application must connect as an ordinary role. A deployment whose application
    user is a superuser, or holds ``BYPASSRLS``, silently disables the entire third
    layer of tenant isolation. That is recorded in
    ``docs/security/security-model.md`` and checked by
    ``app.db.rls.tables_without_rls`` at deploy time.

    Depends on ``test_database_url`` rather than on the cluster alone, and the
    dependency is load-bearing: that fixture drops and recreates ``ecomind_test``,
    so a GRANT issued before it would be discarded with the old database and every
    provisioning statement would then fail with "permission denied for schema
    public".
    """
    role = RLS_TEST_ROLE
    _drop_rls_role(role)
    _psql(f'CREATE ROLE "{role}" LOGIN;')
    # The role creates and owns the probe tables it is tested against. This GRANT
    # must be issued in the test database: roles are cluster-wide but schema
    # privileges are per-database.
    _psql_test_db(f'GRANT CREATE, USAGE ON SCHEMA public TO "{role}";')

    try:
        yield role
    finally:
        _drop_rls_role(role)


def _drop_rls_role(role: str) -> None:
    """
    Remove the role and everything it owns, tolerating any prior state.

    ``DROP OWNED BY`` must run in the database holding the objects, so it is issued
    against ``ecomind_test``. Each statement is attempted independently: the role
    may not exist, may own nothing, or may still own a probe table from a test that
    committed, and none of those is a reason to abort cleanup and leave a stale
    role behind for the next run.
    """
    for statement in (
        f'REASSIGN OWNED BY "{role}" TO postgres;',
        f'DROP OWNED BY "{role}";',
    ):
        try:
            _psql_test_db(statement)
        except subprocess.CalledProcessError:
            continue
    try:
        _psql(f'DROP ROLE IF EXISTS "{role}";')
    except subprocess.CalledProcessError:
        # Reporting this would obscure the actual test failure. The session-scoped
        # fixture re-creates the role at the start of the next run, and
        # _drop_rls_role is called before creation for exactly that reason.
        return


@pytest.fixture(scope="session")
def rls_engine(rls_role: str, test_database_url: str) -> Iterator:
    """
    An engine connected as the non-superuser role.

    ``NullPool`` for the same reason as the main test engine: pytest-asyncio gives
    each test its own event loop, and an asyncpg connection is bound to the loop
    that created it.
    """
    from sqlalchemy.ext.asyncio import create_async_engine
    from sqlalchemy.pool import NullPool

    socket_dir = _socket_dir()
    role_url = f"postgresql+asyncpg://{RLS_TEST_ROLE}@/{TEST_DATABASE_NAME}?host={socket_dir}"
    engine = create_async_engine(role_url, poolclass=NullPool)
    try:
        yield engine
    finally:
        # NullPool retains no connections, so the synchronous dispose is complete
        # and there is nothing left for an await to reach. Disposing the underlying
        # engine directly also keeps this fixture usable at session scope, where an
        # async finaliser would run in a different event loop than its setup.
        engine.sync_engine.dispose()


@pytest.fixture
async def rls_session(rls_engine) -> AsyncIterator:
    """
    A session whose every connection is the non-superuser role.

    Because the role is part of the connection URL rather than session state, a
    ``rollback()`` cannot restore superuser privileges part-way through a test.
    """
    from sqlalchemy.ext.asyncio import AsyncSession

    session = AsyncSession(bind=rls_engine, expire_on_commit=False)
    try:
        yield session
    finally:
        await session.rollback()
        await session.close()


# ---------------------------------------------------------------------------
# Application and HTTP client
# ---------------------------------------------------------------------------
@pytest.fixture
def app(test_settings, database):
    """
    The FastAPI application with its lifespan driven.

    The lifespan is entered manually (rather than relying on the HTTP transport
    to run it) because ``httpx.ASGITransport`` does not emit lifespan events.
    Running it is essential: startup is where logging, configuration validation
    and resource binding happen, so skipping it would test a different
    application than the one that deploys.
    """
    from app.main import create_app

    return create_app(test_settings)


@pytest.fixture
async def client(app) -> AsyncIterator:
    """An HTTP client bound to the application, with the lifespan running."""
    import httpx

    async with app.router.lifespan_context(app):
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://testserver",
            follow_redirects=False,
        ) as http_client:
            yield http_client
