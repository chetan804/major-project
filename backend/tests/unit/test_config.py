"""
Configuration validation.

Startup validation exists so that a misconfiguration fails a deploy rather than
producing a security hole at runtime. Testing the *rejection* paths matters more
than testing the happy path: a rule that never fires is indistinguishable from a
rule that was never written.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.core.config import Settings

pytestmark = pytest.mark.unit

VALID_SECRET = "a" * 48


def make_settings(**overrides: object) -> Settings:
    """Build settings with a valid baseline so each test varies one thing."""
    base: dict[str, object] = {
        "environment": "development",
        "jwt_secret_key": VALID_SECRET,
        "redis_adapter": "redis",
        "job_runner": "celery",
        "database_url": "postgresql+asyncpg://u:p@localhost:5432/db",
        "migration_database_url": "postgresql+psycopg2://u:p@localhost:5432/db",
    }
    base.update(overrides)
    return Settings(**base)


# ---------------------------------------------------------------------------
# Backend restriction
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "url",
    [
        "sqlite:///./test.db",
        "mysql+pymysql://u:p@localhost/db",
        "mongodb://localhost:27017/db",
    ],
)
def test_non_postgresql_backends_are_rejected(url: str) -> None:
    """
    Only PostgreSQL is accepted.

    ADR-0002 records why: a substitute engine does not enforce the constraints,
    ``NUMERIC`` precision or row-level security this schema depends on, so tests
    against it would pass while proving nothing. This must fail at construction
    time, not at the first query.
    """
    with pytest.raises(ValidationError, match="Only PostgreSQL URLs are supported"):
        make_settings(database_url=url)


def test_postgresql_urls_are_accepted() -> None:
    assert make_settings().database_url.startswith("postgresql+asyncpg://")


# ---------------------------------------------------------------------------
# Startup validation
# ---------------------------------------------------------------------------
def test_valid_development_configuration_reports_no_problems() -> None:
    assert make_settings().validate_for_startup() == []


def test_empty_jwt_secret_is_fatal() -> None:
    """A missing signing key must stop startup, never fall back to a default."""
    problems = make_settings(jwt_secret_key="").validate_for_startup()

    assert any("JWT_SECRET_KEY is empty" in problem for problem in problems)


def test_placeholder_jwt_secret_is_fatal() -> None:
    """
    The template placeholder must be rejected even though it is non-empty.

    A copied ``.env`` with the example value would otherwise look configured
    while every token was signed with a publicly known key.
    """
    problems = make_settings(
        jwt_secret_key="CHANGE_ME_generate_a_64_byte_random_secret"
    ).validate_for_startup()

    assert any("template placeholder" in problem for problem in problems)


def test_short_jwt_secret_is_rejected_only_in_production() -> None:
    """Length is enforced where it matters; development is not obstructed."""
    short = "abc123"
    assert make_settings(jwt_secret_key=short).validate_for_startup() == []

    problems = make_settings(environment="production", jwt_secret_key=short).validate_for_startup()
    assert any("at least 32 characters" in problem for problem in problems)


def test_production_rejects_wildcard_cors() -> None:
    problems = make_settings(
        environment="production", cors_allowed_origins="*"
    ).validate_for_startup()

    assert any("must not contain '*'" in problem for problem in problems)


def test_production_rejects_debug_mode() -> None:
    """
    Debug mode must be off in production.

    With ``debug=True`` the error middleware echoes the exception type and
    message to the client, which is exactly the internal disclosure section 34
    forbids.
    """
    problems = make_settings(environment="production", debug=True).validate_for_startup()

    assert any("DEBUG must be false" in problem for problem in problems)


def test_production_rejects_development_adapters() -> None:
    """
    Development adapters must never run in production.

    Both of these are functional, which is precisely why they are dangerous: the
    system would behave plausibly while using an in-process cache and executing
    every background job inside the request process.
    """
    problems = make_settings(
        environment="production", redis_adapter="fakeredis"
    ).validate_for_startup()
    assert any("fakeredis is a development-only adapter" in problem for problem in problems)

    problems = make_settings(environment="production", job_runner="inline").validate_for_startup()
    assert any("JOB_RUNNER=inline" in problem for problem in problems)


def test_production_rejects_enabled_simulator() -> None:
    """Simulated telemetry must never be presented as live operational data."""
    problems = make_settings(
        environment="production", simulator_enabled=True
    ).validate_for_startup()

    assert any("SIMULATOR_ENABLED must be false" in problem for problem in problems)


def test_object_storage_requires_a_bucket() -> None:
    problems = make_settings(storage_provider="s3").validate_for_startup()
    assert any("requires S3_BUCKET" in problem for problem in problems)

    assert (
        make_settings(storage_provider="s3", s3_bucket="ecomind-files").validate_for_startup() == []
    )


def test_smtp_requires_a_host() -> None:
    problems = make_settings(email_provider="smtp").validate_for_startup()
    assert any("requires SMTP_HOST" in problem for problem in problems)


def test_hosted_llm_requires_endpoint_and_model() -> None:
    problems = make_settings(llm_provider="openai_compatible").validate_for_startup()
    assert any("requires LLM_BASE_URL and LLM_MODEL" in problem for problem in problems)


def test_unimplemented_sms_provider_is_refused() -> None:
    """
    An unimplemented integration must fail loudly rather than silently no-op.

    Accepting ``twilio`` and dropping messages would be a fake integration.
    """
    problems = make_settings(sms_provider="twilio").validate_for_startup()
    assert any("not implemented in this build" in problem for problem in problems)


def test_all_problems_are_reported_together() -> None:
    """
    Every problem is returned in one pass.

    Reporting only the first would make an operator fix them one restart at a
    time, which is how a security setting ends up never being set.
    """
    problems = make_settings(
        environment="production",
        jwt_secret_key="",
        debug=True,
        cors_allowed_origins="*",
        redis_adapter="fakeredis",
        job_runner="inline",
        simulator_enabled=True,
    ).validate_for_startup()

    assert len(problems) >= 6


# ---------------------------------------------------------------------------
# Derived accessors
# ---------------------------------------------------------------------------
def test_cors_origins_are_parsed_and_trimmed() -> None:
    """
    A comma-separated list is split and whitespace removed.

    Declaring the field as a list would make pydantic-settings attempt JSON
    decoding of ``a,b,c`` and fail with a confusing error, which is why the
    accessor exists.
    """
    settings = make_settings(cors_allowed_origins="http://localhost:5173, http://localhost:3000 ,")

    assert settings.cors_origins == ["http://localhost:5173", "http://localhost:3000"]


def test_allowed_mime_types_are_lowercased() -> None:
    settings = make_settings(storage_allowed_mime_types="image/JPEG, image/PNG")

    assert settings.allowed_mime_types == {"image/jpeg", "image/png"}


@pytest.mark.parametrize(
    ("environment", "expected"),
    [("production", True), ("development", False), ("test", False)],
)
def test_is_production_flag(environment: str, expected: bool) -> None:
    assert make_settings(environment=environment).is_production is expected


def test_adapter_summary_labels_every_simulated_component() -> None:
    """
    The adapter inventory must be accurate for every component.

    ``/health`` publishes this, and ADR-0013 requires that a reader cannot
    mistake a development adapter or simulator for real infrastructure.
    """
    summary = make_settings(
        redis_adapter="fakeredis",
        job_runner="inline",
        routing_provider="local_haversine",
        weather_provider="local_synthetic",
        llm_provider="local",
        sms_provider="noop",
    ).adapter_summary()

    assert summary["cache"]["is_simulated"] is True
    assert summary["jobs"]["is_simulated"] is True
    assert summary["routing"]["is_simulated"] is True
    assert summary["weather"]["is_simulated"] is True
    assert summary["llm"]["is_simulated"] is True

    # Real infrastructure and genuinely implemented adapters are not flagged.
    assert summary["email"]["is_simulated"] is False
    assert summary["storage"]["is_simulated"] is False


def test_geo_summary_describes_the_active_strategy() -> None:
    """The geo layer must state which SQL strategy is in force (ADR-0005)."""
    assert make_settings(geo_enable_postgis=False).adapter_summary()["geo"]["backend"] == (
        "numeric_haversine"
    )
    assert make_settings(geo_enable_postgis=True).adapter_summary()["geo"]["backend"] == "postgis"
