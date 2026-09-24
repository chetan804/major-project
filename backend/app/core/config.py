"""
Application configuration.

Configuration is environment-driven (master directive, section 56): no secret is
ever committed, and every value has a typed, validated definition here so a
misconfiguration fails loudly at startup rather than at the first request.

Design notes
------------
* ``extra="ignore"`` because the same ``.env`` is shared with the frontend, which
  carries ``VITE_*`` keys this process has no use for.
* Fields whose environment representation is a delimited list (CORS origins,
  allowed MIME types) are declared as ``str`` with an accessor that splits them.
  Declaring them as ``list[str]`` would make pydantic-settings attempt JSON
  decoding of ``a,b,c`` and raise a confusing error.
* ``get_settings()`` is cached but clearable, so tests can point the application
  at an isolated database without re-importing modules.
"""

from __future__ import annotations

import functools
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["development", "test", "staging", "production"]
LogFormat = Literal["json", "console"]
CacheAdapter = Literal["redis", "fakeredis"]
JobRunner = Literal["inline", "celery"]
StorageProvider = Literal["local", "s3", "minio"]
LlmProvider = Literal["local", "openai_compatible"]
RoutingProvider = Literal["local_haversine", "osrm", "google", "mapbox"]
WeatherProvider = Literal["local_synthetic", "openweather"]
EmailProvider = Literal["console", "smtp"]
SmsProvider = Literal["noop", "twilio"]


class Settings(BaseSettings):
    """Validated application settings, loaded from the environment and `.env`."""

    model_config = SettingsConfigDict(
        # The repository root holds the canonical `.env`; when the process runs
        # from `backend/`, the first entry resolves it. A `.env` in the current
        # working directory takes precedence (later files win).
        env_file=("../.env", ".env"),
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # -- Application --------------------------------------------------------
    app_name: str = "EcoMind-AI"
    app_version: str = "0.1.0"
    environment: Environment = "development"
    debug: bool = False
    api_v1_prefix: str = "/api/v1"
    default_timezone: str = "Asia/Kolkata"
    default_locale: str = "en-IN"

    # -- Database -----------------------------------------------------------
    database_url: str = "postgresql+asyncpg://ecomind:ecomind@localhost:5432/ecomind"
    migration_database_url: str = "postgresql+psycopg2://ecomind:ecomind@localhost:5432/ecomind"
    db_pool_size: int = Field(default=10, ge=1, le=100)
    db_max_overflow: int = Field(default=20, ge=0, le=200)
    db_pool_recycle_seconds: int = Field(default=1800, ge=-1)
    db_echo: bool = False
    db_enable_rls: bool = True
    geo_enable_postgis: bool = False

    @field_validator("database_url", "migration_database_url")
    @classmethod
    def _require_postgres(cls, value: str) -> str:
        """
        Reject non-PostgreSQL backends outright.

        The schema depends on PostgreSQL semantics — ``NUMERIC`` exactness,
        ``CHECK`` constraints, row-level security, ``gen_random_uuid()`` — and
        ADR-0002 records why a substitute is not acceptable. Failing at startup
        is far better than passing tests on an engine that ignores constraints.
        """
        if not value.startswith("postgresql"):
            raise ValueError(
                "Only PostgreSQL URLs are supported (see ADR-0002). "
                f"Received a URL beginning with {value.split('://', 1)[0]!r}."
            )
        return value

    # -- Authentication -----------------------------------------------------
    jwt_secret_key: str = Field(default="", min_length=0)
    jwt_algorithm: Literal["HS256", "HS384", "HS512"] = "HS256"
    access_token_expire_minutes: int = Field(default=15, ge=1, le=1440)
    refresh_token_expire_days: int = Field(default=30, ge=1, le=365)
    refresh_token_rotation: bool = True
    password_min_length: int = Field(default=12, ge=8, le=128)
    argon2_time_cost: int = Field(default=3, ge=1, le=10)
    argon2_memory_cost_kib: int = Field(default=65536, ge=8192)
    argon2_parallelism: int = Field(default=2, ge=1, le=8)

    # -- Cache / queue ------------------------------------------------------
    redis_url: str = "redis://localhost:6379/0"
    redis_adapter: CacheAdapter = "redis"
    cache_ttl_seconds: int = Field(default=60, ge=1)
    rate_limit_enabled: bool = True
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"
    job_runner: JobRunner = "inline"

    # -- CORS / security headers -------------------------------------------
    cors_allowed_origins: str = "http://localhost:5173,http://localhost:3000"
    security_headers_enabled: bool = True
    hsts_enabled: bool = False

    # -- File storage -------------------------------------------------------
    storage_provider: StorageProvider = "local"
    storage_local_root: str = "./storage"
    storage_max_upload_mb: int = Field(default=10, ge=1, le=200)
    storage_allowed_mime_types: str = "image/jpeg,image/png,image/webp,text/csv,application/pdf"
    s3_endpoint_url: str = ""
    s3_bucket: str = ""
    s3_access_key_id: str = ""
    s3_secret_access_key: str = ""
    s3_region: str = ""

    # -- AI ----------------------------------------------------------------
    llm_provider: LlmProvider = "local"
    llm_base_url: str = ""
    llm_api_key: str = ""
    llm_model: str = ""
    llm_request_timeout_seconds: int = Field(default=30, ge=1, le=300)
    llm_max_output_tokens: int = Field(default=1024, ge=64, le=32768)
    classification_review_threshold: float = Field(default=0.70, ge=0.0, le=1.0)

    # -- Integration adapters ----------------------------------------------
    routing_provider: RoutingProvider = "local_haversine"
    routing_provider_base_url: str = ""
    routing_provider_api_key: str = ""
    weather_provider: WeatherProvider = "local_synthetic"
    weather_provider_api_key: str = ""
    email_provider: EmailProvider = "console"
    smtp_host: str = ""
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_from_address: str = "no-reply@ecomind.local"
    sms_provider: SmsProvider = "noop"

    # -- Optimization -------------------------------------------------------
    optimizer_max_solve_seconds: int = Field(default=10, ge=1, le=600)
    optimizer_default_avg_speed_kph: float = Field(default=24.0, gt=0, le=120)
    optimizer_enable_time_windows: bool = True
    optimizer_traffic_factor: float = Field(default=1.0, ge=1.0, le=5.0)

    # -- Telemetry ---------------------------------------------------------
    telemetry_ingest_api_key: str = ""
    telemetry_max_backfill_days: int = Field(default=7, ge=0, le=365)
    telemetry_offline_threshold_minutes: int = Field(default=180, ge=1)
    dedup_window_seconds: int = Field(default=60, ge=0)

    # -- Observability ------------------------------------------------------
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = "INFO"
    log_format: LogFormat = "json"
    request_id_header: str = "X-Request-ID"
    metrics_enabled: bool = True

    # -- Simulator ----------------------------------------------------------
    simulator_enabled: bool = False
    simulator_random_seed: int = 1337
    simulator_time_compression: float = Field(default=1.0, gt=0, le=1000)

    # ---------------------------------------------------------------------
    # Derived accessors
    # ---------------------------------------------------------------------
    @property
    def cors_origins(self) -> list[str]:
        """CORS allow-list parsed from the comma-separated setting."""
        return [origin.strip() for origin in self.cors_allowed_origins.split(",") if origin.strip()]

    @property
    def allowed_mime_types(self) -> set[str]:
        """Upload allow-list parsed from the comma-separated setting."""
        return {
            mime.strip().lower()
            for mime in self.storage_allowed_mime_types.split(",")
            if mime.strip()
        }

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    @property
    def is_test(self) -> bool:
        return self.environment == "test"

    # ---------------------------------------------------------------------
    # Startup validation
    # ---------------------------------------------------------------------
    def validate_for_startup(self) -> list[str]:
        """
        Return a list of fatal configuration problems, empty when healthy.

        Called once during application startup. Returning problems (rather than
        raising on the first one) lets an operator see every misconfiguration in
        a single pass instead of fixing them one deploy at a time.
        """
        problems: list[str] = []

        if not self.jwt_secret_key:
            problems.append(
                "JWT_SECRET_KEY is empty. Generate one with: "
                'python -c "import secrets; print(secrets.token_urlsafe(64))"'
            )
        elif self.is_production and len(self.jwt_secret_key) < 32:
            problems.append(
                "JWT_SECRET_KEY must be at least 32 characters in production "
                f"(currently {len(self.jwt_secret_key)})."
            )
        elif "CHANGE_ME" in self.jwt_secret_key:
            problems.append(
                "JWT_SECRET_KEY still contains the template placeholder. "
                "Run ./scripts/bootstrap.sh or set a real secret."
            )

        if self.is_production:
            if "*" in self.cors_origins:
                problems.append("CORS_ALLOWED_ORIGINS must not contain '*' in production.")
            if self.debug:
                problems.append("DEBUG must be false in production.")
            if not self.hsts_enabled:
                problems.append(
                    "HSTS_ENABLED should be true in production (TLS terminates "
                    "at the reverse proxy)."
                )
            if self.log_format != "json":
                problems.append("LOG_FORMAT should be 'json' in production.")
            if not self.security_headers_enabled:
                problems.append("SECURITY_HEADERS_ENABLED must be true in production.")

        if self.redis_adapter == "fakeredis" and self.is_production:
            problems.append(
                "REDIS_ADAPTER=fakeredis is a development-only adapter and must "
                "not be used in production."
            )
        if self.job_runner == "inline" and self.is_production:
            problems.append(
                "JOB_RUNNER=inline runs jobs in the request process and must not "
                "be used in production; configure Celery."
            )
        if self.storage_provider != "local" and not self.s3_bucket:
            problems.append(f"STORAGE_PROVIDER={self.storage_provider} requires S3_BUCKET.")
        if self.email_provider == "smtp" and not self.smtp_host:
            problems.append("EMAIL_PROVIDER=smtp requires SMTP_HOST.")
        if self.llm_provider == "openai_compatible" and (
            not self.llm_base_url or not self.llm_model
        ):
            problems.append("LLM_PROVIDER=openai_compatible requires LLM_BASE_URL and LLM_MODEL.")
        if self.simulator_enabled and self.is_production:
            problems.append(
                "SIMULATOR_ENABLED must be false in production; simulated "
                "telemetry must never be presented as live operational data."
            )
        if self.sms_provider == "twilio":
            problems.append(
                "SMS_PROVIDER=twilio is not implemented in this build. Use "
                "'noop' or add the adapter (see docs/architecture/decisions.md)."
            )

        return problems

    def adapter_summary(self) -> dict[str, object]:
        """
        Describe which implementation backs each pluggable component.

        Exposed by ``/health`` so that no reader can mistake a development
        adapter or simulator for real infrastructure (ADR-0013).
        """
        return {
            "cache": {
                "backend": self.redis_adapter,
                "is_simulated": self.redis_adapter == "fakeredis",
                "note": (
                    "In-process Redis-compatible adapter; not a real Redis server."
                    if self.redis_adapter == "fakeredis"
                    else "Real Redis server."
                ),
            },
            "jobs": {
                "backend": self.job_runner,
                "is_simulated": self.job_runner == "inline",
                "note": (
                    "Jobs execute synchronously inside the API process."
                    if self.job_runner == "inline"
                    else "Celery worker pool."
                ),
            },
            "storage": {"backend": self.storage_provider, "is_simulated": False},
            "routing": {
                "backend": self.routing_provider,
                "is_simulated": self.routing_provider == "local_haversine",
                "note": (
                    "Deterministic haversine distance/time. Travel times are "
                    "ESTIMATED, not measured, and are labelled as such in API "
                    "responses."
                    if self.routing_provider == "local_haversine"
                    else "External routing provider."
                ),
            },
            "weather": {
                "backend": self.weather_provider,
                "is_simulated": self.weather_provider == "local_synthetic",
            },
            "llm": {
                "backend": self.llm_provider,
                "is_simulated": self.llm_provider == "local",
                "note": (
                    "Deterministic rule-based planner over the same "
                    "permission-checked tool registry. It produces real answers "
                    "from real tool output; it is not a mock. It does not generate "
                    "free-form language."
                    if self.llm_provider == "local"
                    else "Hosted OpenAI-compatible endpoint."
                ),
            },
            "email": {"backend": self.email_provider, "is_simulated": False},
            "sms": {
                "backend": self.sms_provider,
                "is_simulated": True,
                "note": "No SMS gateway configured; messages are recorded only.",
            },
            "simulator_enabled": self.simulator_enabled,
            "geo": {
                "backend": "postgis" if self.geo_enable_postgis else "numeric_haversine",
                "note": (
                    "PostGIS geometry columns and ST_DWithin."
                    if self.geo_enable_postgis
                    else "Validated NUMERIC coordinates with bounding-box + "
                    "haversine queries (see ADR-0005)."
                ),
            },
        }


@functools.lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings()


def clear_settings_cache() -> None:
    """Drop the cached settings. Used by tests that rebind the environment."""
    get_settings.cache_clear()
