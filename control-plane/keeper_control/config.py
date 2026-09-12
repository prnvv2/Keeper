"""Control-plane configuration.

Read from environment variables with a ``KEEPER_CP_`` prefix, or a ``.env``
file. Nothing here has a working default that would be unsafe in production:
``ingest_api_keys`` empty means ingest is open, and the service refuses to
start in that state unless ``allow_anonymous_ingest`` is set explicitly. A
telemetry endpoint that anyone can post to is a way to poison an audit trail.
"""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import (
    BaseSettings,
    DotEnvSettingsSource,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)

#: Fields that accept a comma-separated string as well as a JSON list.
#:
#: pydantic-settings parses any complex-typed field (``list[str]`` here) as
#: JSON *before* field validators run, so ``KEEPER_CP_INGEST_API_KEYS=a,b``
#: raises a SettingsError rather than reaching :meth:`Settings._split`. That is
#: exactly the spelling every compose file and deployment guide uses, so the
#: env source below hands these fields through as raw strings and lets the
#: validator do the splitting.
_LIST_FIELDS = frozenset(
    {"cors_origins", "ingest_api_keys", "admin_api_keys", "siem_targets"}
)


class _LenientMixin:
    """Hands the listed fields through as raw strings for the validator."""

    def prepare_field_value(self, field_name, field, value, value_is_complex):
        if field_name in _LIST_FIELDS and isinstance(value, str):
            return value
        return super().prepare_field_value(field_name, field, value, value_is_complex)


class _LenientEnvSource(_LenientMixin, EnvSettingsSource):
    pass


class _LenientDotEnvSource(_LenientMixin, DotEnvSettingsSource):
    pass


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="KEEPER_CP_", env_file=".env", env_file_encoding="utf-8", extra="ignore"
    )

    # --- service ---------------------------------------------------------
    environment: Literal["development", "staging", "production"] = "development"
    host: str = "0.0.0.0"
    port: int = 8080
    log_level: str = "info"
    cors_origins: list[str] = Field(default_factory=lambda: ["http://localhost:5173"])

    # --- storage ---------------------------------------------------------
    # SQLite by default so `docker compose up` and `pytest` both work with no
    # external service. Point this at Postgres for anything real: the audit
    # trail is append-heavy and SQLite's single-writer lock becomes the
    # bottleneck well before the ingest API does.
    database_url: str = "sqlite:///./keeper.db"
    pool_size: int = 10
    max_overflow: int = 20
    # Audit events older than this are deleted by the retention job. Zero
    # disables deletion — required by some regulatory regimes, and then the
    # operator owns the disk-space problem.
    retention_days: int = 90
    retention_interval_s: int = 3600

    # --- authentication ---------------------------------------------------
    #: Keys SDK instances present when shipping telemetry and pulling policy.
    ingest_api_keys: list[str] = Field(default_factory=list)
    allow_anonymous_ingest: bool = False
    #: Keys for dashboard/API users. Real deployments front this with OIDC;
    #: see docs/deployment.md.
    admin_api_keys: list[str] = Field(default_factory=list)
    session_secret: str = "change-me-in-production"
    dashboard_auth_required: bool = True

    # --- ingest -----------------------------------------------------------
    max_events_per_batch: int = 500
    max_body_bytes: int = 8 * 1024 * 1024
    ingest_rate_limit_per_minute: int = 6000

    # --- alerting ---------------------------------------------------------
    alerting_enabled: bool = True
    alert_webhook_url: str | None = None
    alert_slack_webhook_url: str | None = None
    alert_evaluation_interval_s: int = 30

    # --- SIEM export ------------------------------------------------------
    siem_enabled: bool = False
    siem_targets: list[str] = Field(default_factory=list)  # "webhook:URL", "syslog:host:port", "otlp:URL"
    siem_batch_size: int = 100
    siem_flush_interval_s: int = 5
    siem_min_severity: str = "low"

    # --- anomaly detection ------------------------------------------------
    anomaly_enabled: bool = True
    anomaly_window_minutes: int = 15
    anomaly_injection_threshold: int = 5     # blocked injections from one principal
    anomaly_cross_app_threshold: int = 2     # distinct apps the same probe hit
    anomaly_volume_sigma: float = 3.0        # z-score over the rolling baseline

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        return (
            init_settings,
            _LenientEnvSource(settings_cls),
            _LenientDotEnvSource(settings_cls),
            file_secret_settings,
        )

    @field_validator("cors_origins", "ingest_api_keys", "admin_api_keys", "siem_targets", mode="before")
    @classmethod
    def _split(cls, value: object) -> object:
        """Accept comma-separated strings as well as JSON lists.

        ``KEEPER_CP_INGEST_API_KEYS=a,b`` is what people actually type into a
        compose file; requiring JSON there is a support burden for no gain.
        Both spellings work, so a value copied from a Kubernetes manifest and a
        value typed into a shell behave the same way.
        """
        if isinstance(value, str):
            stripped = value.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                # The lenient env source deliberately skips JSON parsing for
                # these fields, so do it here rather than assuming it happened.
                try:
                    return json.loads(stripped)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"value looks like JSON but does not parse: {exc}") from exc
            return [part.strip() for part in stripped.split(",") if part.strip()]
        return value

    @property
    def is_production(self) -> bool:
        return self.environment == "production"

    def startup_warnings(self) -> list[str]:
        """Configuration that is legal but should be shouted about."""
        warnings: list[str] = []
        if not self.ingest_api_keys and not self.allow_anonymous_ingest:
            warnings.append(
                "no KEEPER_CP_INGEST_API_KEYS configured: telemetry ingest will reject every "
                "request. Set keys, or set KEEPER_CP_ALLOW_ANONYMOUS_INGEST=true for local dev."
            )
        if self.allow_anonymous_ingest and self.is_production:
            warnings.append(
                "ALLOW_ANONYMOUS_INGEST is on in production: anyone who can reach this service "
                "can forge audit events."
            )
        if self.session_secret == "change-me-in-production" and self.is_production:
            warnings.append("SESSION_SECRET is still the default value in production.")
        if self.database_url.startswith("sqlite") and self.is_production:
            warnings.append(
                "SQLite in production: telemetry ingest is write-heavy and will serialise on "
                "SQLite's single writer. Use Postgres."
            )
        if not self.dashboard_auth_required:
            warnings.append("dashboard authentication is disabled: the audit trail is world-readable.")
        return warnings


@lru_cache
def get_settings() -> Settings:
    return Settings()
