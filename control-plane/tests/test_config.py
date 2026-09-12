"""Configuration tests.

These exist because of a real bug: every other test constructs ``Settings()``
directly with Python lists, so nothing exercised the path that Docker, the
Kubernetes manifests and every line of the deployment guide actually use —
environment variables. pydantic-settings JSON-parses complex fields before
field validators run, so ``KEEPER_CP_INGEST_API_KEYS=a,b`` raised a
``SettingsError`` at startup while the whole test suite stayed green.

The lesson generalises: test the configuration path the documentation tells
people to use, not the one the tests find convenient.
"""

from __future__ import annotations

import pytest

from keeper_control.config import Settings


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    """Isolate from the developer's real environment and any local .env."""
    import os

    for key in list(os.environ):
        if key.startswith("KEEPER_CP_"):
            monkeypatch.delenv(key, raising=False)
    yield


def settings(monkeypatch, **env: str) -> Settings:
    for key, value in env.items():
        monkeypatch.setenv(f"KEEPER_CP_{key.upper()}", value)
    # _env_file=None keeps a developer's local .env out of the assertion.
    return Settings(_env_file=None)


# --- list fields from the environment --------------------------------------


def test_comma_separated_keys_from_env(monkeypatch):
    """The spelling every compose file and deployment guide uses."""
    config = settings(monkeypatch, ingest_api_keys="key-a,key-b")
    assert config.ingest_api_keys == ["key-a", "key-b"]


def test_json_list_keys_from_env(monkeypatch):
    """The spelling a Kubernetes manifest or Terraform output tends to produce."""
    config = settings(monkeypatch, admin_api_keys='["key-c", "key-d"]')
    assert config.admin_api_keys == ["key-c", "key-d"]


def test_single_value_from_env(monkeypatch):
    config = settings(monkeypatch, ingest_api_keys="only-one")
    assert config.ingest_api_keys == ["only-one"]


def test_empty_value_is_an_empty_list(monkeypatch):
    """An unset-but-present variable is common in compose files."""
    config = settings(monkeypatch, siem_targets="")
    assert config.siem_targets == []


def test_whitespace_is_trimmed(monkeypatch):
    config = settings(monkeypatch, cors_origins=" http://a , http://b ")
    assert config.cors_origins == ["http://a", "http://b"]


def test_malformed_json_is_rejected_clearly(monkeypatch):
    with pytest.raises(Exception, match="does not parse"):
        settings(monkeypatch, ingest_api_keys='["unterminated')


def test_siem_targets_survive_their_colons(monkeypatch):
    """SIEM targets contain colons and slashes; splitting is on commas only."""
    config = settings(
        monkeypatch,
        siem_targets="webhook:https://splunk.example.com/services/collector,syslog:siem.internal:514",
    )
    assert config.siem_targets == [
        "webhook:https://splunk.example.com/services/collector",
        "syslog:siem.internal:514",
    ]


# --- other env coercion ----------------------------------------------------


def test_booleans_and_numbers_from_env(monkeypatch):
    config = settings(monkeypatch, allow_anonymous_ingest="true", retention_days="30",
                      anomaly_volume_sigma="2.5")
    assert config.allow_anonymous_ingest is True
    assert config.retention_days == 30
    assert config.anomaly_volume_sigma == 2.5


def test_defaults_are_usable_with_no_environment(monkeypatch):
    config = settings(monkeypatch)
    assert config.database_url.startswith("sqlite")
    assert config.environment == "development"
    assert config.ingest_api_keys == []


# --- startup warnings ------------------------------------------------------


def test_warns_when_ingest_would_reject_everything(monkeypatch):
    config = settings(monkeypatch)
    assert any("will reject every" in w for w in config.startup_warnings())


def test_no_warning_once_keys_are_configured(monkeypatch):
    config = settings(monkeypatch, ingest_api_keys="k", admin_api_keys="a")
    assert config.startup_warnings() == []


def test_warns_about_anonymous_ingest_in_production(monkeypatch):
    config = settings(monkeypatch, environment="production", allow_anonymous_ingest="true",
                      ingest_api_keys="k", session_secret="s",
                      database_url="postgresql+psycopg://x/y")
    assert any("forge audit events" in w for w in config.startup_warnings())


def test_warns_about_sqlite_and_default_secret_in_production(monkeypatch):
    config = settings(monkeypatch, environment="production", ingest_api_keys="k")
    warnings = " ".join(config.startup_warnings())
    assert "SQLite in production" in warnings
    assert "SESSION_SECRET" in warnings


def test_warns_when_dashboard_auth_is_disabled(monkeypatch):
    config = settings(monkeypatch, ingest_api_keys="k", dashboard_auth_required="false")
    assert any("world-readable" in w for w in config.startup_warnings())


# --- the app actually starts from environment configuration ----------------


def test_app_builds_from_environment_alone(monkeypatch, tmp_path):
    """The regression this file exists for: startup, configured the documented way."""
    from fastapi.testclient import TestClient

    from keeper_control.app import create_app

    config = settings(
        monkeypatch,
        ingest_api_keys="ingest-1,ingest-2",
        admin_api_keys="admin-1",
        database_url=f"sqlite:///{tmp_path / 'env.db'}",
        anomaly_enabled="false",
    )
    with TestClient(create_app(config)) as client:
        assert client.get("/healthz").json()["status"] == "ok"
        # Both keys from the comma-separated list must work.
        for key in ("ingest-1", "ingest-2"):
            response = client.get("/v1/policies/default", headers={"Authorization": f"Bearer {key}"})
            assert response.status_code == 200
        assert client.get("/v1/policies/default", headers={"Authorization": "Bearer admin-1"}).status_code == 401
