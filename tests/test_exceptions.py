import pytest

from keeper.core.exceptions import (
    KeeperError,
    ConfigurationError,
    LayerNotRegisteredError,
    OllamaConnectionError,
    PipelineError,
    PluginLoadError,
    PolicyViolationError,
    RateLimitExceededError,
)


class TestExceptions:
    def test_keeper_error(self):
        with pytest.raises(KeeperError):
            raise KeeperError("base error")

    def test_pipeline_error(self):
        with pytest.raises(PipelineError):
            raise PipelineError("pipeline error")

    def test_configuration_error(self):
        with pytest.raises(ConfigurationError):
            raise ConfigurationError("bad config")

    def test_policy_violation_error(self):
        err = PolicyViolationError("blocked", risk_score=0.95, violations=["test"])
        assert err.risk_score == 0.95
        assert err.violations == ["test"]
        assert str(err) == "blocked"

    def test_ollama_connection_error(self):
        err = OllamaConnectionError()
        assert "ollama serve" in str(err).lower()

    def test_plugin_load_error(self):
        err = PluginLoadError("my_plugin", "import failed")
        assert err.plugin_name == "my_plugin"
        assert err.reason == "import failed"

    def test_rate_limit_exceeded_error(self):
        err = RateLimitExceededError("10.0.0.1", 100)
        assert err.ip == "10.0.0.1"
        assert err.limit == 100

    def test_layer_not_registered_error(self):
        err = LayerNotRegisteredError("custom_layer")
        assert err.layer_name == "custom_layer"
        assert "custom_layer" in str(err)

    def test_exception_hierarchy(self):
        assert issubclass(PipelineError, KeeperError)
        assert issubclass(ConfigurationError, KeeperError)
        assert issubclass(PolicyViolationError, KeeperError)
        assert issubclass(OllamaConnectionError, KeeperError)
        assert issubclass(PluginLoadError, KeeperError)
        assert issubclass(RateLimitExceededError, KeeperError)
        assert issubclass(LayerNotRegisteredError, PipelineError)

    def test_policy_violation_defaults(self):
        err = PolicyViolationError("test")
        assert err.risk_score == 0.0
        assert err.violations == []
