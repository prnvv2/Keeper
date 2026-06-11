from aanf.core.engine import Action


class TestAction:
    def test_action_values(self):
        assert Action.ALLOW.value == "allow"
        assert Action.BLOCK.value == "block"
        assert Action.REDACT.value == "redact"
        assert Action.ALERT.value == "alert"

    def test_action_enum_membership(self):
        assert Action("allow") == Action.ALLOW
        assert Action("block") == Action.BLOCK
        assert Action("redact") == Action.REDACT
        assert Action("alert") == Action.ALERT


class TestPolicyEngine:
    def test_init_default_config(self, policy_engine):
        assert policy_engine.config is not None
        assert "layers" in policy_engine.config
        assert "actions" in policy_engine.config

    def test_evaluate_allow(self, policy_engine):
        assert policy_engine.evaluate(0.0) == Action.ALLOW
        assert policy_engine.evaluate(0.3) == Action.ALLOW

    def test_evaluate_alert(self, policy_engine):
        assert policy_engine.evaluate(0.5) == Action.ALERT

    def test_evaluate_redact(self, policy_engine):
        assert policy_engine.evaluate(0.7) == Action.REDACT

    def test_evaluate_block(self, policy_engine):
        assert policy_engine.evaluate(0.9) == Action.BLOCK
        assert policy_engine.evaluate(1.0) == Action.BLOCK

    def test_get_layer_config(self, policy_engine):
        config = policy_engine.get_layer_config("network")
        assert "rate_limit" in config
        assert config.get("enabled", True) is True

    def test_get_layer_config_missing(self, policy_engine):
        config = policy_engine.get_layer_config("nonexistent")
        assert config == {}

    def test_get_guardrail_config(self, policy_engine):
        config = policy_engine.get_guardrail_config("prompt_guard")
        assert "threshold" in config

    def test_get_guardrail_config_missing(self, policy_engine):
        config = policy_engine.get_guardrail_config("nonexistent")
        assert config == {}

    def test_reload(self, policy_engine):
        before = policy_engine.config["actions"]["block_threshold"]
        policy_engine.reload()
        after = policy_engine.config["actions"]["block_threshold"]
        assert before == after
