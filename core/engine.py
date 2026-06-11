import yaml
from pathlib import Path
from enum import Enum
from typing import Optional


class Action(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    REDACT = "redact"
    ALERT = "alert"


class PolicyEngine:
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self._default_config_path()
        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)
        self.actions = self.config.get("actions", {})

    @staticmethod
    def _default_config_path() -> str:
        pkg_dir = Path(__file__).resolve().parent.parent
        candidate = pkg_dir / "config" / "policies.yaml"
        if candidate.exists():
            return str(candidate)
        return "config/policies.yaml"

    def evaluate(self, risk_score: float) -> Action:
        if risk_score >= self.actions.get("block_threshold", 0.9):
            return Action.BLOCK
        if risk_score >= self.actions.get("redact_threshold", 0.7):
            return Action.REDACT
        if risk_score >= self.actions.get("alert_threshold", 0.5):
            return Action.ALERT
        return Action.ALLOW

    def get_layer_config(self, name: str) -> dict:
        return self.config.get("layers", {}).get(name, {})

    def get_guardrail_config(self, name: str) -> dict:
        return self.config.get("guardrails", {}).get(name, {})

    def reload(self) -> None:
        with open(self.config_path) as f:
            self.config = yaml.safe_load(f)
