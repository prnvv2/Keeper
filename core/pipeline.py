import time
import json
import logging
from dataclasses import dataclass, field
from typing import Optional

from keeper.core.engine import PolicyEngine, Action
from keeper.core.exceptions import LayerNotRegisteredError

logger = logging.getLogger("keeper.pipeline")


@dataclass
class RequestContext:
    prompt: str
    user_id: str = ""
    session_id: str = ""
    ip: str = ""
    metadata: dict = field(default_factory=dict)
    risk_score: float = 0.0
    action: Action = Action.ALLOW
    latency_ms: float = 0.0
    violations: list = field(default_factory=list)


class Pipeline:
    def __init__(self, policy_engine: PolicyEngine):
        self.engine = policy_engine
        self.layers = []

    def register(self, layer, config_override: Optional[dict] = None):
        self.layers.append((layer, config_override))

    def unregister(self, name: str) -> None:
        self.layers = [(l, c) for l, c in self.layers if l.name != name]
        if not any(l.name == name for l, _ in self.layers):
            pass

    def get_layer(self, name: str):
        for layer, _ in self.layers:
            if layer.name == name:
                return layer
        raise LayerNotRegisteredError(name)

    async def run(self, ctx: RequestContext) -> RequestContext:
        start = time.perf_counter()
        for layer, config_override in self.layers:
            config = self.engine.get_layer_config(layer.name)
            if config_override:
                config = {**config, **config_override}
            if not config.get("enabled", True):
                continue
            ctx = await layer.analyze(ctx, config)
            if ctx.action == Action.BLOCK:
                break
        ctx.latency_ms = (time.perf_counter() - start) * 1000
        self._log(ctx)
        return ctx

    def _log(self, ctx: RequestContext):
        logger.info(json.dumps({
            "action": ctx.action.value,
            "risk_score": round(ctx.risk_score, 3),
            "latency_ms": round(ctx.latency_ms, 2),
            "violations": ctx.violations,
            "session": ctx.session_id,
            "user": ctx.user_id,
        }))

    def __repr__(self) -> str:
        registered = [l.name for l, _ in self.layers]
        return f"Pipeline(layers={registered})"

    def to_dict(self) -> dict:
        return {
            "layers": [l.name for l, _ in self.layers],
            "config": self.engine.config,
        }
