import pytest

from keeper.core.engine import Action
from keeper.core.exceptions import LayerNotRegisteredError
from keeper.core.pipeline import RequestContext
from keeper.layers.base import BaseLayer


class TestRequestContext:
    def test_default_values(self):
        ctx = RequestContext(prompt="hello")
        assert ctx.prompt == "hello"
        assert ctx.user_id == ""
        assert ctx.session_id == ""
        assert ctx.ip == ""
        assert ctx.metadata == {}
        assert ctx.risk_score == 0.0
        assert ctx.action == Action.ALLOW
        assert ctx.latency_ms == 0.0
        assert ctx.violations == []

    def test_custom_values(self):
        ctx = RequestContext(
            prompt="test",
            user_id="user1",
            session_id="sess1",
            ip="10.0.0.1",
            metadata={"key": "value"},
            risk_score=0.5,
            action=Action.ALERT,
            violations=["warning"],
        )
        assert ctx.user_id == "user1"
        assert ctx.metadata["key"] == "value"
        assert ctx.risk_score == 0.5

    def test_risk_score_accumulation(self):
        ctx = RequestContext(prompt="test", risk_score=0.3)
        ctx.risk_score = max(ctx.risk_score, 0.7)
        assert ctx.risk_score == 0.7
        ctx.risk_score = max(ctx.risk_score, 0.5)
        assert ctx.risk_score == 0.7


class TestPipeline:
    @pytest.mark.asyncio
    async def test_run_empty_pipeline(self, pipeline, ctx):
        result = await pipeline.run(ctx)
        assert result.action == Action.ALLOW
        assert result.risk_score == 0.0
        assert result.latency_ms >= 0.0

    @pytest.mark.asyncio
    async def test_run_with_layer(self, pipeline, ctx):
        class PassLayer(BaseLayer):
            name = "pass"
            async def analyze(self, ctx, config):
                ctx.risk_score = max(ctx.risk_score, 0.1)
                return ctx

        pipeline.register(PassLayer())
        result = await pipeline.run(ctx)
        assert result.risk_score == 0.1

    @pytest.mark.asyncio
    async def test_short_circuit_on_block(self, pipeline, ctx):
        class BlockLayer(BaseLayer):
            name = "blocker"
            async def analyze(self, ctx, config):
                ctx.action = Action.BLOCK
                ctx.risk_score = 1.0
                return ctx

        class NeverReached(BaseLayer):
            name = "never"
            async def analyze(self, ctx, config):
                ctx.risk_score = 999
                return ctx

        pipeline.register(BlockLayer())
        pipeline.register(NeverReached())
        result = await pipeline.run(ctx)
        assert result.risk_score == 1.0

    @pytest.mark.asyncio
    async def test_disabled_layer_skipped(self, pipeline, ctx):
        class SkippedLayer(BaseLayer):
            name = "skipped"
            async def analyze(self, ctx, config):
                ctx.risk_score = 1.0
                return ctx

        pipeline.register(SkippedLayer(), config_override={"enabled": False})
        result = await pipeline.run(ctx)
        assert result.risk_score == 0.0

    def test_get_layer(self, pipeline):
        from keeper.layers.network import NetworkLayer
        pipeline.register(NetworkLayer())
        layer = pipeline.get_layer("network")
        assert layer.name == "network"

    def test_get_layer_not_found(self, pipeline):
        with pytest.raises(LayerNotRegisteredError):
            pipeline.get_layer("nonexistent")

    def test_unregister(self, pipeline):
        from keeper.layers.network import NetworkLayer
        pipeline.register(NetworkLayer())
        assert len(pipeline.layers) == 1
        pipeline.unregister("network")
        assert len(pipeline.layers) == 0

    def test_repr(self, pipeline):
        from keeper.layers.network import NetworkLayer
        pipeline.register(NetworkLayer())
        r = repr(pipeline)
        assert "network" in r

    def test_to_dict(self, pipeline):
        d = pipeline.to_dict()
        assert "layers" in d
        assert "config" in d
