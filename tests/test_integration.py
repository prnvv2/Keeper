import pytest


class TestFastAPIMiddleware:
    def test_middleware_init(self):
        from unittest.mock import MagicMock

        from keeper.core.engine import PolicyEngine
        from keeper.core.pipeline import Pipeline
        from keeper.integration.fastapi_middleware import KeeperMiddleware

        app = MagicMock()
        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        middleware = KeeperMiddleware(app, pipeline=pipeline)
        assert middleware.pipeline is not None


class TestLitellmProxy:
    def test_pre_call_hook_no_pipeline(self):
        from keeper.integration.litellm_proxy import keeper_pre_call_hook, pipeline

        original = pipeline
        import keeper.integration.litellm_proxy as proxy
        proxy.pipeline = None

        import inspect
        if inspect.iscoroutinefunction(keeper_pre_call_hook):
            import asyncio
            asyncio.run(keeper_pre_call_hook({"messages": [{"role": "user", "content": "hi"}]}))

        proxy.pipeline = original


class TestMCPTool:
    @pytest.mark.asyncio
    async def test_call_returns_schema(self):
        from keeper.core.engine import PolicyEngine
        from keeper.core.pipeline import Pipeline
        from keeper.integration.mcp_server import keeperMCPTool

        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        tool = keeperMCPTool(pipeline)
        result = await tool.call("test prompt")
        assert "action" in result
        assert "risk_score" in result
        assert "violations" in result
        assert "allowed" in result

    def test_schema_property(self):
        from keeper.core.engine import PolicyEngine
        from keeper.core.pipeline import Pipeline
        from keeper.integration.mcp_server import keeperMCPTool

        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        tool = keeperMCPTool(pipeline)
        schema = tool.schema
        assert schema["name"] == "keeper_guardrail"
        assert "inputSchema" in schema
        assert "prompt" in schema["inputSchema"]["properties"]
