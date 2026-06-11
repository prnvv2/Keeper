import pytest


class TestFastAPIMiddleware:
    def test_middleware_init(self):
        from unittest.mock import MagicMock

        from aanf.core.engine import PolicyEngine
        from aanf.core.pipeline import Pipeline
        from aanf.integration.fastapi_middleware import AANFMiddleware

        app = MagicMock()
        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        middleware = AANFMiddleware(app, pipeline=pipeline)
        assert middleware.pipeline is not None


class TestLitellmProxy:
    def test_pre_call_hook_no_pipeline(self):
        from aanf.integration.litellm_proxy import aanf_pre_call_hook, pipeline

        original = pipeline
        import aanf.integration.litellm_proxy as proxy
        proxy.pipeline = None

        import inspect
        if inspect.iscoroutinefunction(aanf_pre_call_hook):
            import asyncio
            asyncio.run(aanf_pre_call_hook({"messages": [{"role": "user", "content": "hi"}]}))

        proxy.pipeline = original


class TestMCPTool:
    @pytest.mark.asyncio
    async def test_call_returns_schema(self):
        from aanf.core.engine import PolicyEngine
        from aanf.core.pipeline import Pipeline
        from aanf.integration.mcp_server import AANFMCPTool

        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        tool = AANFMCPTool(pipeline)
        result = await tool.call("test prompt")
        assert "action" in result
        assert "risk_score" in result
        assert "violations" in result
        assert "allowed" in result

    def test_schema_property(self):
        from aanf.core.engine import PolicyEngine
        from aanf.core.pipeline import Pipeline
        from aanf.integration.mcp_server import AANFMCPTool

        engine = PolicyEngine()
        pipeline = Pipeline(engine)
        tool = AANFMCPTool(pipeline)
        schema = tool.schema
        assert schema["name"] == "aanf_guardrail"
        assert "inputSchema" in schema
        assert "prompt" in schema["inputSchema"]["properties"]
