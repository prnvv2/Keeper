# integration/mcp_server.py
# Model Context Protocol (MCP) server adapter.
# Exposes AANF as a standard MCP tool that any MCP-compatible
# application (Claude Desktop, VS Code, etc.) can invoke.

from aanf.core.pipeline import Pipeline, RequestContext
from aanf.core.engine import Action


class AANFMCPTool:
    # Implements the MCP tool interface — call() + schema().

    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    async def call(self, prompt: str, **kwargs) -> dict:
        # Run the full AANF pipeline and return structured results.
        ctx = RequestContext(prompt=prompt, metadata=kwargs)
        ctx = await self.pipeline.run(ctx)
        return {
            "action": ctx.action.value,
            "risk_score": ctx.risk_score,
            "violations": ctx.violations,
            "allowed": ctx.action == Action.ALLOW,
        }

    @property
    def schema(self) -> dict:
        # MCP tool schema — describes the tool for auto-discovery.
        return {
            "name": "aanf_guardrail",
            "description": "Scans a prompt for security violations",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "prompt": {"type": "string"},
                },
                "required": ["prompt"],
            },
        }
