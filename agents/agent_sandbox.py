# agents/agent_sandbox.py
# Mediates agent tool calls — enforces allow/deny lists for
# tool access (file I/O, HTTP, shell, etc.) and captures
# tool metadata for downstream scanning.

from aanf.core.pipeline import RequestContext
from aanf.core.engine import Action


class AgentSandbox:
    # Each agent tool call passes through here before execution.
    # Policies come from config/policies.yaml.

    def __init__(self, allowed_tools: list = None, denied_tools: list = None):
        self.allowed_tools = allowed_tools or []  # If set, only these tools are allowed
        self.denied_tools = denied_tools or []     # Explicitly blocked tools

    async def intercept_tool_call(self, ctx: RequestContext, tool_name: str, tool_args: dict) -> RequestContext:
        # Block the call if tool is denied or not in allowlist.
        if tool_name in self.denied_tools:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"sandbox: denied tool '{tool_name}'")
            return ctx

        if self.allowed_tools and tool_name not in self.allowed_tools:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"sandbox: tool '{tool_name}' not in allowlist")
            return ctx

        ctx.metadata["tool_name"] = tool_name
        ctx.metadata["tool_args"] = tool_args
        return ctx
