# integration/langchain_hooks.py
# LangChain callback handler — hooks into the agent execution lifecycle.
# Scans prompts before LLM calls and tool outputs after execution.
# Works with any LangChain agent (ReAct, OpenAI Tools, etc.).

from typing import Any, Dict, List
from langchain_core.callbacks import BaseCallbackHandler
from keeper.core.pipeline import Pipeline, RequestContext
from keeper.core.engine import Action


class KeeperGuardrailHandler(BaseCallbackHandler):
    # LangChain calls on_llm_start before each LLM call,
    # and on_tool_end after each tool returns.

    def __init__(self, pipeline: Pipeline):
        self.pipeline = pipeline

    async def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs):
        # Scan every prompt before it reaches the LLM.
        for prompt in prompts:
            ctx = RequestContext(prompt=prompt)
            ctx = await self.pipeline.run(ctx)
            if ctx.action in (Action.BLOCK, Action.REDACT):
                raise ValueError(f"keeper blocked LLM call: {ctx.violations}")

    async def on_tool_end(self, output: str, **kwargs):
        # Scan tool outputs for injected instructions or unsafe code.
        ctx = RequestContext(prompt="", metadata={"generated_code": output})
        ctx = await self.pipeline.run(ctx)
        if ctx.action in (Action.BLOCK, Action.REDACT):
            raise ValueError(f"keeper blocked tool output: {ctx.violations}")
