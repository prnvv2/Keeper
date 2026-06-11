# integration/litellm_proxy.py
# Integration with LiteLLM proxy server.
# LiteLLM routes requests to 100+ LLM providers — AANF hooks into
# the pre-call pipeline to scan prompts before they reach the provider.

from aanf.core.pipeline import Pipeline, RequestContext
from aanf.core.engine import Action


# Global pipeline reference, set at startup by the LiteLLM config
pipeline: Pipeline = None


async def aanf_pre_call_hook(data: dict) -> dict:
    # LiteLLM calls this before forwarding a request to the LLM provider.
    # If AANF blocks it, LiteLLM raises a PermissionError.
    global pipeline
    if pipeline is None:
        return data

    messages = data.get("messages", [])
    prompt = messages[-1].get("content", "") if messages else ""

    ctx = RequestContext(prompt=prompt)
    ctx = await pipeline.run(ctx)

    if ctx.action in (Action.BLOCK, Action.REDACT):
        raise PermissionError(f"AANF blocked: {ctx.violations}")
    return data


def aanf_auth(user_data: dict) -> dict:
    # Optional auth hook — currently a passthrough.
    return user_data
