# layers/context.py
# Multi-turn attack detection. Maintains session history and checks
# for "goal drift" — gradual manipulation across conversation turns
# (e.g., Crescendo, Echo Chamber attacks).

from keeper.layers.base import BaseLayer
from keeper.core.pipeline import RequestContext
from keeper.core.engine import Action
from keeper.models.ollama_client import OllamaClient


# Prompt that asks Ollama to compare the original goal vs. latest message
DRIFT_PROMPT = """Compare the user's original request with their latest message.
Rate the divergence on 0.0-1.0 (1.0 = completely different goal).
Only output the number.

Original: {original}
Latest: {latest}
Score:"""


class ContextLayer(BaseLayer):
    name = "context"

    def __init__(self):
        self.ollama = OllamaClient()
        self.sessions = {}  # {session_id: [list of prompts]}

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # Track conversation history per session.
        # Once we have 3+ turns, measure semantic drift from the original request.
        sid = ctx.session_id
        history = self.sessions.get(sid, [])
        threshold = config.get("drift_threshold", 0.6)
        model = config.get("model", "llama3.2")

        if not history:
            history.append(ctx.prompt)
            self.sessions[sid] = history
            return ctx

        max_history = config.get("max_history", 20)
        original = history[0]
        history.append(ctx.prompt)
        self.sessions[sid] = history[-max_history:]

        if len(history) < 3:
            return ctx

        prompt = DRIFT_PROMPT.format(original=original[:1000], latest=ctx.prompt[:1000])
        try:
            resp = await self.ollama.generate(model, prompt)
            drift = float(resp.strip())
        except Exception:
            drift = 0.0

        if drift >= threshold:
            ctx.action = Action.BLOCK
            ctx.violations.append(f"context drift: {drift:.2f}")
        return ctx
