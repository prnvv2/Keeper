import asyncio
import logging
import sys

from keeper.core.engine import PolicyEngine
from keeper.core.pipeline import Pipeline, RequestContext

from keeper.layers.network import NetworkLayer
from keeper.layers.syntactic import SyntacticLayer
from keeper.layers.semantic import SemanticLayer
from keeper.layers.context import ContextLayer

from keeper.guardrails.prompt_guard import PromptGuard
from keeper.guardrails.alignment_check import AlignmentCheck
from keeper.guardrails.code_shield import CodeShield

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("keeper")


def build_pipeline() -> Pipeline:
    engine = PolicyEngine()
    pipeline = Pipeline(engine)

    pipeline.register(NetworkLayer())
    pipeline.register(SyntacticLayer())
    pipeline.register(PromptGuard())
    pipeline.register(SemanticLayer())
    pipeline.register(AlignmentCheck())
    pipeline.register(CodeShield())
    pipeline.register(ContextLayer())

    return pipeline


async def run_cli():
    pipeline = build_pipeline()
    logger.info("keeper ready. Type prompts or 'quit'.")

    while True:
        prompt = input("\n>>> ")
        if prompt.strip().lower() in ("quit", "exit"):
            break

        ctx = RequestContext(prompt=prompt, user_id="cli", session_id="cli-session")
        ctx = await pipeline.run(ctx)

        print(f"  Action:     {ctx.action.value}")
        print(f"  Risk:       {ctx.risk_score:.2f}")
        print(f"  Latency:    {ctx.latency_ms:.1f}ms")
        if ctx.violations:
            print(f"  Violations: {ctx.violations}")


def run_server():
    from fastapi import FastAPI, Request
    from keeper.integration.fastapi_middleware import keeperMiddleware

    app = FastAPI(title="keeper")
    pipeline = build_pipeline()
    app.add_middleware(keeperMiddleware, pipeline=pipeline)

    @app.post("/chat")
    async def chat(req: Request):
        data = await req.json()
        prompt = data.get("prompt", "")
        ctx = RequestContext(
            prompt=prompt,
            user_id=req.headers.get("x-user-id", ""),
            session_id=req.headers.get("x-session-id", ""),
            ip=req.client.host if req.client else "",
        )
        ctx = await pipeline.run(ctx)
        return {
            "action": ctx.action.value,
            "risk_score": ctx.risk_score,
            "violations": ctx.violations,
        }

    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)


def entry_point():
    if "--server" in sys.argv:
        run_server()
    else:
        asyncio.run(run_cli())


if __name__ == "__main__":
    entry_point()
