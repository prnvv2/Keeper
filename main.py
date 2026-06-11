import asyncio
import logging
import sys

from aanf.core.engine import PolicyEngine
from aanf.core.pipeline import Pipeline, RequestContext

from aanf.layers.network import NetworkLayer
from aanf.layers.syntactic import SyntacticLayer
from aanf.layers.semantic import SemanticLayer
from aanf.layers.context import ContextLayer

from aanf.guardrails.prompt_guard import PromptGuard
from aanf.guardrails.alignment_check import AlignmentCheck
from aanf.guardrails.code_shield import CodeShield

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
)
logger = logging.getLogger("aanf")


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
    logger.info("AANF ready. Type prompts or 'quit'.")

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
    from aanf.integration.fastapi_middleware import AANFMiddleware

    app = FastAPI(title="AANF")
    pipeline = build_pipeline()
    app.add_middleware(AANFMiddleware, pipeline=pipeline)

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
