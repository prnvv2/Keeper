from fastapi import FastAPI, Request
from keeper import build_pipeline, RequestContext
from keeper.integration.fastapi_middleware import KeeperMiddleware

app = FastAPI(title="My App with keeper")
pipeline = build_pipeline()
app.add_middleware(KeeperMiddleware, pipeline=pipeline)


@app.post("/chat")
async def chat(req: Request):
    data = await req.json()
    ctx = RequestContext(
        prompt=data.get("prompt", ""),
        user_id=req.headers.get("x-user-id", "anonymous"),
        session_id=req.headers.get("x-session-id", "default"),
        ip=req.client.host if req.client else "unknown",
    )
    ctx = await pipeline.run(ctx)
    return {
        "response": "Echo: " + data.get("prompt", ""),
        "keeper_action": ctx.action.value,
        "keeper_risk": ctx.risk_score,
        "keeper_violations": ctx.violations,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
