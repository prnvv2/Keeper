from fastapi import FastAPI, Request
from aanf import build_pipeline, RequestContext
from aanf.integration.fastapi_middleware import AANFMiddleware

app = FastAPI(title="My App with AANF")
pipeline = build_pipeline()
app.add_middleware(AANFMiddleware, pipeline=pipeline)


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
        "aanf_action": ctx.action.value,
        "aanf_risk": ctx.risk_score,
        "aanf_violations": ctx.violations,
    }


@app.get("/health")
async def health():
    return {"status": "ok"}
