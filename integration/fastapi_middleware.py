# integration/fastapi_middleware.py
# Drop-in ASGI middleware for FastAPI applications.
# Intercepts every incoming request, runs the keeper pipeline,
# and blocks/redacts before the request reaches your route handler.

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
from keeper.core.pipeline import Pipeline, RequestContext
from keeper.core.engine import Action


class KeeperMiddleware(BaseHTTPMiddleware):
    # Plug into any FastAPI app with app.add_middleware(KeeperMiddleware, pipeline=...)

    def __init__(self, app, pipeline: Pipeline):
        super().__init__(app)
        self.pipeline = pipeline

    async def dispatch(self, request: Request, call_next):
        # Extract the prompt from the request body (JSON or raw text).
        body = await request.body()
        try:
            import json
            data = json.loads(body)
            prompt = data.get("prompt", data.get("messages", [{}])[-1].get("content", ""))
        except Exception:
            prompt = body.decode("utf-8", errors="ignore")

        ctx = RequestContext(
            prompt=prompt,
            user_id=request.headers.get("x-user-id", ""),
            session_id=request.headers.get("x-session-id", ""),
            ip=request.client.host if request.client else "",
        )

        ctx = await self.pipeline.run(ctx)

        if ctx.action in (Action.BLOCK, Action.REDACT):
            return JSONResponse(
                status_code=403,
                content={"error": "blocked by keeper", "reason": ctx.violations},
            )

        response = await call_next(request)
        return response
