"""The gateway ASGI application.

Request lifecycle for ``POST /v1/chat/completions`` (``/v1/messages`` is the
same with Anthropic's wire format)::

    client ──► access control (identity, model RBAC, rate limit)
           ──► tool definitions screened + pinned        (MCP03 / ASI04)
           ──► new turn screened: user text as INPUT,
               tool results as TOOL_RESULT                (LLM01, LLM02, MCP06 …)
           ──► upstream model
           ──► response text screened as OUTPUT           (LLM02, LLM05, LLM07 …)
           ──► proposed tool calls mediated as TOOL_CALL  (LLM06, ASI02, ASI05 …)
           ──► client, with x-keeper-* headers

**Only the new turn is screened.** Chat APIs resend the whole conversation on
every request. Re-screening every historical message would multiply cost and
emit duplicate audit events for content already judged; messages after the
last assistant turn are the ones that have not been seen yet.

**Tool calls are judged against what caused them.** If the new turn contained
tool results (or other lower-trust content), tool calls the model proposes in
response are mediated at that lower trust level — which is exactly the
indirect-injection-to-action path ``token_flow`` exists to stop.

**Streaming never forwards unchecked text.** Deltas are buffered and released
only after a checkpoint evaluation has passed the text that contains them, so
a leak can be cut mid-stream without any of it reaching the client. Tool-call
deltas are held entirely until the call can be mediated as a whole. The cost is
up to ``stream_checkpoint_chars`` of added latency per checkpoint.

Anthropic ``stream: true`` requests are fulfilled by a buffered upstream call
replayed as a spec-shaped SSE stream: correct for every client, without
token-by-token latency. Native Anthropic streaming is a planned addition.
"""

from __future__ import annotations

import contextlib
import hmac
import json
import time
from collections.abc import AsyncIterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

try:
    import httpx
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
    from starlette.background import BackgroundTask
    from starlette.concurrency import run_in_threadpool
except ImportError as exc:  # pragma: no cover - depends on installed extras
    raise ImportError(
        "the Keeper gateway needs its optional dependencies: pip install 'keeper-firewall[gateway]'"
    ) from exc

from ..client import Keeper
from ..errors import AuthenticationError, AuthorizationError, RateLimitError
from ..types import Action, Decision, Message, RequestContext, Stage, TrustLevel

_FORWARD_HEADERS = (
    "authorization", "x-api-key", "anthropic-version", "anthropic-beta",
    "openai-organization", "openai-project", "traceparent",
)


@dataclass(slots=True)
class GatewayConfig:
    upstream: str = "https://api.openai.com/v1"
    anthropic_upstream: str = "https://api.anthropic.com"
    #: When set, replaces whatever key the client sent. Lets the gateway hold
    #: provider credentials so applications never see them.
    upstream_api_key: str | None = None
    anthropic_api_key: str | None = None
    #: ``error``: HTTP ``block_status`` with a structured error body.
    #: ``completion``: HTTP 200 with the refusal as the assistant's message.
    block_mode: str = "error"
    block_status: int = 400
    stream_checkpoint_chars: int = 200
    stream_holdback_chars: int = 48
    timeout_s: float = 120.0
    user_header: str = "x-keeper-user"
    roles_header: str = "x-keeper-roles"
    tenant_header: str = "x-keeper-tenant"
    session_header: str = "x-keeper-session"
    credential_header: str = "x-keeper-key"
    #: Requests larger than this are refused with 413 before parsing.
    max_body_bytes: int = 8 * 1024 * 1024
    #: Enables ``GET /keeper/events`` for callers presenting this bearer key.
    #: Unset (the default) means the endpoint does not exist: recent audit
    #: events contain prompts, and the gateway port is reachable by every
    #: client application.
    admin_key: str | None = None
    #: Pin tool definitions across requests. Off by default: clients of a
    #: shared gateway do not share one tool namespace, and pinning across them
    #: would let the first client to name a tool "search" make every other
    #: client's "search" look like a rug pull. When on, pins are scoped to the
    #: ``x-keeper-tool-server`` header, falling back to tenant, then principal.
    pin_tool_definitions: bool = False
    tool_server_header: str = "x-keeper-tool-server"


# ---------------------------------------------------------------------------
# Wire-format helpers
# ---------------------------------------------------------------------------

_TRUST_BY_ROLE = {
    "system": TrustLevel.SYSTEM,
    "developer": TrustLevel.SYSTEM,
    "user": TrustLevel.USER,
    "assistant": TrustLevel.USER,
    "tool": TrustLevel.TOOL,
    "function": TrustLevel.TOOL,
}


def content_text(content: Any) -> str:
    """Flatten OpenAI/Anthropic message content (string or parts) to text."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, Mapping):
                kind = part.get("type")
                if kind in ("text", "input_text", "output_text"):
                    parts.append(str(part.get("text", "")))
                elif kind == "tool_result":
                    parts.append(content_text(part.get("content")))
        return "\n".join(p for p in parts if p)
    return str(content)


def _replace_text(message: dict[str, Any], text: str) -> None:
    """Write redacted text back. Non-text parts (images, tool results) are kept, first,
    because Anthropic requires ``tool_result`` blocks to lead a user message."""
    content = message.get("content")
    if isinstance(content, list):
        others = [p for p in content if not (isinstance(p, Mapping) and p.get("type") in ("text", "input_text"))]
        message["content"] = [*others, {"type": "text", "text": text}]
    else:
        message["content"] = text


def _new_turn_start(messages: Sequence[Mapping[str, Any]]) -> int:
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].get("role") == "assistant":
            return i + 1
    return 0


def open_construct(text: str) -> int:
    """Index where an unterminated markdown link/image or HTML tag starts, else ``len(text)``.

    A streamed ``![x](https://evil.example/?d=...`` cannot be judged until its
    closing parenthesis arrives, so it must not be released before then.
    """
    cut = len(text)
    bracket = text.rfind("[")
    if bracket != -1:
        rest = text[bracket:]
        close = rest.find("]")
        unterminated = (
            close == -1
            or close == len(rest) - 1                       # "]" last: "(" may follow
            or (rest[close + 1] == "(" and ")" not in rest[close + 1:])
        )
        if unterminated:
            cut = bracket - 1 if bracket > 0 and text[bracket - 1] == "!" else bracket
    angle = text.rfind("<")
    if angle != -1 and ">" not in text[angle:]:
        cut = min(cut, angle)
    return cut


def _worst(decisions: Sequence[Decision]) -> Decision | None:
    worst: Decision | None = None
    for d in decisions:
        if worst is None or d.action.escalates_over(worst.action):
            worst = d
    return worst


def _parse_args(raw: Any) -> dict[str, Any]:
    if isinstance(raw, Mapping):
        return dict(raw)
    try:
        value = json.loads(raw or "{}")
        return value if isinstance(value, dict) else {"_value": value}
    except (TypeError, ValueError):
        return {"_raw": str(raw)}


# ---------------------------------------------------------------------------
# The gateway
# ---------------------------------------------------------------------------


class KeeperGateway:
    def __init__(
        self,
        keeper: Keeper,
        config: GatewayConfig | None = None,
        *,
        client: httpx.AsyncClient | None = None,
    ) -> None:
        self.keeper = keeper
        self.config = config or GatewayConfig()
        self.client = client or httpx.AsyncClient(timeout=self.config.timeout_s)
        @contextlib.asynccontextmanager
        async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
            yield
            await self.client.aclose()
            self.keeper.flush()

        self.app = FastAPI(
            title="Keeper AI Gateway",
            description="OpenAI/Anthropic-compatible proxy enforcing the Keeper AI firewall.",
            version=__import__("keeper_firewall").__version__,
            lifespan=lifespan,
        )
        self._routes()

    # -- routes ------------------------------------------------------------

    def _routes(self) -> None:
        app = self.app

        @app.get("/healthz")
        async def healthz() -> Any:
            return self.keeper.health()

        @app.get("/metrics")
        async def metrics() -> Any:
            return PlainTextResponse(self.keeper.metrics_text(), media_type="text/plain; version=0.0.4")

        @app.get("/keeper/coverage")
        async def coverage() -> Any:
            return {"threats": self.keeper.coverage()}

        @app.get("/keeper/events")
        async def events(request: Request, limit: int = 50) -> Any:
            if not self._is_admin(request):
                return JSONResponse({"error": {"message": "not found", "type": "not_found"}}, status_code=404)
            return {"events": self.keeper.recent_events(min(max(limit, 1), 500))}

        @app.post("/v1/chat/completions")
        async def chat_completions(request: Request) -> Any:
            return await self._openai(request)

        @app.post("/v1/messages")
        async def messages(request: Request) -> Any:
            return await self._anthropic(request)

    # -- shared screening --------------------------------------------------

    def _is_admin(self, request: Request) -> bool:
        key = self.config.admin_key
        if not key:
            return False
        header = request.headers.get("authorization") or ""
        presented = header[7:] if header.lower().startswith("bearer ") else ""
        return bool(presented) and hmac.compare_digest(presented.encode(), key.encode())

    async def _read_body(self, request: Request) -> dict[str, Any] | Response:
        limit = self.config.max_body_bytes
        declared = request.headers.get("content-length")
        if declared and declared.isdigit() and int(declared) > limit:
            return JSONResponse({"error": {"message": "request body too large", "type": "payload_too_large"}},
                                status_code=413)
        raw = await request.body()
        if len(raw) > limit:
            return JSONResponse({"error": {"message": "request body too large", "type": "payload_too_large"}},
                                status_code=413)
        try:
            body = json.loads(raw)
        except ValueError:
            return JSONResponse({"error": {"message": "request body is not valid JSON", "type": "invalid_request"}},
                                status_code=400)
        if not isinstance(body, dict):
            return JSONResponse({"error": {"message": "request body must be a JSON object", "type": "invalid_request"}},
                                status_code=400)
        return body

    def _tool_server(self, request: Request, context: RequestContext) -> str:
        return (
            request.headers.get(self.config.tool_server_header)
            or (f"tenant:{context.principal.tenant}" if context.principal.tenant else f"principal:{context.principal.id}")
        )

    def _context(self, request: Request, body: Mapping[str, Any]) -> RequestContext:
        cfg, h = self.config, request.headers
        roles = [r.strip() for r in (h.get(cfg.roles_header) or "").split(",") if r.strip()]
        raw_metadata = body.get("metadata")
        metadata: Mapping[str, Any] = raw_metadata if isinstance(raw_metadata, Mapping) else {}
        return self.keeper.context(
            credential=h.get(cfg.credential_header),
            user=h.get(cfg.user_header) or body.get("user") or metadata.get("user_id"),
            roles=roles,
            tenant=h.get(cfg.tenant_header),
            session=h.get(cfg.session_header),
            model=body.get("model"),
            traceparent=h.get("traceparent"),
            tags={"gateway": True, "route": request.url.path},
        )

    def _screen_request(
        self,
        context: RequestContext,
        turns: Sequence[tuple[Any, str, TrustLevel, Stage]],
        history: list[Message],
        tools: Sequence[Mapping[str, Any]],
        max_tokens: Any,
        tool_server: str = "request",
    ) -> tuple[list[Decision], TrustLevel]:
        """Run access control and every input-side stage. Mutates redacted turns in place."""
        self.keeper.authorize(context, model=context.model)
        decisions: list[Decision] = []

        if tools:
            for _tool, decision in self.keeper.check_tool_definitions(
                tools, context, server=tool_server, pin=self.config.pin_tool_definitions
            ):
                decisions.append(decision)
                if decision.blocked:
                    return decisions, TrustLevel.EXTERNAL

        cause = TrustLevel.USER_CONFIRMED
        for message, text, trust, stage in turns:
            if trust.authority() < cause.authority():
                cause = trust
            if not text.strip():
                continue
            decision = self.keeper.pipeline.evaluate(
                stage, text, context, trust=trust, history=history,
                metadata={"max_tokens": max_tokens if isinstance(max_tokens, int) else None},
            )
            decisions.append(decision)
            if decision.blocked:
                break
            if decision.action is Action.REDACT and decision.payload is not None:
                _replace_text(message, decision.payload)
        return decisions, (cause if cause is not TrustLevel.USER_CONFIRMED else TrustLevel.USER)

    def _screen_output(self, context: RequestContext, text: str, latency_ms: float,
                       tokens_in: int | None, tokens_out: int | None) -> Decision:
        return self.keeper.pipeline.evaluate(
            Stage.OUTPUT, text, context, trust=TrustLevel.SYSTEM,
            latency_ms=latency_ms, tokens_in=tokens_in, tokens_out=tokens_out,
        )

    def _screen_tool_calls(self, context: RequestContext, calls: Sequence[tuple[str, dict[str, Any]]],
                           cause: TrustLevel) -> list[Decision]:
        return [self.keeper.check_tool_call(name, args, context, trust=cause) for name, args in calls]

    def _headers(self, context: RequestContext, decisions: Sequence[Decision]) -> dict[str, str]:
        worst = _worst(decisions)
        risk = max((d.risk.score for d in decisions if d.risk is not None), default=0)
        threats: dict[str, None] = {}
        for d in decisions:
            threats.update(dict.fromkeys(d.threats))
        return {
            "x-keeper-correlation-id": context.correlation_id,
            "x-keeper-action": worst.action.value if worst else "allow",
            "x-keeper-risk": str(risk),
            "x-keeper-threats": ",".join(threats),
        }

    def _block_body(self, decision: Decision, *, anthropic: bool = False) -> dict[str, Any]:
        detail = {
            "message": self.keeper._block_message(decision),
            "type": "keeper_blocked",
            "code": "content_blocked",
            "stage": decision.stage.value,
            "correlation_id": decision.correlation_id,
            "threats": list(decision.threats),
            "risk": decision.risk.to_dict() if decision.risk is not None else None,
        }
        if anthropic:
            return {"type": "error", "error": detail}
        return {"error": detail}

    def _upstream_headers(self, request: Request, *, anthropic: bool) -> dict[str, str]:
        headers = {k: v for k, v in request.headers.items() if k.lower() in _FORWARD_HEADERS}
        headers["content-type"] = "application/json"
        if anthropic and self.config.anthropic_api_key:
            headers.pop("authorization", None)
            headers["x-api-key"] = self.config.anthropic_api_key
            headers.setdefault("anthropic-version", "2023-06-01")
        elif not anthropic and self.config.upstream_api_key:
            headers.pop("x-api-key", None)
            headers["authorization"] = f"Bearer {self.config.upstream_api_key}"
        return headers

    async def _access_error(self, exc: Exception, *, anthropic: bool) -> JSONResponse:
        status = 429 if isinstance(exc, RateLimitError) else 401 if isinstance(exc, AuthenticationError) else 403
        detail = {"message": str(exc), "type": "keeper_access_denied"}
        headers = {}
        if isinstance(exc, RateLimitError) and exc.retry_after:
            headers["retry-after"] = str(int(exc.retry_after) + 1)
        body = {"type": "error", "error": detail} if anthropic else {"error": detail}
        return JSONResponse(body, status_code=status, headers=headers)

    # -- OpenAI ------------------------------------------------------------

    async def _openai(self, request: Request) -> Response:
        parsed_body = await self._read_body(request)
        if isinstance(parsed_body, Response):
            return parsed_body
        body: dict[str, Any] = parsed_body
        messages: list[dict[str, Any]] = [dict(m) for m in body.get("messages") or []]
        body["messages"] = messages
        try:
            context = self._context(request, body)
        except AuthenticationError as exc:
            return await self._access_error(exc, anthropic=False)
        context.provider = "openai-compatible"

        history = [
            Message(role=str(m.get("role", "user")), content=content_text(m.get("content")),
                    trust=_TRUST_BY_ROLE.get(str(m.get("role")), TrustLevel.EXTERNAL))
            for m in messages
        ]
        context.messages = history
        start = _new_turn_start(messages)
        turns = []
        for m in messages[start:]:
            role = str(m.get("role", "user"))
            if role in ("system", "developer"):
                continue
            trust = _TRUST_BY_ROLE.get(role, TrustLevel.EXTERNAL)
            stage = Stage.TOOL_RESULT if trust is TrustLevel.TOOL else Stage.INPUT
            turns.append((m, content_text(m.get("content")), trust, stage))

        try:
            decisions, cause = await run_in_threadpool(
                self._screen_request, context, turns, history[:start], body.get("tools") or [],
                body.get("max_tokens") or body.get("max_completion_tokens"), self._tool_server(request, context),
            )
        except (AuthorizationError, RateLimitError, AuthenticationError) as exc:
            return await self._access_error(exc, anthropic=False)

        blocked = next((d for d in decisions if d.blocked), None)
        if blocked is not None:
            return self._openai_blocked(body, context, blocked, decisions)

        url = self.config.upstream.rstrip("/") + "/chat/completions"
        headers = self._upstream_headers(request, anthropic=False)
        if body.get("stream"):
            return await self._openai_stream(url, headers, body, context, cause, decisions)

        t0 = time.perf_counter()
        upstream = await self.client.post(url, json=body, headers=headers)
        latency = (time.perf_counter() - t0) * 1000
        if upstream.status_code >= 400:
            return Response(upstream.content, status_code=upstream.status_code,
                            media_type=upstream.headers.get("content-type", "application/json"))
        data = upstream.json()
        usage = data.get("usage") or {}

        for choice in data.get("choices") or []:
            message = choice.get("message") or {}
            text = content_text(message.get("content"))
            out = await run_in_threadpool(
                self._screen_output, context, text, latency, usage.get("prompt_tokens"), usage.get("completion_tokens")
            )
            decisions.append(out)
            if out.blocked:
                message["content"] = self.keeper._block_message(out)
                message.pop("tool_calls", None)
                choice["finish_reason"] = "content_filter"
                continue
            if out.action is Action.REDACT and out.payload is not None:
                message["content"] = out.payload
            calls = message.get("tool_calls") or []
            if calls:
                tool_decisions = await run_in_threadpool(
                    self._screen_tool_calls, context,
                    [((c.get("function") or {}).get("name", ""), _parse_args((c.get("function") or {}).get("arguments")))
                     for c in calls],
                    cause,
                )
                decisions.extend(tool_decisions)
                refused = next((d for d in tool_decisions if d.blocked), None)
                if refused is not None:
                    message.pop("tool_calls", None)
                    message["content"] = self.keeper._block_message(refused)
                    choice["finish_reason"] = "content_filter"

        if any(d.blocked for d in decisions) and self.config.block_mode == "error":
            return JSONResponse(self._block_body(next(d for d in decisions if d.blocked)),
                                status_code=self.config.block_status, headers=self._headers(context, decisions))
        return JSONResponse(data, headers=self._headers(context, decisions))

    def _openai_blocked(self, body: Mapping[str, Any], context: RequestContext, blocked: Decision,
                        decisions: Sequence[Decision]) -> Response:
        headers = self._headers(context, decisions)
        if self.config.block_mode == "error":
            return JSONResponse(self._block_body(blocked), status_code=self.config.block_status, headers=headers)
        text = self.keeper._block_message(blocked)
        created = int(time.time())
        if body.get("stream"):
            async def gen() -> AsyncIterator[bytes]:
                chunk = {"id": f"chatcmpl-{context.correlation_id}", "object": "chat.completion.chunk",
                         "created": created, "model": body.get("model"),
                         "choices": [{"index": 0, "delta": {"role": "assistant", "content": text},
                                      "finish_reason": "content_filter"}]}
                yield f"data: {json.dumps(chunk)}\n\n".encode()
                yield b"data: [DONE]\n\n"
            return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)
        return JSONResponse(
            {
                "id": f"chatcmpl-{context.correlation_id}",
                "object": "chat.completion",
                "created": created,
                "model": body.get("model"),
                "choices": [{"index": 0, "message": {"role": "assistant", "content": text},
                             "finish_reason": "content_filter"}],
                "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
            },
            headers=headers,
        )

    async def _openai_stream(self, url: str, headers: dict[str, str], body: dict[str, Any],
                             context: RequestContext, cause: TrustLevel, decisions: list[Decision]) -> Response:
        request = self.client.build_request("POST", url, json=body, headers=headers)
        t0 = time.perf_counter()
        upstream = await self.client.send(request, stream=True)
        if upstream.status_code >= 400:
            content = await upstream.aread()
            await upstream.aclose()
            return Response(content, status_code=upstream.status_code,
                            media_type=upstream.headers.get("content-type", "application/json"))

        cfg = self.config
        pipeline = self.keeper.pipeline

        async def gen() -> AsyncIterator[bytes]:
            text = ""          # everything the model has produced
            sent = ""          # what the client has received (checked, possibly redacted)
            template: dict[str, Any] = {}
            tool_parts: dict[int, dict[str, Any]] = {}
            finish: str | None = None
            trailing: list[dict[str, Any]] = []
            last_check = 0

            def chunk(delta: dict[str, Any], finish_reason: str | None = None) -> bytes:
                c = {**template, "choices": [{"index": 0, "delta": delta, "finish_reason": finish_reason}]}
                return f"data: {json.dumps(c)}\n\n".encode()

            async def release(final: bool) -> tuple[bytes | None, Decision]:
                nonlocal sent
                stage = Stage.OUTPUT if final else Stage.STREAM
                if final:
                    decision = await run_in_threadpool(
                        self._screen_output, context, text, (time.perf_counter() - t0) * 1000, None, None
                    )
                else:
                    decision = await run_in_threadpool(
                        pipeline.evaluate, stage, text, context, trust=TrustLevel.SYSTEM, emit=False
                    )
                    if decision.blocked:
                        pipeline.emit(decision, context, response=text)
                if decision.blocked:
                    return None, decision
                checked = decision.payload if decision.action is Action.REDACT and decision.payload else text
                limit = len(checked) if final else max(
                    len(sent), min(len(checked) - cfg.stream_holdback_chars, open_construct(checked))
                )
                out = checked[len(sent):limit] if checked.startswith(sent) else ""
                if not out:
                    return b"", decision
                sent += out
                return chunk({"content": out}), decision

            try:
                async for line in upstream.aiter_lines():
                    if not line.startswith("data:"):
                        continue
                    data = line[5:].strip()
                    if data == "[DONE]":
                        break
                    try:
                        parsed = json.loads(data)
                    except ValueError:
                        continue
                    choices = parsed.get("choices") or []
                    if not choices:
                        trailing.append(parsed)  # usage-only chunk
                        continue
                    if not template:
                        template = {k: v for k, v in parsed.items() if k != "choices"}
                    choice = choices[0]
                    delta = choice.get("delta") or {}
                    if delta.get("role") and not sent and not text:
                        yield chunk({"role": delta["role"], "content": ""})
                    for part in delta.get("tool_calls") or []:
                        try:
                            index = int(part.get("index", 0))
                        except (TypeError, ValueError):
                            index = 0
                        slot = tool_parts.setdefault(index,
                                                     {"id": None, "name": "", "arguments": ""})
                        slot["id"] = part.get("id") or slot["id"]
                        fn = part.get("function") or {}
                        slot["name"] += fn.get("name") or ""
                        slot["arguments"] += fn.get("arguments") or ""
                    if delta.get("content"):
                        text += delta["content"]
                        if len(text) - last_check >= cfg.stream_checkpoint_chars:
                            last_check = len(text)
                            out, decision = await release(final=False)
                            if out is None:
                                decisions.append(decision)
                                yield chunk({"content": "\n\n" + self.keeper._block_message(decision)}, "content_filter")
                                yield b"data: [DONE]\n\n"
                                return
                            if out:
                                yield out
                    if choice.get("finish_reason"):
                        finish = choice["finish_reason"]

                out, decision = await release(final=True)
                decisions.append(decision)
                if out is None:
                    yield chunk({"content": "\n\n" + self.keeper._block_message(decision)}, "content_filter")
                    yield b"data: [DONE]\n\n"
                    return
                if out:
                    yield out

                if tool_parts:
                    calls = [(p["name"], _parse_args(p["arguments"])) for _, p in sorted(tool_parts.items())]
                    tool_decisions = await run_in_threadpool(self._screen_tool_calls, context, calls, cause)
                    decisions.extend(tool_decisions)
                    refused = next((d for d in tool_decisions if d.blocked), None)
                    if refused is not None:
                        yield chunk({"content": self.keeper._block_message(refused)}, "content_filter")
                        yield b"data: [DONE]\n\n"
                        return
                    yield chunk({"tool_calls": [
                        {"index": i, "id": p["id"], "type": "function",
                         "function": {"name": p["name"], "arguments": p["arguments"]}}
                        for i, p in sorted(tool_parts.items())
                    ]})
                yield chunk({}, finish or "stop")
                for extra in trailing:
                    yield f"data: {json.dumps(extra)}\n\n".encode()
                yield b"data: [DONE]\n\n"
            finally:
                await upstream.aclose()

        return StreamingResponse(gen(), media_type="text/event-stream",
                                 headers=self._headers(context, decisions),
                                 background=BackgroundTask(upstream.aclose))

    # -- Anthropic ---------------------------------------------------------

    async def _anthropic(self, request: Request) -> Response:
        parsed_body = await self._read_body(request)
        if isinstance(parsed_body, Response):
            return parsed_body
        body: dict[str, Any] = parsed_body
        messages: list[dict[str, Any]] = [dict(m) for m in body.get("messages") or []]
        body["messages"] = messages
        try:
            context = self._context(request, body)
        except AuthenticationError as exc:
            return await self._access_error(exc, anthropic=True)
        context.provider = "anthropic"

        history: list[Message] = []
        if body.get("system"):
            history.append(Message(role="system", content=content_text(body["system"]), trust=TrustLevel.SYSTEM))
        for m in messages:
            history.append(Message(role=str(m.get("role", "user")), content=content_text(m.get("content")),
                                   trust=TrustLevel.USER))
        context.messages = history
        start = _new_turn_start(messages)

        turns = []
        for m in messages[start:]:
            content = m.get("content")
            blocks = content if isinstance(content, list) else [{"type": "text", "text": content or ""}]
            texts = [b for b in blocks if isinstance(b, Mapping) and b.get("type") == "text"]
            results = [b for b in blocks if isinstance(b, Mapping) and b.get("type") == "tool_result"]
            for result in results:
                # Each tool_result block is its own boundary crossing; redaction
                # is written back into that block.
                turns.append((result, content_text(result.get("content")), TrustLevel.TOOL, Stage.TOOL_RESULT))
            if texts:
                turns.append((m, "\n".join(str(b.get("text", "")) for b in texts), TrustLevel.USER, Stage.INPUT))

        try:
            decisions, cause = await run_in_threadpool(
                self._screen_request, context, turns, history[: len(history) - (len(messages) - start)],
                body.get("tools") or [], body.get("max_tokens"), self._tool_server(request, context),
            )
        except (AuthorizationError, RateLimitError, AuthenticationError) as exc:
            return await self._access_error(exc, anthropic=True)

        wants_stream = bool(body.pop("stream", False))
        blocked = next((d for d in decisions if d.blocked), None)
        if blocked is not None:
            if self.config.block_mode == "error":
                return JSONResponse(self._block_body(blocked, anthropic=True), status_code=self.config.block_status,
                                    headers=self._headers(context, decisions))
            data = self._anthropic_refusal(body, context, self.keeper._block_message(blocked))
            return self._anthropic_reply(data, wants_stream, context, decisions)

        url = self.config.anthropic_upstream.rstrip("/") + "/v1/messages"
        t0 = time.perf_counter()
        upstream = await self.client.post(url, json=body, headers=self._upstream_headers(request, anthropic=True))
        latency = (time.perf_counter() - t0) * 1000
        if upstream.status_code >= 400:
            return Response(upstream.content, status_code=upstream.status_code,
                            media_type=upstream.headers.get("content-type", "application/json"))
        data = upstream.json()
        usage = data.get("usage") or {}
        blocks = data.get("content") or []

        text = "\n".join(str(b.get("text", "")) for b in blocks if b.get("type") == "text")
        out = await run_in_threadpool(
            self._screen_output, context, text, latency, usage.get("input_tokens"), usage.get("output_tokens")
        )
        decisions.append(out)
        refused: Decision | None = out if out.blocked else None
        if refused is None:
            if out.action is Action.REDACT and out.payload is not None:
                text_blocks = [b for b in blocks if b.get("type") == "text"]
                if text_blocks:
                    text_blocks[0]["text"] = out.payload
                    for b in text_blocks[1:]:
                        blocks.remove(b)
            calls = [(b.get("name", ""), _parse_args(b.get("input"))) for b in blocks if b.get("type") == "tool_use"]
            if calls:
                tool_decisions = await run_in_threadpool(self._screen_tool_calls, context, calls, cause)
                decisions.extend(tool_decisions)
                refused = next((d for d in tool_decisions if d.blocked), None)
        if refused is not None:
            if self.config.block_mode == "error":
                return JSONResponse(self._block_body(refused, anthropic=True), status_code=self.config.block_status,
                                    headers=self._headers(context, decisions))
            data["content"] = [{"type": "text", "text": self.keeper._block_message(refused)}]
            data["stop_reason"] = "end_turn"
        return self._anthropic_reply(data, wants_stream, context, decisions)

    @staticmethod
    def _anthropic_refusal(body: Mapping[str, Any], context: RequestContext, text: str) -> dict[str, Any]:
        return {
            "id": f"msg_{context.correlation_id}",
            "type": "message",
            "role": "assistant",
            "model": body.get("model"),
            "content": [{"type": "text", "text": text}],
            "stop_reason": "end_turn",
            "stop_sequence": None,
            "usage": {"input_tokens": 0, "output_tokens": 0},
        }

    def _anthropic_reply(self, data: dict[str, Any], stream: bool, context: RequestContext,
                         decisions: Sequence[Decision]) -> Response:
        headers = self._headers(context, decisions)
        if not stream:
            return JSONResponse(data, headers=headers)

        def event(kind: str, payload: Mapping[str, Any]) -> bytes:
            return f"event: {kind}\ndata: {json.dumps({'type': kind, **payload})}\n\n".encode()

        async def gen() -> AsyncIterator[bytes]:
            head = {k: v for k, v in data.items() if k not in ("content", "stop_reason", "stop_sequence")}
            usage = dict(data.get("usage") or {})
            yield event("message_start", {"message": {**head, "content": [], "stop_reason": None,
                                                      "stop_sequence": None,
                                                      "usage": {**usage, "output_tokens": 0}}})
            for i, block in enumerate(data.get("content") or []):
                if block.get("type") == "tool_use":
                    yield event("content_block_start", {"index": i, "content_block": {**block, "input": {}}})
                    yield event("content_block_delta", {"index": i, "delta": {
                        "type": "input_json_delta", "partial_json": json.dumps(block.get("input") or {})}})
                else:
                    yield event("content_block_start", {"index": i, "content_block": {"type": "text", "text": ""}})
                    yield event("content_block_delta", {"index": i, "delta": {
                        "type": "text_delta", "text": block.get("text", "")}})
                yield event("content_block_stop", {"index": i})
            yield event("message_delta", {"delta": {"stop_reason": data.get("stop_reason"),
                                                    "stop_sequence": data.get("stop_sequence")},
                                          "usage": {"output_tokens": usage.get("output_tokens", 0)}})
            yield event("message_stop", {})

        return StreamingResponse(gen(), media_type="text/event-stream", headers=headers)


def create_app(
    keeper: Keeper | None = None,
    config: GatewayConfig | None = None,
    *,
    client: httpx.AsyncClient | None = None,
    **keeper_overrides: Any,
) -> FastAPI:
    """Build the gateway ASGI app. ``uvicorn keeper_firewall.gateway:create_app --factory``."""
    keeper = keeper or Keeper(str(keeper_overrides.pop("application", "keeper-gateway")), **keeper_overrides)
    return KeeperGateway(keeper, config, client=client).app
