"""Built-in HTTP providers: OpenAI-compatible and Anthropic.

Implemented on :mod:`urllib` so that ``pip install keeper-firewall`` pulls in no
model SDK. "OpenAI-compatible" covers a large share of what people actually run
— vLLM, Ollama, Together, Groq, LM Studio, Azure OpenAI with a base-URL change
— which is why it is one adapter with a configurable ``base_url`` rather than
one class per vendor.

If the application already has a vendor SDK configured, prefer
:class:`~keeper_firewall.providers.base.CallableProvider`: it keeps the app's
retry policy, proxy settings, and provider-specific parameters intact instead
of reimplementing them here badly.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterator, Sequence
from typing import Any

from ..errors import KeeperError
from ..transport.client import ControlPlaneClient
from ..types import LLMResponse, Message
from .base import parse_tool_calls, require


class OpenAICompatibleProvider:
    """Chat-completions client for any OpenAI-compatible endpoint."""

    name = "openai"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.openai.com/v1",
        model: str = "gpt-4o-mini",
        timeout_ms: int = 60_000,
        organization: str | None = None,
        default_params: dict[str, Any] | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.default_params = dict(default_params or {})
        headers = {}
        if organization:
            headers["OpenAI-Organization"] = organization
        self._client = ControlPlaneClient(
            self.base_url, api_key=self.api_key, timeout_ms=timeout_ms, extra_headers=headers
        )

    def _body(self, messages: Sequence[Message], model: str | None, stream: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
        return {
            "model": model or self.model,
            "messages": [m.to_dict() for m in messages],
            "stream": stream,
            **self.default_params,
            **kwargs,
        }

    def complete(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> LLMResponse:
        require(self.api_key, "OpenAICompatibleProvider needs an api_key or OPENAI_API_KEY")
        response = self._client.post_json("/chat/completions", self._body(messages, model, False, kwargs))
        if not response.ok:
            raise KeeperError(f"model provider returned HTTP {response.status}: {response.body[:300]!r}")
        data = response.json() or {}
        choice = (data.get("choices") or [{}])[0]
        message = choice.get("message") or {}
        usage = data.get("usage") or {}
        return LLMResponse(
            text=message.get("content") or "",
            model=data.get("model", model or self.model),
            raw=data,
            tokens_in=usage.get("prompt_tokens"),
            tokens_out=usage.get("completion_tokens"),
            finish_reason=choice.get("finish_reason"),
            tool_calls=parse_tool_calls(message.get("tool_calls")),
        )

    def stream(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> Iterator[str]:
        require(self.api_key, "OpenAICompatibleProvider needs an api_key or OPENAI_API_KEY")
        body = json.dumps(self._body(messages, model, True, kwargs)).encode()
        for event in _sse(self._client, "/chat/completions", body):
            if event == "[DONE]":
                return
            try:
                chunk = json.loads(event)
            except json.JSONDecodeError:
                continue
            delta = ((chunk.get("choices") or [{}])[0].get("delta") or {}).get("content")
            if delta:
                yield delta


class AnthropicProvider:
    """Messages-API client for Anthropic models."""

    name = "anthropic"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        base_url: str = "https://api.anthropic.com/v1",
        model: str = "claude-sonnet-5",
        max_tokens: int = 1024,
        timeout_ms: int = 60_000,
        version: str = "2023-06-01",
        default_params: dict[str, Any] | None = None,
    ) -> None:
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.max_tokens = max_tokens
        self.default_params = dict(default_params or {})
        self._client = ControlPlaneClient(
            self.base_url,
            timeout_ms=timeout_ms,
            extra_headers={"anthropic-version": version, "x-api-key": self.api_key or ""},
        )

    @staticmethod
    def _split_system(messages: Sequence[Message]) -> tuple[str | None, list[dict[str, Any]]]:
        """Anthropic takes the system prompt as a top-level field, not a turn."""
        system_parts = [m.content for m in messages if m.role == "system"]
        turns = [m.to_dict() for m in messages if m.role != "system"]
        return ("\n\n".join(system_parts) or None), turns

    def _body(self, messages: Sequence[Message], model: str | None, stream: bool, kwargs: dict[str, Any]) -> dict[str, Any]:
        system, turns = self._split_system(messages)
        body: dict[str, Any] = {
            "model": model or self.model,
            "messages": turns,
            "max_tokens": kwargs.pop("max_tokens", self.max_tokens),
            **self.default_params,
            **kwargs,
        }
        if system:
            body["system"] = system
        if stream:
            body["stream"] = True
        return body

    def complete(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> LLMResponse:
        require(self.api_key, "AnthropicProvider needs an api_key or ANTHROPIC_API_KEY")
        response = self._client.post_json("/messages", self._body(messages, model, False, kwargs))
        if not response.ok:
            raise KeeperError(f"model provider returned HTTP {response.status}: {response.body[:300]!r}")
        data = response.json() or {}
        blocks = data.get("content") or []
        text = "".join(b.get("text", "") for b in blocks if b.get("type") == "text")
        usage = data.get("usage") or {}
        tool_use = [
            {"id": b.get("id"), "function": {"name": b.get("name"), "arguments": b.get("input")}}
            for b in blocks
            if b.get("type") == "tool_use"
        ]
        return LLMResponse(
            text=text,
            model=data.get("model", model or self.model),
            raw=data,
            tokens_in=usage.get("input_tokens"),
            tokens_out=usage.get("output_tokens"),
            finish_reason=data.get("stop_reason"),
            tool_calls=parse_tool_calls(tool_use),
        )

    def stream(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> Iterator[str]:
        require(self.api_key, "AnthropicProvider needs an api_key or ANTHROPIC_API_KEY")
        body = json.dumps(self._body(messages, model, True, kwargs)).encode()
        for event in _sse(self._client, "/messages", body):
            try:
                chunk = json.loads(event)
            except json.JSONDecodeError:
                continue
            if chunk.get("type") == "content_block_delta":
                text = (chunk.get("delta") or {}).get("text")
                if text:
                    yield text


def _sse(client: ControlPlaneClient, path: str, body: bytes) -> Iterator[str]:
    """Read a ``text/event-stream`` response, yielding raw ``data:`` payloads.

    Streaming needs the response object itself, not the buffered body that
    :meth:`ControlPlaneClient.request` returns, so this opens the connection
    directly using the client's configured TLS context and headers.
    """
    import urllib.request

    headers = {"User-Agent": "keeper-firewall", "Content-Type": "application/json", "Accept": "text/event-stream"}
    headers.update(client.extra_headers)
    if client.api_key:
        headers["Authorization"] = f"Bearer {client.api_key}"
    # client.base_url is validated as http(s) by ControlPlaneClient.
    request = urllib.request.Request(f"{client.base_url}{path}", data=body, headers=headers, method="POST")  # noqa: S310
    with urllib.request.urlopen(request, timeout=client.timeout, context=client._ssl_context) as response:  # noqa: S310
        if response.status >= 400:
            raise KeeperError(f"model provider returned HTTP {response.status}")
        for raw_line in response:
            line = raw_line.decode("utf-8", "replace").strip()
            if line.startswith("data:"):
                yield line[5:].strip()
