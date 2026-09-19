"""Model backend adapters.

Keeper does not want to become an LLM SDK. The adapter's only job is to
normalise "send these messages, get text back" and "stream tokens" across
backends so the pipeline has one shape to work with.

Three consequences of that scoping:

* :class:`CallableProvider` is the primary integration for existing code. If
  the application already builds its own OpenAI/Anthropic/Bedrock call, it
  passes a function and keeps every provider-specific parameter it was using.
  Keeper never has to track a provider's API surface.
* The built-in HTTP providers exist so the ten-minute quickstart works without
  a second SDK, and they use the stdlib rather than adding a dependency.
* :meth:`Provider.stream` yields text chunks. Mid-stream enforcement
  (:mod:`keeper_firewall.runtime.stream`) is built on that one primitive, so a
  new backend gets circuit-breaking for free.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator, Sequence
from typing import Any, Protocol

from ..errors import ConfigurationError, KeeperError
from ..types import LLMResponse, Message, ToolCall


class Provider(Protocol):
    """What the pipeline needs from a model backend."""

    name: str

    def complete(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> LLMResponse: ...

    def stream(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> Iterator[str]: ...


class CallableProvider:
    """Wraps an application-supplied function.

    The function receives ``(messages, **kwargs)`` where ``messages`` is a list
    of ``{"role": ..., "content": ...}`` dicts, and returns either a string or
    an :class:`~keeper_firewall.types.LLMResponse`. Anything else raises, rather
    than being coerced — a provider silently stringifying an unexpected object
    is how a response object ends up in an audit log as ``<object at 0x…>``.
    """

    name = "callable"

    def __init__(
        self,
        fn: Callable[..., Any],
        *,
        stream_fn: Callable[..., Iterator[str]] | None = None,
        model: str | None = None,
        name: str | None = None,
    ) -> None:
        self.fn = fn
        self.stream_fn = stream_fn
        self.model = model
        if name:
            self.name = name

    def complete(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> LLMResponse:
        payload = [m.to_dict() for m in messages]
        result = self.fn(payload, **kwargs)
        if isinstance(result, LLMResponse):
            return result
        if isinstance(result, str):
            return LLMResponse(text=result, model=model or self.model or "callable")
        raise KeeperError(
            f"callable provider returned {type(result).__name__}; expected str or LLMResponse"
        )

    def stream(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> Iterator[str]:
        if self.stream_fn is None:
            # Degrade cleanly: one chunk. Mid-stream enforcement still runs,
            # it just has nothing to break early on.
            yield self.complete(messages, model=model, **kwargs).text
            return
        yield from self.stream_fn([m.to_dict() for m in messages], **kwargs)


class EchoProvider:
    """Deterministic fake backend for tests, demos, and the quickstart.

    Lets someone verify their Keeper integration — audit events, metrics,
    dashboard rows — before they have an API key for anything.
    """

    name = "echo"

    def __init__(self, response: str | Callable[[Sequence[Message]], str] | None = None, *, latency_ms: float = 0.0) -> None:
        self.response = response
        self.latency_ms = latency_ms

    def _text(self, messages: Sequence[Message]) -> str:
        if callable(self.response):
            return self.response(messages)
        if isinstance(self.response, str):
            return self.response
        last = next((m.content for m in reversed(messages) if m.role == "user"), "")
        return f"echo: {last}"

    def complete(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> LLMResponse:
        if self.latency_ms:
            time.sleep(self.latency_ms / 1000)
        text = self._text(messages)
        return LLMResponse(
            text=text,
            model=model or "echo-1",
            tokens_in=sum(len(m.content.split()) for m in messages),
            tokens_out=len(text.split()),
            finish_reason="stop",
        )

    def stream(self, messages: Sequence[Message], *, model: str | None = None, **kwargs: Any) -> Iterator[str]:
        text = self._text(messages)
        for i in range(0, len(text), 16):
            if self.latency_ms:
                time.sleep(self.latency_ms / 1000 / max(1, len(text) // 16))
            yield text[i : i + 16]


def parse_tool_calls(raw: Any) -> tuple[ToolCall, ...]:
    """Normalise provider-specific tool-call payloads into :class:`ToolCall`."""
    if not raw:
        return ()
    calls: list[ToolCall] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        # OpenAI shape: {"function": {"name":…, "arguments": "<json>"}}
        fn = item.get("function") or item
        name = fn.get("name")
        if not name:
            continue
        args = fn.get("arguments") or fn.get("input") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError:
                args = {"_raw": args}
        calls.append(ToolCall(name=str(name), arguments=args, call_id=str(item.get("id") or "")))
    return tuple(calls)


def require(value: Any, message: str) -> Any:
    if not value:
        raise ConfigurationError(message)
    return value
