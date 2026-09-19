"""Distributed tracing.

OpenTelemetry is the right default: it is the only telemetry standard the AI
tooling ecosystem has actually converged on, and a Keeper span nested inside
the application's existing trace is what lets an engineer see "this request
spent 340ms in the model and 6ms in the firewall" without correlating two
systems by hand.

But ``opentelemetry-sdk`` is a heavy dependency to force on every application
that installs an AI firewall, so it is optional. Without it, this module still
produces and propagates W3C ``traceparent`` values, so audit events carry
trace/span ids that line up with whatever the application's real tracer emits.
Tracing degrades to "correlatable ids", never to nothing.
"""

from __future__ import annotations

import contextlib
import os
import random
from collections.abc import Iterator, Mapping
from typing import Any

try:  # pragma: no cover - depends on the host environment
    from opentelemetry import trace as _otel_trace
    from opentelemetry.trace import SpanKind as _SpanKind
except ImportError:  # pragma: no cover
    _otel_trace = None
    _SpanKind = None

TRACEPARENT = "traceparent"
_VERSION = "00"


def _rand_hex(nbytes: int) -> str:
    return os.urandom(nbytes).hex()


def new_trace_id() -> str:
    return _rand_hex(16)


def new_span_id() -> str:
    return _rand_hex(8)


def format_traceparent(trace_id: str, span_id: str, sampled: bool = True) -> str:
    return f"{_VERSION}-{trace_id}-{span_id}-{'01' if sampled else '00'}"


def parse_traceparent(value: str | None) -> tuple[str | None, str | None]:
    """Parse a W3C traceparent header into ``(trace_id, span_id)``."""
    if not value:
        return None, None
    parts = value.strip().split("-")
    if len(parts) != 4 or len(parts[1]) != 32 or len(parts[2]) != 16:
        return None, None
    if parts[1] == "0" * 32 or parts[2] == "0" * 16:
        return None, None
    return parts[1], parts[2]


class Tracer:
    """Thin tracing facade with an OpenTelemetry backend when available."""

    def __init__(self, enabled: bool = True, service_name: str = "keeper-sdk") -> None:
        self.service_name = service_name
        self.otel_available = _otel_trace is not None
        self.enabled = enabled
        self._tracer = _otel_trace.get_tracer(service_name) if (enabled and self.otel_available) else None

    @contextlib.contextmanager
    def span(self, name: str, **attributes: Any) -> Iterator[SpanHandle]:
        """Start a span. Always yields a handle, with or without OTel."""
        if self._tracer is None:
            handle = SpanHandle(new_trace_id(), new_span_id())
            yield handle
            return
        with self._tracer.start_as_current_span(  # pragma: no cover - env dependent
            name, kind=_SpanKind.INTERNAL
        ) as otel_span:
            ctx = otel_span.get_span_context()
            handle = SpanHandle(
                format(ctx.trace_id, "032x"), format(ctx.span_id, "016x"), otel_span
            )
            for key, value in attributes.items():
                handle.set(key, value)
            yield handle

    def current_ids(self) -> tuple[str | None, str | None]:
        """Trace and span id of the application's *current* span, if any."""
        if self._tracer is None or _otel_trace is None:
            return None, None
        ctx = _otel_trace.get_current_span().get_span_context()  # pragma: no cover
        if not ctx.is_valid:
            return None, None
        return format(ctx.trace_id, "032x"), format(ctx.span_id, "016x")


class SpanHandle:
    """A span you can attach attributes and events to, OTel or not."""

    __slots__ = ("_otel", "attributes", "events", "span_id", "trace_id")

    def __init__(self, trace_id: str, span_id: str, otel_span: Any = None) -> None:
        self.trace_id = trace_id
        self.span_id = span_id
        self._otel = otel_span
        self.attributes: dict[str, Any] = {}
        self.events: list[tuple[str, Mapping[str, Any]]] = []

    def set(self, key: str, value: Any) -> None:
        self.attributes[key] = value
        if self._otel is not None:  # pragma: no cover - env dependent
            if isinstance(value, (str, bool, int, float)):
                self._otel.set_attribute(key, value)
            else:
                self._otel.set_attribute(key, str(value))

    def event(self, name: str, **attributes: Any) -> None:
        self.events.append((name, attributes))
        if self._otel is not None:  # pragma: no cover - env dependent
            self._otel.add_event(name, {k: str(v) for k, v in attributes.items()})

    def traceparent(self) -> str:
        return format_traceparent(self.trace_id, self.span_id)


def sampled(rate: float) -> bool:
    """Head sampling decision. Security events bypass this — they are always kept."""
    return rate >= 1.0 or random.random() < rate  # noqa: S311 - trace sampling, not security
