"""Observability: audit events, metrics, tracing, redaction.

Co-equal with enforcement, not a byproduct of it. The three exports here cover
the three questions an operator asks: *what happened* (audit events), *how is
it behaving* (metrics), and *where did the time go* (tracing).
"""

from .events import (
    CallbackSink,
    EventBuilder,
    FanoutSink,
    JSONLinesSink,
    MemorySink,
    Sink,
    StreamSink,
    security_relevant,
    to_jsonl,
)
from .metrics import Metrics, Timer
from .redaction import Redactor, replace_spans
from .tracing import (
    SpanHandle,
    Tracer,
    format_traceparent,
    new_span_id,
    new_trace_id,
    parse_traceparent,
)

__all__ = [
    "CallbackSink",
    "EventBuilder",
    "FanoutSink",
    "JSONLinesSink",
    "MemorySink",
    "Metrics",
    "Redactor",
    "Sink",
    "SpanHandle",
    "StreamSink",
    "Timer",
    "Tracer",
    "format_traceparent",
    "new_span_id",
    "new_trace_id",
    "parse_traceparent",
    "replace_spans",
    "security_relevant",
    "to_jsonl",
]
