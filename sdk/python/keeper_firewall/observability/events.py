"""Audit event construction and local sinks.

Every enforcement decision becomes exactly one :class:`AuditEvent`. Building it
is separated from shipping it (:mod:`keeper_firewall.transport.shipper`) so
that the local audit trail keeps working when the control plane does not —
which is the whole point of the fail-safe design in ``docs/architecture.md``.

Local sinks are synchronous and cheap. Remote shipping is asynchronous and
best-effort. An event is never lost silently: a drop increments
``keeper_telemetry_dropped_total`` with a reason label, so "we stopped seeing
audit events" is itself an alertable condition.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from typing import Any, Callable, Iterable, Protocol, Sequence

from ..types import (
    Action,
    AuditEvent,
    Decision,
    RequestContext,
    Severity,
    Stage,
    new_id,
    now_ms,
)
from .redaction import Redactor


class Sink(Protocol):
    """Anywhere an audit event can be written."""

    def emit(self, event: AuditEvent) -> None: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class EventBuilder:
    """Turns a :class:`Decision` into a redacted, shippable audit event."""

    def __init__(
        self,
        redactor: Redactor,
        *,
        instance_id: str = "",
        policy_version: str | None = None,
    ) -> None:
        self.redactor = redactor
        self.instance_id = instance_id
        self.policy_version = policy_version

    def build(
        self,
        decision: Decision,
        context: RequestContext,
        *,
        prompt: str | None = None,
        response: str | None = None,
        latency_ms: float = 0.0,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
        error: str | None = None,
        extra_tags: dict[str, Any] | None = None,
    ) -> AuditEvent:
        prompt_out, prompt_labels = self.redactor.apply(prompt, decision.findings, kind="prompt")
        response_out, response_labels = self.redactor.apply(response, decision.findings, kind="response")

        tags = dict(context.tags)
        if extra_tags:
            tags.update(extra_tags)
        if decision.fail_mode_engaged:
            tags["fail_mode_engaged"] = decision.fail_mode_engaged
        if self.redactor.config.hash_payloads and prompt:
            tags["prompt_sha256"] = self.redactor.digest(prompt)
        if self.redactor.config.hash_payloads and response:
            tags["response_sha256"] = self.redactor.digest(response)

        return AuditEvent(
            event_id=new_id("evt_"),
            correlation_id=decision.correlation_id or context.correlation_id,
            timestamp_ms=now_ms(),
            stage=decision.stage,
            action=decision.action,
            severity=decision.severity,
            application=context.application,
            environment=context.environment,
            instance_id=self.instance_id,
            session_id=context.session_id,
            principal_id=context.principal.id,
            principal_roles=tuple(context.principal.roles),
            tenant=context.principal.tenant,
            model=context.model,
            provider=context.provider,
            trace_id=context.trace_id,
            span_id=context.span_id,
            policy_version=self.policy_version,
            findings=decision.findings,
            policy_traces=decision.policy_traces,
            prompt=prompt_out,
            response=response_out,
            redacted_fields=tuple(dict.fromkeys(prompt_labels + response_labels)),
            latency_ms=latency_ms,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            error=error,
            tags=tags,
            threats=decision.threats,
            risk=decision.risk.to_dict() if decision.risk is not None else None,
        )


class JSONLinesSink:
    """Append-only newline-delimited JSON, the SIEM-friendliest local format.

    Deliberately not using :mod:`logging`: audit records must not inherit the
    host application's log level, formatters, or filters. An operator turning
    their app to WARNING should not silently disable the audit trail.
    """

    def __init__(self, path: str, *, max_bytes: int = 100 * 1024 * 1024, backups: int = 3) -> None:
        self.path = path
        self.max_bytes = max_bytes
        self.backups = backups
        self._lock = threading.Lock()
        directory = os.path.dirname(os.path.abspath(path))
        if directory:
            os.makedirs(directory, exist_ok=True)
        self._fh = open(path, "a", encoding="utf-8")

    def emit(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"), default=str)
        with self._lock:
            self._fh.write(line + "\n")
            self._fh.flush()
            if self.max_bytes and self._fh.tell() > self.max_bytes:
                self._rotate()

    def _rotate(self) -> None:
        self._fh.close()
        for i in range(self.backups - 1, 0, -1):
            src, dst = f"{self.path}.{i}", f"{self.path}.{i + 1}"
            if os.path.exists(src):
                os.replace(src, dst)
        os.replace(self.path, f"{self.path}.1")
        self._fh = open(self.path, "a", encoding="utf-8")

    def flush(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.flush()

    def close(self) -> None:
        with self._lock:
            if not self._fh.closed:
                self._fh.close()


class StreamSink:
    """Writes audit events as JSON lines to a stream (stdout by default)."""

    def __init__(self, stream: Any = None) -> None:
        self.stream = stream or sys.stdout
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        line = json.dumps(event.to_dict(), separators=(",", ":"), default=str)
        with self._lock:
            self.stream.write(line + "\n")

    def flush(self) -> None:
        with self._lock:
            if hasattr(self.stream, "flush"):
                self.stream.flush()

    def close(self) -> None:
        self.flush()


class MemorySink:
    """Keeps the last N events in memory. For tests and local debugging."""

    def __init__(self, capacity: int = 1000) -> None:
        self.capacity = capacity
        self.events: list[AuditEvent] = []
        self._lock = threading.Lock()

    def emit(self, event: AuditEvent) -> None:
        with self._lock:
            self.events.append(event)
            if len(self.events) > self.capacity:
                del self.events[: len(self.events) - self.capacity]

    def by_stage(self, stage: Stage) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self.events if e.stage is stage]

    def blocked(self) -> list[AuditEvent]:
        with self._lock:
            return [e for e in self.events if e.action is Action.BLOCK]

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class CallbackSink:
    """Hands each event to a caller-supplied function.

    The escape hatch for applications that already have an audit pipeline and
    want Keeper's events inside it rather than beside it. Exceptions from the
    callback are swallowed: a broken listener must not break the request.
    """

    def __init__(self, callback: Callable[[AuditEvent], None], on_error: Callable[[BaseException], None] | None = None) -> None:
        self.callback = callback
        self.on_error = on_error

    def emit(self, event: AuditEvent) -> None:
        try:
            self.callback(event)
        except Exception as exc:  # noqa: BLE001 - listener must not break the request
            if self.on_error:
                self.on_error(exc)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class FanoutSink:
    """Writes each event to several sinks; one failing does not stop the rest."""

    def __init__(self, sinks: Sequence[Sink] = ()) -> None:
        self.sinks: list[Sink] = list(sinks)

    def add(self, sink: Sink) -> None:
        self.sinks.append(sink)

    def emit(self, event: AuditEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception:  # noqa: BLE001 - a broken sink must not break the request
                continue

    def flush(self) -> None:
        for sink in self.sinks:
            try:
                sink.flush()
            except Exception:  # noqa: BLE001
                continue

    def close(self) -> None:
        for sink in self.sinks:
            try:
                sink.close()
            except Exception:  # noqa: BLE001
                continue


def security_relevant(event: AuditEvent) -> bool:
    """Events that must never be dropped or sampled away.

    A block, a challenge, or anything at HIGH severity or above is the reason
    the system exists. Volume-driven shedding applies to the ALLOW stream only.
    """
    return (
        event.action in (Action.BLOCK, Action.CHALLENGE)
        or event.severity.rank() >= Severity.HIGH.rank()
        or event.error is not None
    )


def to_jsonl(events: Iterable[AuditEvent]) -> str:
    return "\n".join(json.dumps(e.to_dict(), separators=(",", ":"), default=str) for e in events)
