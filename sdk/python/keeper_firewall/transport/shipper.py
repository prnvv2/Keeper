"""Asynchronous telemetry shipping.

The single hardest non-functional requirement in ``docs/architecture.md``: the
control plane must never be a synchronous dependency of the request path. An
AI firewall that adds the control plane's availability to every LLM call has
made the application strictly less reliable than it was before.

So shipping is a bounded queue drained by a background thread:

* :meth:`TelemetryShipper.emit` is non-blocking and never raises. Worst case it
  drops an event and increments a counter.
* The queue is bounded. When it fills, low-severity events are dropped first;
  BLOCK/CHALLENGE/HIGH+ events displace them. An audit trail that loses the
  block records under load is worse than useless.
* Failed batches retry with exponential backoff and jitter, then are dropped
  rather than retried forever — unbounded retry against a struggling control
  plane is how a degraded service becomes an outage.
* ``flush()`` and ``close()`` are synchronous and are wired to ``atexit``, so a
  short-lived process still delivers its audit trail.
"""

from __future__ import annotations

import atexit
import random
import threading
import time
from collections import deque
from typing import Callable

from ..config import TelemetryConfig
from ..errors import TransportError
from ..observability.events import security_relevant
from ..observability.metrics import Metrics
from ..types import AuditEvent
from .client import ControlPlaneClient


class TelemetryShipper:
    """Batches audit events and ships them to the control plane."""

    def __init__(
        self,
        config: TelemetryConfig,
        *,
        instance_id: str,
        metrics: Metrics | None = None,
        client: ControlPlaneClient | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self.config = config
        self.instance_id = instance_id
        self.metrics = metrics
        self.on_error = on_error
        self.client = client or (
            ControlPlaneClient(
                config.endpoint,
                api_key=config.api_key,
                timeout_ms=config.timeout_ms,
            )
            if config.endpoint
            else None
        )

        self._queue: deque[AuditEvent] = deque()
        self._lock = threading.Lock()
        self._wake = threading.Event()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._dropped = 0
        self._shipped = 0
        self._failed_batches = 0
        self._last_error: str | None = None
        self._last_success_ms: int | None = None

        if self.enabled:
            self._start()

    @property
    def enabled(self) -> bool:
        return bool(self.config.enabled and self.client is not None)

    def _start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="keeper-telemetry", daemon=True)
        self._thread.start()
        atexit.register(self.close)

    # -- producer side -----------------------------------------------------

    def emit(self, event: AuditEvent) -> None:
        """Queue an event. Never blocks, never raises."""
        if not self.enabled:
            return
        with self._lock:
            if len(self._queue) >= self.config.queue_capacity:
                if not self._make_room(event):
                    self._dropped += 1
                    self._count_drop("queue_full")
                    return
            self._queue.append(event)
            depth = len(self._queue)
        if self.metrics:
            self.metrics.gauge("telemetry_queue_depth", depth)
        if depth >= self.config.batch_size:
            self._wake.set()

    def _make_room(self, incoming: AuditEvent) -> bool:
        """Evict a droppable event to make room. Caller holds the lock.

        Only ALLOW-path events are droppable. If the queue is entirely
        security-relevant we refuse the incoming event unless it is itself
        security-relevant, in which case we drop the oldest anyway and record
        it: losing the *oldest* block is marginally better than losing the
        newest, and either way the drop counter fires an alert.
        """
        for i, queued in enumerate(self._queue):
            if not security_relevant(queued):
                del self._queue[i]
                self._dropped += 1
                self._count_drop("evicted_low_severity")
                return True
        if security_relevant(incoming):
            self._queue.popleft()
            self._dropped += 1
            self._count_drop("evicted_security_event")
            return True
        return False

    def _count_drop(self, reason: str) -> None:
        if self.metrics:
            self.metrics.inc("telemetry_dropped_total", reason=reason)

    # -- consumer side -----------------------------------------------------

    def _run(self) -> None:
        interval = self.config.flush_interval_ms / 1000
        while not self._stop.is_set():
            self._wake.wait(timeout=interval)
            self._wake.clear()
            self._drain()
        self._drain()

    def _drain(self) -> None:
        while True:
            batch = self._take_batch()
            if not batch:
                return
            self._send(batch)

    def _take_batch(self) -> list[AuditEvent]:
        with self._lock:
            n = min(self.config.batch_size, len(self._queue))
            batch = [self._queue.popleft() for _ in range(n)]
            depth = len(self._queue)
        if self.metrics and batch:
            self.metrics.gauge("telemetry_queue_depth", depth)
        return batch

    def _send(self, batch: list[AuditEvent]) -> None:
        assert self.client is not None
        payload = [e.to_dict() for e in batch]
        delay = 0.25
        for attempt in range(self.config.max_retries + 1):
            try:
                response = self.client.ship_events(payload, self.instance_id)
                if response.ok:
                    self._shipped += len(batch)
                    self._last_success_ms = int(time.time() * 1000)
                    if self.metrics:
                        self.metrics.inc("telemetry_events_total", len(batch), outcome="shipped")
                    return
                if 400 <= response.status < 500 and response.status not in (408, 429):
                    # A rejected batch will be rejected again: schema mismatch,
                    # bad credentials. Retrying is pure noise.
                    self._fail(f"control plane rejected batch: HTTP {response.status}", batch, "rejected")
                    return
                last = f"HTTP {response.status}"
            except TransportError as exc:
                last = str(exc)
            except Exception as exc:  # noqa: BLE001 - shipper must never crash the app
                last = repr(exc)

            self._last_error = last
            if attempt < self.config.max_retries:
                time.sleep(delay + random.random() * delay)
                delay = min(delay * 2, 8.0)

        self._fail(f"giving up after {self.config.max_retries} retries: {self._last_error}", batch, "unreachable")

    def _fail(self, message: str, batch: list[AuditEvent], reason: str) -> None:
        self._failed_batches += 1
        self._last_error = message
        self._dropped += len(batch)
        if self.metrics:
            self.metrics.inc("telemetry_dropped_total", len(batch), reason=reason)
        if self.on_error:
            try:
                self.on_error(TransportError(message))
            except Exception:  # noqa: BLE001
                pass

    # -- lifecycle ---------------------------------------------------------

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Block until the queue drains or ``timeout_s`` elapses."""
        if not self.enabled:
            return True
        deadline = time.monotonic() + timeout_s
        self._wake.set()
        while time.monotonic() < deadline:
            with self._lock:
                if not self._queue:
                    return True
            time.sleep(0.02)
            self._wake.set()
        with self._lock:
            return not self._queue

    def close(self) -> None:
        if self._stop.is_set():
            return
        self.flush(timeout_s=self.config.timeout_ms / 1000)
        self._stop.set()
        self._wake.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=2.0)

    # -- self-observability ------------------------------------------------

    def health(self) -> dict[str, object]:
        """Shipper health, surfaced on the SDK's own health endpoint."""
        with self._lock:
            depth = len(self._queue)
        return {
            "enabled": self.enabled,
            "endpoint": self.config.endpoint,
            "queue_depth": depth,
            "queue_capacity": self.config.queue_capacity,
            "shipped": self._shipped,
            "dropped": self._dropped,
            "failed_batches": self._failed_batches,
            "last_error": self._last_error,
            "last_success_ms": self._last_success_ms,
            "healthy": self._failed_batches == 0 or self._last_success_ms is not None,
        }
