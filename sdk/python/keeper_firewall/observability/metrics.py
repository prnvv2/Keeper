"""Prometheus-compatible metrics for the SDK.

The SDK must be observable as *infrastructure*, not only as a security tool: an
ops team should be able to alert on Keeper's own error rate and p95 overhead
the same way they alert on their database driver.

Two backends:

* If ``prometheus_client`` is installed, metrics are registered in the process's
  default registry, so they appear on whatever ``/metrics`` endpoint the host
  application already exposes. Nothing extra to wire up.
* Otherwise a small built-in registry collects the same series and renders
  them in the Prometheus text exposition format. This keeps
  ``prometheus_client`` an optional dependency rather than something we force
  into every user's dependency tree.

Cardinality is controlled deliberately. Labels are bounded sets (stage, action,
detector, severity, provider); ``principal_id``, ``correlation_id`` and model
names supplied by callers never become labels — those belong in the audit
trail, which is built to be high cardinality, not in a time series.
"""

from __future__ import annotations

import math
import threading
import time
from typing import Any, Iterable, Mapping, Sequence

from ..config import MetricsConfig

try:  # pragma: no cover - depends on the host environment
    import prometheus_client as _prom
except ImportError:  # pragma: no cover
    _prom = None

#: Process-global cache of prometheus_client collectors, keyed by metric name.
#: See :meth:`Metrics._register`.
_PROM_CACHE: dict[str, Any] = {}


# ---------------------------------------------------------------------------
# Built-in fallback registry
# ---------------------------------------------------------------------------


class _Series:
    __slots__ = ("name", "help", "type", "labelnames", "values", "buckets", "lock")

    def __init__(self, name: str, help_: str, type_: str, labelnames: Sequence[str], buckets: Sequence[float] = ()):
        self.name = name
        self.help = help_
        self.type = type_
        self.labelnames = tuple(labelnames)
        self.buckets = tuple(buckets)
        self.values: dict[tuple[str, ...], Any] = {}
        self.lock = threading.Lock()

    def _key(self, labels: Mapping[str, str]) -> tuple[str, ...]:
        return tuple(str(labels.get(name, "")) for name in self.labelnames)

    def inc(self, labels: Mapping[str, str], amount: float = 1.0) -> None:
        key = self._key(labels)
        with self.lock:
            self.values[key] = self.values.get(key, 0.0) + amount

    def set(self, labels: Mapping[str, str], value: float) -> None:
        with self.lock:
            self.values[self._key(labels)] = value

    def observe(self, labels: Mapping[str, str], value: float) -> None:
        key = self._key(labels)
        with self.lock:
            state = self.values.get(key)
            if state is None:
                state = {"sum": 0.0, "count": 0, "buckets": [0] * len(self.buckets)}
                self.values[key] = state
            state["sum"] += value
            state["count"] += 1
            for i, bound in enumerate(self.buckets):
                if value <= bound:
                    state["buckets"][i] += 1

    def render(self) -> list[str]:
        lines = [f"# HELP {self.name} {self.help}", f"# TYPE {self.name} {self.type}"]
        with self.lock:
            snapshot = dict(self.values)
        for key, value in sorted(snapshot.items()):
            labels = dict(zip(self.labelnames, key))
            if self.type == "histogram":
                cumulative = 0
                for bound, count in zip(self.buckets, value["buckets"]):
                    cumulative += count
                    lines.append(f"{self.name}_bucket{_fmt({**labels, 'le': _fmt_float(bound)})} {cumulative}")
                lines.append(f"{self.name}_bucket{_fmt({**labels, 'le': '+Inf'})} {value['count']}")
                lines.append(f"{self.name}_sum{_fmt(labels)} {value['sum']}")
                lines.append(f"{self.name}_count{_fmt(labels)} {value['count']}")
            else:
                lines.append(f"{self.name}{_fmt(labels)} {value}")
        return lines


def _fmt(labels: Mapping[str, str]) -> str:
    if not labels:
        return ""
    inner = ",".join(
        f'{k}="{str(v).replace(chr(92), chr(92) * 2)}"' for k, v in sorted(labels.items()) if v != ""
    )
    return "{" + inner + "}" if inner else ""


def _fmt_float(value: float) -> str:
    if math.isinf(value):
        return "+Inf"
    return repr(int(value)) if float(value).is_integer() else repr(value)


# ---------------------------------------------------------------------------
# Public metrics facade
# ---------------------------------------------------------------------------


class Metrics:
    """The SDK's metric surface. One instance per :class:`Keeper`."""

    def __init__(self, config: MetricsConfig | None = None, application: str = "unknown") -> None:
        self.config = config or MetricsConfig()
        self.application = application
        self._ns = self.config.namespace
        self._own: dict[str, _Series] = {}
        self._prom: dict[str, Any] = {}
        self._server_started = False
        if self.config.enabled:
            self._define()

    # -- definition --------------------------------------------------------

    def _define(self) -> None:
        buckets = self.config.latency_buckets_ms
        self._counter("requests_total", "AI requests processed by the firewall.", ("stage", "action", "application"))
        self._counter("detector_runs_total", "Detector executions.", ("detector", "stage", "outcome", "application"))
        self._counter("detector_hits_total", "Detector detections.", ("detector", "severity", "action", "application"))
        self._counter("detector_errors_total", "Detector failures.", ("detector", "fail_mode", "application"))
        self._counter("policy_evaluations_total", "Policy evaluations.", ("policy_id", "action", "application"))
        self._counter("blocked_total", "Interactions blocked.", ("stage", "category", "application"))
        self._counter("access_denied_total", "Access control rejections.", ("reason", "application"))
        self._counter("telemetry_events_total", "Audit events emitted.", ("outcome", "application"))
        self._counter("telemetry_dropped_total", "Audit events dropped.", ("reason", "application"))
        self._histogram("pipeline_latency_ms", "Firewall overhead per stage.", ("stage", "application"), buckets)
        self._histogram("detector_latency_ms", "Per-detector latency.", ("detector", "application"), buckets)
        self._histogram("policy_latency_ms", "Policy evaluation latency.", ("policy_id", "application"), buckets)
        self._histogram("model_latency_ms", "Upstream model latency.", ("provider", "application"),
                        (10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000))
        self._gauge("telemetry_queue_depth", "Pending audit events.", ("application",))
        self._gauge("policy_age_seconds", "Age of the active policy bundle.", ("policy_id", "application"))
        self._gauge("info", "Build and configuration info.", ("application", "sdk_version", "environment"))

    def _name(self, name: str) -> str:
        return f"{self._ns}_{name}"

    def _register(self, name: str, factory: Callable[[], Any]) -> None:
        """Create a prometheus_client collector, or reuse the existing one.

        The default registry is process-global, so a second :class:`Keeper` in
        the same process (two apps in one worker, or a test suite) would
        otherwise raise ``DuplicateTimeseries``. Sharing the collector is the
        correct outcome anyway: every series is labelled by ``application``, so
        two instances write to distinct label sets of one metric family.
        """
        full = self._name(name)
        existing = _PROM_CACHE.get(full)
        if existing is None:
            existing = factory()
            _PROM_CACHE[full] = existing
        self._prom[name] = existing

    def _counter(self, name: str, help_: str, labels: Sequence[str]) -> None:
        if _prom is not None:
            self._register(name, lambda: _prom.Counter(self._name(name), help_, labels))
        else:
            self._own[name] = _Series(self._name(name), help_, "counter", labels)

    def _gauge(self, name: str, help_: str, labels: Sequence[str]) -> None:
        if _prom is not None:
            self._register(name, lambda: _prom.Gauge(self._name(name), help_, labels))
        else:
            self._own[name] = _Series(self._name(name), help_, "gauge", labels)

    def _histogram(self, name: str, help_: str, labels: Sequence[str], buckets: Sequence[float]) -> None:
        if _prom is not None:
            self._register(
                name,
                lambda: _prom.Histogram(
                    self._name(name), help_, labels, buckets=tuple(buckets) + (float("inf"),)
                ),
            )
        else:
            self._own[name] = _Series(self._name(name), help_, "histogram", labels, buckets)

    # -- recording ---------------------------------------------------------

    def inc(self, name: str, amount: float = 1.0, **labels: str) -> None:
        if not self.config.enabled:
            return
        labels.setdefault("application", self.application)
        if _prom is not None:
            metric = self._prom.get(name)
            if metric is not None:
                metric.labels(**{k: labels.get(k, "") for k in metric._labelnames}).inc(amount)
        else:
            series = self._own.get(name)
            if series is not None:
                series.inc(labels, amount)

    def observe(self, name: str, value: float, **labels: str) -> None:
        if not self.config.enabled:
            return
        labels.setdefault("application", self.application)
        if _prom is not None:
            metric = self._prom.get(name)
            if metric is not None:
                metric.labels(**{k: labels.get(k, "") for k in metric._labelnames}).observe(value)
        else:
            series = self._own.get(name)
            if series is not None:
                series.observe(labels, value)

    def gauge(self, name: str, value: float, **labels: str) -> None:
        if not self.config.enabled:
            return
        labels.setdefault("application", self.application)
        if _prom is not None:
            metric = self._prom.get(name)
            if metric is not None:
                metric.labels(**{k: labels.get(k, "") for k in metric._labelnames}).set(value)
        else:
            series = self._own.get(name)
            if series is not None:
                series.set(labels, value)

    # -- exposition --------------------------------------------------------

    def render(self) -> str:
        """Prometheus text exposition for the built-in registry.

        When ``prometheus_client`` is present this delegates to it, so the
        output is identical whichever backend is active.
        """
        if _prom is not None:  # pragma: no cover - depends on environment
            return _prom.generate_latest().decode()
        lines: list[str] = []
        for series in self._own.values():
            lines.extend(series.render())
        return "\n".join(lines) + "\n"

    def start_http_server(self, port: int | None = None) -> None:
        """Expose ``/metrics`` from inside the SDK process.

        Only for applications that do not already serve metrics. Most should
        leave ``metrics.port`` unset and let the host app expose the registry.
        """
        port = port or self.config.port
        if port is None or self._server_started:
            return
        if _prom is not None:  # pragma: no cover - depends on environment
            _prom.start_http_server(port)
        else:
            from http.server import BaseHTTPRequestHandler, HTTPServer

            metrics = self

            class Handler(BaseHTTPRequestHandler):
                def do_GET(self) -> None:  # noqa: N802 - stdlib API
                    if self.path.rstrip("/") not in ("/metrics", ""):
                        self.send_response(404)
                        self.end_headers()
                        return
                    body = metrics.render().encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; version=0.0.4")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args: Any) -> None:  # silence stdlib logging
                    return

            server = HTTPServer(("0.0.0.0", port), Handler)
            thread = threading.Thread(target=server.serve_forever, name="keeper-metrics", daemon=True)
            thread.start()
        self._server_started = True


class Timer:
    """Context manager recording elapsed milliseconds into a histogram."""

    __slots__ = ("metrics", "name", "labels", "start", "elapsed_ms")

    def __init__(self, metrics: Metrics, name: str, **labels: str) -> None:
        self.metrics = metrics
        self.name = name
        self.labels = labels
        self.start = 0.0
        self.elapsed_ms = 0.0

    def __enter__(self) -> "Timer":
        self.start = time.perf_counter()
        return self

    def __exit__(self, *exc: object) -> None:
        self.elapsed_ms = (time.perf_counter() - self.start) * 1000
        self.metrics.observe(self.name, self.elapsed_ms, **self.labels)


def bounded(values: Iterable[str], allowed: frozenset[str], fallback: str = "other") -> list[str]:
    """Clamp a label value to a known set, protecting metric cardinality."""
    return [v if v in allowed else fallback for v in values]
