"""SIEM export.

The organisation's SIEM is almost certainly the system of record; Keeper's
dashboard is a purpose-built *view*, not a silo. So the audit trail has to
leave in formats the existing SOC already ingests, in near real time.

Three targets ship in v1, chosen by what people actually run:

``webhook``
    JSON POST, newline-delimited. Every SIEM on earth has an HTTP collector
    (Splunk HEC, Elastic, Datadog, Sentinel via Logic App), and this is the one
    that works without us implementing a vendor SDK. **Built first**, because
    it unblocks every destination at once.

``syslog`` (CEF)
    RFC 5424 syslog carrying ArcSight CEF. Still the lingua franca for
    on-prem SIEM and for anything routed through a syslog relay. The mapping
    from audit event to CEF fields is the fiddly part and is done properly
    below, including the escaping rules people usually get wrong.

``otlp``
    OpenTelemetry logs over HTTP/protobuf-JSON. The forward-looking option and
    the one that lines up with the SDK's own tracing, so a security event and
    the trace it came from land in the same backend.

Delivery is at-least-once with a checkpoint, not exactly-once. Events carry a
stable ``event_id``, so the receiving SIEM can deduplicate; promising
exactly-once over an HTTP sink we do not control would be a lie.
"""

from __future__ import annotations

import json
import logging
import socket
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

log = logging.getLogger("keeper.siem")

#: Audit action -> CEF severity (0-10).
CEF_SEVERITY = {"allow": 1, "flag": 4, "redact": 4, "challenge": 7, "block": 8}
SEVERITY_TO_CEF = {"info": 1, "low": 3, "medium": 5, "high": 8, "critical": 10}
#: Syslog priority: facility 13 (log audit) * 8 + severity.
SYSLOG_FACILITY = 13


class SIEMExporter(Protocol):
    name: str

    def export(self, events: Sequence[Mapping[str, Any]]) -> int: ...

    def close(self) -> None: ...


def _clean(event: Mapping[str, Any]) -> dict[str, Any]:
    """Normalise a stored row into the shape exporters emit."""
    return {
        "event_id": event.get("event_id"),
        "correlation_id": event.get("correlation_id"),
        "timestamp_ms": event.get("timestamp_ms"),
        "stage": event.get("stage"),
        "action": event.get("action"),
        "severity": event.get("severity"),
        "application": event.get("application"),
        "environment": event.get("environment"),
        "instance_id": event.get("instance_id"),
        "principal_id": event.get("principal_id"),
        "tenant": event.get("tenant"),
        "model": event.get("model"),
        "provider": event.get("provider"),
        "trace_id": event.get("trace_id"),
        "policy_version": event.get("policy_version"),
        "detectors_fired": event.get("detectors_fired") or [],
        "categories": event.get("categories") or [],
        "findings": event.get("findings") or [],
        "latency_ms": event.get("latency_ms"),
        "prompt": event.get("prompt"),
        "response": event.get("response"),
        "tags": event.get("tags") or {},
        "threats": event.get("threats") or [],
        "risk_score": event.get("risk_score") or 0,
        "risk_band": event.get("risk_band") or "none",
    }


class WebhookExporter:
    """Newline-delimited JSON over HTTPS."""

    name = "webhook"

    def __init__(self, url: str, *, headers: Mapping[str, str] | None = None, timeout_s: float = 10.0) -> None:
        self.url = url
        self.headers = {"Content-Type": "application/x-ndjson", **(headers or {})}
        self._client = httpx.Client(timeout=timeout_s)

    def export(self, events: Sequence[Mapping[str, Any]]) -> int:
        if not events:
            return 0
        body = "\n".join(json.dumps(_clean(e), separators=(",", ":"), default=str) for e in events)
        response = self._client.post(self.url, content=body.encode(), headers=self.headers)
        response.raise_for_status()
        return len(events)

    def close(self) -> None:
        self._client.close()


class CEFExporter:
    """RFC 5424 syslog carrying ArcSight CEF records."""

    name = "syslog"

    VENDOR = "Keeper"
    PRODUCT = "AI Firewall"
    VERSION = "1.0"

    def __init__(self, host: str, port: int = 514, *, protocol: str = "udp", timeout_s: float = 5.0) -> None:
        self.host = host
        self.port = port
        self.protocol = protocol
        self.timeout_s = timeout_s
        self._sock: socket.socket | None = None

    def _socket(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.protocol == "tcp":
            sock = socket.create_connection((self.host, self.port), timeout=self.timeout_s)
        else:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout_s)
        self._sock = sock
        return sock

    def export(self, events: Sequence[Mapping[str, Any]]) -> int:
        sock = self._socket()
        sent = 0
        for event in events:
            line = self.format_syslog(event).encode("utf-8", "replace")
            try:
                if self.protocol == "tcp":
                    sock.sendall(line + b"\n")
                else:
                    sock.sendto(line, (self.host, self.port))
                sent += 1
            except OSError:
                # Reconnect once; a dropped TCP session should not lose the
                # rest of the batch.
                self._sock = None
                sock = self._socket()
                if self.protocol == "tcp":
                    sock.sendall(line + b"\n")
                else:
                    sock.sendto(line, (self.host, self.port))
                sent += 1
        return sent

    def format_syslog(self, event: Mapping[str, Any]) -> str:
        severity = min(7, max(0, 7 - SEVERITY_TO_CEF.get(event.get("severity", "info"), 1) // 2))
        priority = SYSLOG_FACILITY * 8 + severity
        timestamp = time.strftime(
            "%Y-%m-%dT%H:%M:%S", time.gmtime((event.get("timestamp_ms") or 0) / 1000)
        ) + "Z"
        host = event.get("application") or "keeper"
        return f"<{priority}>1 {timestamp} {host} keeper - - - {self.format_cef(event)}"

    def format_cef(self, event: Mapping[str, Any]) -> str:
        findings = [f for f in (event.get("findings") or []) if f.get("detected")]
        name = findings[0].get("summary") if findings else f"{event.get('action')} at {event.get('stage')}"
        signature = findings[0].get("category") if findings else f"keeper.{event.get('stage')}"
        severity = max(
            CEF_SEVERITY.get(event.get("action", "allow"), 1),
            SEVERITY_TO_CEF.get(event.get("severity", "info"), 1),
        )
        header = "|".join(
            _cef_escape_header(part)
            for part in (
                "CEF:0", self.VENDOR, self.PRODUCT, self.VERSION,
                str(signature), str(name)[:200], str(severity),
            )
        )
        extension = {
            "rt": event.get("timestamp_ms"),
            "externalId": event.get("event_id"),
            "cs1Label": "correlationId",
            "cs1": event.get("correlation_id"),
            "cs2Label": "detectors",
            "cs2": ",".join(event.get("detectors_fired") or []),
            "cs3Label": "policyVersion",
            "cs3": event.get("policy_version"),
            "cs4Label": "traceId",
            "cs4": event.get("trace_id"),
            "act": event.get("action"),
            "outcome": "failure" if event.get("action") in ("block", "challenge") else "success",
            "suser": event.get("principal_id"),
            "duser": event.get("tenant"),
            "dproc": event.get("model"),
            "app": event.get("application"),
            "deviceProcessName": event.get("stage"),
            "cn1Label": "latencyMs",
            "cn1": event.get("latency_ms"),
            "cs5Label": "owaspThreats",
            "cs5": ",".join(event.get("threats") or []),
            "cn2Label": "riskScore",
            "cn2": event.get("risk_score") or 0,
            "cs6Label": "riskBand",
            "cs6": event.get("risk_band") or "none",
            "deviceExternalId": event.get("instance_id"),
        }
        parts = [f"{k}={_cef_escape_value(v)}" for k, v in extension.items() if v not in (None, "")]
        return f"{header}|{' '.join(parts)}"

    def close(self) -> None:
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


def _cef_escape_header(value: str) -> str:
    """In the CEF header, ``\\`` and ``|`` must be escaped."""
    return value.replace("\\", "\\\\").replace("|", "\\|")


def _cef_escape_value(value: Any) -> str:
    """In CEF extensions, ``\\``, ``=`` and newlines must be escaped."""
    text = str(value)
    return text.replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "")


class OTLPExporter:
    """OpenTelemetry logs over HTTP, JSON encoding.

    Emitted as OTel *log records* rather than spans: an audit event is a
    discrete fact, not a duration. ``trace_id`` is carried through so the SIEM
    or backend can join a security event to the application trace that produced
    it — the property that makes this worth supporting alongside the webhook.
    """

    name = "otlp"

    def __init__(self, endpoint: str, *, headers: Mapping[str, str] | None = None, timeout_s: float = 10.0) -> None:
        self.endpoint = endpoint.rstrip("/")
        if not self.endpoint.endswith("/v1/logs"):
            self.endpoint = f"{self.endpoint}/v1/logs"
        self.headers = {"Content-Type": "application/json", **(headers or {})}
        self._client = httpx.Client(timeout=timeout_s)

    def export(self, events: Sequence[Mapping[str, Any]]) -> int:
        if not events:
            return 0
        records = [self._record(e) for e in events]
        payload = {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": [
                            _kv("service.name", "keeper-control-plane"),
                            _kv("telemetry.sdk.name", "keeper"),
                        ]
                    },
                    "scopeLogs": [{"scope": {"name": "keeper.audit"}, "logRecords": records}],
                }
            ]
        }
        response = self._client.post(self.endpoint, json=payload, headers=self.headers)
        response.raise_for_status()
        return len(events)

    @staticmethod
    def _record(event: Mapping[str, Any]) -> dict[str, Any]:
        severity_number = {"info": 9, "low": 9, "medium": 13, "high": 17, "critical": 21}.get(
            event.get("severity", "info"), 9
        )
        findings = [f for f in (event.get("findings") or []) if f.get("detected")]
        body = findings[0].get("summary") if findings else f"{event.get('action')} at {event.get('stage')}"
        record: dict[str, Any] = {
            "timeUnixNano": str(int(event.get("timestamp_ms") or 0) * 1_000_000),
            "severityNumber": severity_number,
            "severityText": str(event.get("severity", "info")).upper(),
            "body": {"stringValue": str(body)},
            "attributes": [
                _kv("keeper.event_id", event.get("event_id")),
                _kv("keeper.correlation_id", event.get("correlation_id")),
                _kv("keeper.action", event.get("action")),
                _kv("keeper.stage", event.get("stage")),
                _kv("keeper.application", event.get("application")),
                _kv("keeper.environment", event.get("environment")),
                _kv("keeper.principal_id", event.get("principal_id")),
                _kv("keeper.tenant", event.get("tenant")),
                _kv("keeper.model", event.get("model")),
                _kv("keeper.policy_version", event.get("policy_version")),
                _kv("keeper.detectors", ",".join(event.get("detectors_fired") or [])),
                _kv("keeper.categories", ",".join(event.get("categories") or [])),
                _kv("keeper.threats", ",".join(event.get("threats") or [])),
                _kv("keeper.risk_score", event.get("risk_score") or 0),
                _kv("keeper.risk_band", event.get("risk_band") or "none"),
            ],
        }
        if event.get("trace_id"):
            record["traceId"] = event["trace_id"]
        if event.get("span_id"):
            record["spanId"] = event["span_id"]
        return {k: v for k, v in record.items() if v is not None}

    def close(self) -> None:
        self._client.close()


def _kv(key: str, value: Any) -> dict[str, Any]:
    return {"key": key, "value": {"stringValue": "" if value is None else str(value)}}


def build_exporter(spec: str) -> SIEMExporter:
    """Build an exporter from a config string.

    Accepted forms::

        webhook:https://splunk.example.com/services/collector/raw
        syslog:siem.internal:514
        syslog+tcp:siem.internal:601
        otlp:https://otel-collector.internal:4318
    """
    kind, _, rest = spec.partition(":")
    if not rest:
        raise ValueError(f"malformed SIEM target {spec!r}")
    if kind == "webhook":
        return WebhookExporter(rest)
    if kind in ("syslog", "syslog+udp", "syslog+tcp"):
        host, _, port = rest.partition(":")
        protocol = "tcp" if kind.endswith("tcp") else "udp"
        return CEFExporter(host, int(port or 514), protocol=protocol)
    if kind == "otlp":
        return OTLPExporter(rest)
    raise ValueError(f"unknown SIEM target kind {kind!r}")


@dataclass(slots=True)
class ExportResult:
    exported: int = 0
    failed: int = 0
    checkpoint_ms: int = 0
    errors: tuple[str, ...] = ()


class SIEMForwarder:
    """Drains new audit events to every configured target on a timer.

    The checkpoint is ``received_ms``, not ``timestamp_ms``: events arrive out
    of order (an SDK that was offline ships an hour of backlog at once), and
    checkpointing on event time would silently skip them.
    """

    def __init__(self, repo: Any, exporters: Sequence[SIEMExporter], *, batch_size: int = 100, min_severity: str = "info") -> None:
        self.repo = repo
        self.exporters = list(exporters)
        self.batch_size = batch_size
        self.min_severity = min_severity
        self.checkpoint_ms = 0
        self.total_exported = 0
        self.total_failed = 0
        self.last_error: str | None = None

    def run_once(self) -> ExportResult:
        if not self.exporters:
            return ExportResult(checkpoint_ms=self.checkpoint_ms)
        events = self.repo.events_for_export(self.checkpoint_ms, self.batch_size, self.min_severity)
        if not events:
            return ExportResult(checkpoint_ms=self.checkpoint_ms)

        errors: list[str] = []
        exported = 0
        for exporter in self.exporters:
            try:
                exported += exporter.export(events)
            except Exception as exc:
                message = f"{exporter.name}: {exc}"
                errors.append(message)
                self.last_error = message
                log.error("SIEM export failed: %s", message)

        # Advance the checkpoint even on partial failure: a permanently broken
        # target must not pin the checkpoint and re-send the same batch for
        # ever. The failure is counted, surfaced on /health, and alertable.
        self.checkpoint_ms = max(int(e["received_ms"]) for e in events)
        self.total_exported += exported
        self.total_failed += len(errors)
        return ExportResult(
            exported=exported,
            failed=len(errors),
            checkpoint_ms=self.checkpoint_ms,
            errors=tuple(errors),
        )

    def health(self) -> dict[str, Any]:
        return {
            "targets": [e.name for e in self.exporters],
            "checkpoint_ms": self.checkpoint_ms,
            "exported": self.total_exported,
            "failed_batches": self.total_failed,
            "last_error": self.last_error,
        }

    def close(self) -> None:
        for exporter in self.exporters:
            try:
                exporter.close()
            except Exception:
                continue
