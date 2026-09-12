"""Request and response models.

Ingest validation is deliberately permissive about *unknown* fields and strict
about known ones. A fleet is never on one SDK version: a newer instance will
send fields this control plane has not heard of, and rejecting its batch would
lose the audit trail of the most up-to-date deployments. Unknown fields are
accepted and stored; known fields are type-checked.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

Action = Literal["allow", "flag", "redact", "challenge", "block"]
Severity = Literal["info", "low", "medium", "high", "critical"]


class SpanModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    start: int = 0
    end: int = 0
    label: str = "unknown"


class FindingModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    detector: str
    detected: bool = False
    score: float = 0.0
    severity: Severity = "info"
    action: Action = "allow"
    summary: str = ""
    category: str = "unspecified"
    spans: list[SpanModel] = Field(default_factory=list)
    evidence: dict[str, Any] = Field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str | None = None


class PolicyTraceModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    policy_id: str
    policy_version: str
    rule_id: str | None = None
    matched: bool = False
    action: Action = "allow"
    elapsed_ms: float = 0.0
    note: str = ""


class AuditEventModel(BaseModel):
    """One decision, as shipped by the SDK."""

    model_config = ConfigDict(extra="allow")

    event_id: str
    correlation_id: str
    timestamp_ms: int
    stage: str
    action: Action
    severity: Severity
    application: str
    environment: str = "unknown"
    sdk_version: str | None = None
    schema_version: str | None = None
    instance_id: str | None = None
    session_id: str | None = None
    principal_id: str | None = None
    principal_roles: list[str] = Field(default_factory=list)
    tenant: str | None = None
    model: str | None = None
    provider: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    policy_version: str | None = None
    findings: list[FindingModel] = Field(default_factory=list)
    policy_traces: list[PolicyTraceModel] = Field(default_factory=list)
    prompt: str | None = None
    response: str | None = None
    redacted_fields: list[str] = Field(default_factory=list)
    latency_ms: float = 0.0
    tokens_in: int | None = None
    tokens_out: int | None = None
    error: str | None = None
    tags: dict[str, Any] = Field(default_factory=dict)


class IngestRequest(BaseModel):
    instance_id: str
    events: list[AuditEventModel]


class IngestResponse(BaseModel):
    accepted: int
    duplicates: int
    rejected: int = 0
    alerts_fired: int = 0


class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    instance_id: str
    application: str
    environment: str = "unknown"
    sdk_version: str | None = None
    language: str = "python"
    policy_id: str | None = None
    policy_version: str | None = None
    detectors: list[str] = Field(default_factory=list)
    monitor_only: bool = False


class HeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    instance_id: str
    application: str | None = None
    health: dict[str, Any] = Field(default_factory=dict)


class QuotaRequest(BaseModel):
    instance_id: str
    scope: str
    consumed: int = 0


class QuotaResponse(BaseModel):
    scope: str
    lease: dict[str, Any]
    window_s: int


class PolicyResponse(BaseModel):
    bundle: str
    version: str
    etag: str
    policy: dict[str, Any]


class PolicyPublishRequest(BaseModel):
    bundle: str = "default"
    policy: dict[str, Any]
    publish: bool = True
    note: str = ""


class PolicyDryRunRequest(BaseModel):
    policy: dict[str, Any]
    hours: int = 24
    limit: int = 5000


class AlertRuleModel(BaseModel):
    model_config = ConfigDict(extra="allow")
    id: str | None = None
    name: str
    description: str = ""
    enabled: bool = True
    kind: Literal["match", "threshold", "anomaly"] = "match"
    spec: dict[str, Any] = Field(default_factory=dict)
    severity: Severity = "medium"
    channels: list[str] = Field(default_factory=lambda: ["log"])
    cooldown_s: int = 300


class EventPage(BaseModel):
    events: list[dict[str, Any]]
    total: int
    limit: int
    offset: int


class HealthResponse(BaseModel):
    status: str
    version: str
    uptime_ms: int
    environment: str
    database: str
    events_stored: int
    active_instances: int
    ingest: dict[str, Any]
    siem: dict[str, Any] | None = None
    warnings: list[str] = Field(default_factory=list)
