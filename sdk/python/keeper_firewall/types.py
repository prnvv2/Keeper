"""Core data model shared by every Keeper module.

These types are deliberately dependency-free dataclasses rather than pydantic
models: the SDK is installed into third-party applications, so every transitive
dependency we add is a supply-chain liability for our users (see
``docs/threat-model.md``, "Security of the firewall itself"). The control plane,
which we ship as a service and control end to end, is free to use pydantic.

The audit event schema defined here is the contract between the data plane and
the control plane. It is versioned by
:data:`keeper_firewall.version.SCHEMA_VERSION`; any breaking change requires a
version bump plus an ingest-side migration.
"""

from __future__ import annotations

import enum
import time
import uuid
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from .version import SCHEMA_VERSION, __version__


def new_id(prefix: str = "") -> str:
    """Return a short unique identifier, optionally prefixed."""
    raw = uuid.uuid4().hex
    return f"{prefix}{raw}" if prefix else raw


def now_ms() -> int:
    """Current wall-clock time in milliseconds since the epoch."""
    return int(time.time() * 1000)


class Action(str, enum.Enum):
    """What the firewall decided to do with an interaction."""

    ALLOW = "allow"
    FLAG = "flag"            # allowed, but recorded as security-relevant
    REDACT = "redact"        # allowed after mutation of the payload
    CHALLENGE = "challenge"  # requires out-of-band human confirmation
    BLOCK = "block"

    def severity(self) -> int:
        return _ACTION_SEVERITY[self]

    def escalates_over(self, other: "Action") -> bool:
        return self.severity() > other.severity()


_ACTION_SEVERITY: dict["Action", int] = {}


class Severity(str, enum.Enum):
    """Security severity of a finding, used for alerting and SIEM mapping."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict["Severity", int] = {}


class Stage(str, enum.Enum):
    """Pipeline stage at which a decision was taken."""

    INPUT = "input"
    OUTPUT = "output"
    STREAM = "stream"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    RETRIEVAL = "retrieval"
    MEMORY_WRITE = "memory_write"
    MEMORY_READ = "memory_read"
    ACCESS = "access"


class TrustLevel(str, enum.Enum):
    """Provenance trust tiers.

    Derived from the Provenance-Preserving Memory Firewall paper: authority is
    a property of *where content came from*, and no downstream transformation
    (summarisation, consolidation, paraphrase) may raise it. See
    :mod:`keeper_firewall.runtime.memory`.
    """

    SYSTEM = "system"                  # operator-authored configuration
    USER_CONFIRMED = "user_confirmed"  # the human explicitly confirmed it
    USER = "user"                      # typed by the authenticated end user
    TOOL = "tool"                      # returned by a tool the app invoked
    RETRIEVED = "retrieved"            # pulled from a RAG corpus
    EXTERNAL = "external"              # arbitrary third-party content

    def authority(self) -> int:
        return _TRUST_AUTHORITY[self]


_TRUST_AUTHORITY: dict["TrustLevel", int] = {}


class RiskTier(str, enum.Enum):
    """How dangerous an action (typically a tool call) is if wrongly taken."""

    LOW = "low"            # read-only, reversible, no external effect
    MEDIUM = "medium"      # writes local state
    HIGH = "high"          # external effect: payment, email, credential change
    CRITICAL = "critical"  # destructive or irreversible

    def required_authority(self) -> int:
        return _RISK_REQUIRED_AUTHORITY[self]


_RISK_REQUIRED_AUTHORITY: dict["RiskTier", int] = {}


def _init_tables() -> None:
    """Populate the ordering tables once every enum member exists."""
    _ACTION_SEVERITY.update(
        {
            Action.ALLOW: 0,
            Action.FLAG: 1,
            Action.REDACT: 2,
            Action.CHALLENGE: 3,
            Action.BLOCK: 4,
        }
    )
    _SEVERITY_RANK.update(
        {
            Severity.INFO: 0,
            Severity.LOW: 1,
            Severity.MEDIUM: 2,
            Severity.HIGH: 3,
            Severity.CRITICAL: 4,
        }
    )
    _TRUST_AUTHORITY.update(
        {
            TrustLevel.SYSTEM: 5,
            TrustLevel.USER_CONFIRMED: 4,
            TrustLevel.USER: 3,
            TrustLevel.TOOL: 2,
            TrustLevel.RETRIEVED: 1,
            TrustLevel.EXTERNAL: 0,
        }
    )
    _RISK_REQUIRED_AUTHORITY.update(
        {
            RiskTier.LOW: _TRUST_AUTHORITY[TrustLevel.RETRIEVED],
            RiskTier.MEDIUM: _TRUST_AUTHORITY[TrustLevel.USER],
            RiskTier.HIGH: _TRUST_AUTHORITY[TrustLevel.USER_CONFIRMED],
            RiskTier.CRITICAL: _TRUST_AUTHORITY[TrustLevel.USER_CONFIRMED],
        }
    )


_init_tables()


@dataclass(slots=True)
class Principal:
    """The authenticated actor on whose behalf an interaction happens."""

    id: str
    roles: tuple[str, ...] = ()
    tenant: str | None = None
    attributes: Mapping[str, Any] = field(default_factory=dict)
    authenticated: bool = False
    auth_method: str | None = None

    @classmethod
    def anonymous(cls) -> "Principal":
        return cls(id="anonymous", roles=("anonymous",), authenticated=False)

    def has_role(self, role: str) -> bool:
        return role in self.roles


@dataclass(slots=True)
class Message:
    """One turn of a conversation, in the shape every provider agrees on."""

    role: str
    content: str
    name: str | None = None
    trust: TrustLevel = TrustLevel.USER
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"role": self.role, "content": self.content}
        if self.name:
            out["name"] = self.name
        return out


@dataclass(slots=True)
class Span:
    """A character range inside a payload that a detector matched."""

    start: int
    end: int
    label: str
    snippet: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {"start": self.start, "end": self.end, "label": self.label}


@dataclass(slots=True)
class Finding:
    """One detector's verdict about one payload.

    ``score`` is a detector-local confidence in ``[0, 1]``. It is deliberately
    *not* averaged across detectors: the Cognitive Firewall paper shows that
    averaging independent safety signals dilutes a single confident danger
    signal until it stops firing. Keeper combines findings by escalation
    instead (see :meth:`Decision.combine`).
    """

    detector: str
    detected: bool
    score: float = 0.0
    severity: Severity = Severity.INFO
    action: Action = Action.ALLOW
    summary: str = ""
    category: str = "unspecified"
    spans: tuple[Span, ...] = ()
    evidence: Mapping[str, Any] = field(default_factory=dict)
    elapsed_ms: float = 0.0
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "detector": self.detector,
            "detected": self.detected,
            "score": round(self.score, 4),
            "severity": self.severity.value,
            "action": self.action.value,
            "summary": self.summary,
            "category": self.category,
            "spans": [s.to_dict() for s in self.spans],
            "evidence": dict(self.evidence),
            "elapsed_ms": round(self.elapsed_ms, 3),
            "error": self.error,
        }


@dataclass(slots=True)
class PolicyTrace:
    """Why a policy produced the action it did — the auditable rationale."""

    policy_id: str
    policy_version: str
    rule_id: str | None
    matched: bool
    action: Action
    elapsed_ms: float = 0.0
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "policy_id": self.policy_id,
            "policy_version": self.policy_version,
            "rule_id": self.rule_id,
            "matched": self.matched,
            "action": self.action.value,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "note": self.note,
        }


@dataclass(slots=True)
class Decision:
    """The firewall's combined verdict for one pipeline stage."""

    action: Action
    stage: Stage
    correlation_id: str
    findings: tuple[Finding, ...] = ()
    policy_traces: tuple[PolicyTrace, ...] = ()
    payload: str | None = None           # possibly redacted payload
    original_payload: str | None = None  # pre-redaction, never shipped raw
    elapsed_ms: float = 0.0
    fail_mode_engaged: str | None = None  # set when a fail-open/closed path ran

    @property
    def blocked(self) -> bool:
        return self.action is Action.BLOCK

    @property
    def allowed(self) -> bool:
        return self.action in (Action.ALLOW, Action.FLAG, Action.REDACT)

    @property
    def reasons(self) -> tuple[Finding, ...]:
        """Findings that actually drove the decision, most severe first."""
        fired = [f for f in self.findings if f.detected]
        return tuple(sorted(fired, key=lambda f: (-f.action.severity(), -f.score)))

    @property
    def severity(self) -> Severity:
        fired = [f.severity for f in self.findings if f.detected]
        return max(fired, key=lambda s: s.rank()) if fired else Severity.INFO

    @classmethod
    def combine(
        cls,
        stage: Stage,
        correlation_id: str,
        findings: Iterable[Finding],
        policy_traces: Iterable[PolicyTrace] = (),
        payload: str | None = None,
    ) -> "Decision":
        """Escalation combination: the most severe signal wins outright.

        This is the decision rule from the Cognitive Firewall paper, applied to
        detectors rather than to its four LLM gates: each evaluator returns a
        categorical verdict and the pipeline takes the maximum rather than a
        weighted mean, so one confident BLOCK is never out-voted by a quorum of
        ALLOWs.
        """
        found = tuple(findings)
        traces = tuple(policy_traces)
        action = Action.ALLOW
        for f in found:
            if f.detected and f.action.escalates_over(action):
                action = f.action
        for t in traces:
            if t.matched and t.action.escalates_over(action):
                action = t.action
        return cls(
            action=action,
            stage=stage,
            correlation_id=correlation_id,
            findings=found,
            policy_traces=traces,
            payload=payload,
        )


@dataclass(slots=True)
class RequestContext:
    """Everything the pipeline needs to know about one AI interaction.

    One ``RequestContext`` spans the whole request: input filtering, the model
    call, output filtering, and every tool call in between. Its
    ``correlation_id`` ties the resulting audit events together in the control
    plane and is what an investigator pastes into the dashboard search box.
    """

    correlation_id: str = field(default_factory=lambda: new_id("req_"))
    session_id: str | None = None
    principal: Principal = field(default_factory=Principal.anonymous)
    application: str = "unknown"
    environment: str = "production"
    model: str | None = None
    provider: str | None = None
    messages: list[Message] = field(default_factory=list)
    trace_id: str | None = None
    span_id: str | None = None
    tags: Mapping[str, Any] = field(default_factory=dict)
    started_ms: int = field(default_factory=now_ms)

    def conversation_text(self, limit: int | None = None) -> str:
        msgs = self.messages if limit is None else self.messages[-limit:]
        return "\n".join(f"{m.role}: {m.content}" for m in msgs)


@dataclass(slots=True)
class AuditEvent:
    """The unit of observability. One decision -> one audit event.

    Shipped to the control plane as JSON. Field names are stable; additions are
    backwards compatible, removals are not.
    """

    event_id: str
    correlation_id: str
    timestamp_ms: int
    stage: Stage
    action: Action
    severity: Severity
    application: str
    environment: str
    sdk_version: str = __version__
    schema_version: str = SCHEMA_VERSION
    instance_id: str = ""
    session_id: str | None = None
    principal_id: str | None = None
    principal_roles: tuple[str, ...] = ()
    tenant: str | None = None
    model: str | None = None
    provider: str | None = None
    trace_id: str | None = None
    span_id: str | None = None
    policy_version: str | None = None
    findings: tuple[Finding, ...] = ()
    policy_traces: tuple[PolicyTrace, ...] = ()
    prompt: str | None = None
    response: str | None = None
    redacted_fields: tuple[str, ...] = ()
    latency_ms: float = 0.0
    tokens_in: int | None = None
    tokens_out: int | None = None
    error: str | None = None
    tags: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["stage"] = self.stage.value
        d["action"] = self.action.value
        d["severity"] = self.severity.value
        d["findings"] = [f.to_dict() for f in self.findings]
        d["policy_traces"] = [t.to_dict() for t in self.policy_traces]
        d["principal_roles"] = list(self.principal_roles)
        d["redacted_fields"] = list(self.redacted_fields)
        d["tags"] = dict(self.tags)
        return d


@dataclass(slots=True)
class ToolCall:
    """An agent's intent to invoke a tool, intercepted before execution."""

    name: str
    arguments: Mapping[str, Any] = field(default_factory=dict)
    call_id: str = field(default_factory=lambda: new_id("call_"))
    agent: str | None = None
    risk: RiskTier | None = None  # resolved from the tool registry if None

    def argument_text(self) -> str:
        parts = [f"{k}={v!r}" for k, v in sorted(self.arguments.items())]
        return f"{self.name}({', '.join(parts)})"


@dataclass(slots=True)
class Document:
    """A retrieved document, screened before it enters the model's context."""

    content: str
    source: str = "unknown"
    doc_id: str = field(default_factory=lambda: new_id("doc_"))
    trust: TrustLevel = TrustLevel.RETRIEVED
    metadata: Mapping[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class MemoryRecord:
    """A persisted agent memory carrying non-forgeable provenance.

    ``trust`` and ``derived_from`` are *platform maintained*: Keeper sets them
    at write time from the boundary the content crossed, never from what the
    model claims about the memory. That is the non-amplification property — a
    consolidation step may rewrite the text but cannot raise the authority of
    its source.
    """

    content: str
    trust: TrustLevel
    memory_id: str = field(default_factory=lambda: new_id("mem_"))
    source: str = "unknown"
    derived_from: tuple[str, ...] = ()
    transformations: tuple[str, ...] = ()
    user_confirmed: bool = False
    created_ms: int = field(default_factory=now_ms)
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def authority(self) -> int:
        """Effective authority of this record.

        Explicit user confirmation is the *only* way authority rises, and it
        has to be recorded by the platform (not inferred from the text).
        """
        base = self.trust.authority()
        if self.user_confirmed:
            base = max(base, TrustLevel.USER_CONFIRMED.authority())
        return base


@dataclass(slots=True)
class LLMResponse:
    """Normalised response from any model backend."""

    text: str
    model: str
    raw: Any = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    finish_reason: str | None = None
    tool_calls: Sequence[ToolCall] = ()


@dataclass(slots=True)
class GuardedResponse:
    """What :meth:`keeper_firewall.Keeper.chat` hands back to the caller."""

    text: str
    correlation_id: str
    model: str | None = None
    input_decision: Decision | None = None
    output_decision: Decision | None = None
    blocked: bool = False
    raw: Any = None
    tokens_in: int | None = None
    tokens_out: int | None = None
    latency_ms: float = 0.0

    @property
    def findings(self) -> tuple[Finding, ...]:
        out: list[Finding] = []
        for d in (self.input_decision, self.output_decision):
            if d:
                out.extend(d.reasons)
        return tuple(out)

    def __str__(self) -> str:  # convenient: str(response) is the model text
        return self.text
