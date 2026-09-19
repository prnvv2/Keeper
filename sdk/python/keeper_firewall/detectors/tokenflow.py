"""Token-flow auditing: source-to-sink mediation at semantic boundaries.

This detector implements the core mechanism of the Token-Flow Firewall paper.
Its argument, restated: in an agent, almost every security-relevant state
change is carried by natural-language tokens crossing a boundary — a tool
argument, a memory write, a retrieved passage entering context, an outbound
message. Auditing *actions* after the fact is too late and auditing *content*
in isolation lacks the information needed to judge it. What you want is
pre-execution mediation of each transfer, with the source and the sink both in
view.

So each flow is reduced to a structured record — where the tokens came from,
where they are going, how privileged the sink is — and inspected before the
transfer happens. A ``shell.exec`` argument assembled from a web page is a
different event from the same string typed by the authenticated user, even
though the strings are identical.

The paper's cost argument also shapes the design here: full-coverage auditing
is only affordable if the default path is a cheap local check, with escalation
to an expensive arbitrator reserved for the ambiguous, high-impact minority.
This detector *is* the cheap path; it sets ``escalate`` in its evidence when it
wants a second opinion, and the pipeline decides whether to pay for one.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any

from ..config import DetectorConfig
from ..types import Action, Finding, RiskTier, Severity, Stage, TrustLevel
from .base import Detector, DetectorInput, detector

#: Sinks ordered by how much damage a bad transfer into them does. Keys are
#: matched as prefixes against the tool name, so "shell" covers "shell.exec".
DEFAULT_SINK_RISK: dict[str, RiskTier] = {
    "shell": RiskTier.CRITICAL,
    "exec": RiskTier.CRITICAL,
    "subprocess": RiskTier.CRITICAL,
    "file.write": RiskTier.HIGH,
    "file.delete": RiskTier.CRITICAL,
    "fs.": RiskTier.HIGH,
    "db.write": RiskTier.HIGH,
    "db.delete": RiskTier.CRITICAL,
    "sql": RiskTier.HIGH,
    "http.post": RiskTier.HIGH,
    "http.put": RiskTier.HIGH,
    "request": RiskTier.HIGH,
    "email": RiskTier.HIGH,
    "send": RiskTier.HIGH,
    "payment": RiskTier.CRITICAL,
    "transfer": RiskTier.CRITICAL,
    "purchase": RiskTier.CRITICAL,
    "credential": RiskTier.CRITICAL,
    "iam": RiskTier.CRITICAL,
    "memory.write": RiskTier.MEDIUM,
    "search": RiskTier.LOW,
    "read": RiskTier.LOW,
    "get": RiskTier.LOW,
    "lookup": RiskTier.LOW,
}

#: Argument content that indicates the transfer is doing something structurally
#: dangerous regardless of the sink's nominal risk tier.
DANGEROUS_ARGUMENT = (
    ("shell_chaining", re.compile(r"(?:;|&&|\|\||\$\(|`)\s*(?:curl|wget|nc|bash|sh|python|powershell|cmd)\b", re.I)),
    ("path_traversal", re.compile(r"\.\./\.\./|(?:^|[\s'\"])/(?:etc|root|proc|sys)/|%2e%2e%2f", re.I)),
    ("credential_path", re.compile(r"(?:\.ssh/|\.aws/|\.env\b|id_rsa|credentials\.json|\.kube/config|secrets?\.ya?ml)", re.I)),
    ("destructive", re.compile(r"\b(?:rm\s+-[rf]{1,2}|drop\s+(?:table|database)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|$)|format\s+[a-z]:)\b", re.I)),
    ("sql_injection", re.compile(r"(?:'\s*or\s*'?1'?\s*=\s*'?1|union\s+select|--\s*$)", re.I)),
    ("outbound_exfil", re.compile(r"https?://(?!localhost|127\.0\.0\.1)[^\s'\"]{4,}", re.I)),
)


@dataclass(slots=True)
class FlowRecord:
    """The structured source -> sink record an audit decision is made on."""

    source_trust: TrustLevel
    sink: str
    sink_risk: RiskTier
    boundary: Stage
    persistent: bool
    external_effect: bool
    tainted_by: tuple[str, ...] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_trust": self.source_trust.value,
            "sink": self.sink,
            "sink_risk": self.sink_risk.value,
            "boundary": self.boundary.value,
            "persistent": self.persistent,
            "external_effect": self.external_effect,
            "tainted_by": list(self.tainted_by),
            "metadata": dict(self.metadata),
        }


@detector("token_flow")
class TokenFlowDetector(Detector):
    """Mediates a single semantic transfer before it reaches its sink."""

    stages = (Stage.TOOL_CALL, Stage.TOOL_RESULT, Stage.MEMORY_WRITE, Stage.RETRIEVAL)
    category = "unsafe_flow"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.sink_risk: dict[str, RiskTier] = {
            **DEFAULT_SINK_RISK,
            **{k: RiskTier(v) for k, v in (opts.get("sink_risk") or {}).items()},
        }
        self.default_risk = RiskTier(opts.get("default_risk", "medium"))
        # Transfers at or above this tier that carry low-authority content are
        # deferred to a human rather than blocked outright, when the app has
        # wired up a confirmation callback.
        self.challenge_instead_of_block: bool = bool(opts.get("challenge_instead_of_block", False))

    def resolve_risk(self, sink: str) -> RiskTier:
        lowered = sink.lower()
        best: RiskTier | None = None
        for prefix, tier in self.sink_risk.items():
            matches = lowered.startswith(prefix) or f".{prefix}" in lowered or prefix in lowered
            if matches and (best is None or _RISK_ORDER[tier] > _RISK_ORDER[best]):
                best = tier
        return best or self.default_risk

    #: Boundaries where content flows *into* the model's context rather than
    #: into a privileged sink.
    INGRESS_STAGES = (Stage.RETRIEVAL, Stage.TOOL_RESULT)

    #: The only boundary where the authority gap applies: an actual action with
    #: an effect. Ingress (a retrieved passage entering context) is not an
    #: action, and neither is a memory write — the Provenance-Preserving Memory
    #: Firewall paper is explicit that external content may be *remembered*,
    #: just never allowed to *authorise*. Gating storage instead of execution
    #: would block every RAG corpus and every agent note while leaving the
    #: actual laundering path (:mod:`keeper_firewall.runtime.memory`) untouched.
    ACTION_STAGES = (Stage.TOOL_CALL,)

    def build_record(self, data: DetectorInput) -> FlowRecord:
        call = data.tool_call
        if data.stage in self.INGRESS_STAGES:
            # Direction, not the presence of a tool object, decides this: a
            # result from http.get is ingress even though the call that
            # produced it was egress.
            sink = f"model_context<-{call.name}" if call else "model_context"
            risk = RiskTier.LOW
        else:
            sink = call.name if call else data.stage.value
            risk = (call.risk if call and call.risk else self.resolve_risk(sink))
        persistent = data.stage in (Stage.MEMORY_WRITE,) or "write" in sink.lower()
        external = data.stage is Stage.TOOL_CALL and risk in (RiskTier.HIGH, RiskTier.CRITICAL)
        tainted = tuple(data.metadata.get("tainted_by", ()))
        return FlowRecord(
            source_trust=data.trust,
            sink=sink,
            sink_risk=risk,
            boundary=data.stage,
            persistent=persistent,
            external_effect=external,
            tainted_by=tainted,
            metadata={"agent": call.agent if call else None},
        )

    def detect(self, data: DetectorInput) -> Finding:
        record = self.build_record(data)
        dangerous = [name for name, pattern in DANGEROUS_ARGUMENT if pattern.search(data.payload)]

        authority = record.source_trust.authority()
        required = record.sink_risk.required_authority()
        authority_gap = required - authority

        evidence: dict[str, Any] = {
            "flow": record.to_dict(),
            "dangerous_patterns": dangerous,
            "authority": authority,
            "required_authority": required,
        }

        # 1. Structural danger in the argument text: block regardless of source.
        if dangerous and record.sink_risk in (RiskTier.HIGH, RiskTier.CRITICAL):
            return self.hit(
                score=1.0,
                summary=(
                    f"dangerous argument pattern(s) {dangerous} flowing into "
                    f"{record.sink_risk.value}-risk sink {record.sink!r}"
                ),
                severity=Severity.CRITICAL,
                action=Action.BLOCK,
                **evidence,
            )

        # 2. Authority gap: low-trust content driving a privileged sink. This
        #    is the case the paper cares most about and the one a content
        #    classifier cannot see, because the *text* may be entirely benign.
        #    Only applied at an action boundary; see ACTION_STAGES.
        if authority_gap > 0 and record.boundary in self.ACTION_STAGES:
            severity = Severity.CRITICAL if record.sink_risk is RiskTier.CRITICAL else Severity.HIGH
            action = Action.CHALLENGE if self.challenge_instead_of_block else Action.BLOCK
            return self.hit(
                score=min(1.0, 0.6 + 0.15 * authority_gap),
                summary=(
                    f"{record.source_trust.value}-authority content is driving a "
                    f"{record.sink_risk.value}-risk transfer into {record.sink!r}"
                ),
                severity=severity,
                action=action,
                authority_gap=authority_gap,
                **evidence,
            )

        # 3. Permitted, but worth recording: dangerous-looking content on a
        #    low-risk sink, or anything persisted from an untrusted source.
        if dangerous:
            return self.hit(
                score=0.4,
                summary=f"suspicious argument pattern(s) {dangerous} on low-risk sink {record.sink!r}",
                severity=Severity.LOW,
                action=Action.FLAG,
                **evidence,
            )
        if record.persistent and record.source_trust.authority() <= TrustLevel.RETRIEVED.authority():
            return self.hit(
                score=0.35,
                summary=f"{record.source_trust.value} content persisted to {record.sink!r}",
                severity=Severity.LOW,
                action=Action.FLAG,
                escalate=True,
                **evidence,
            )
        return self.clean(f"flow into {record.sink!r} within authority", **evidence)


_RISK_ORDER = {
    RiskTier.LOW: 0,
    RiskTier.MEDIUM: 1,
    RiskTier.HIGH: 2,
    RiskTier.CRITICAL: 3,
}
