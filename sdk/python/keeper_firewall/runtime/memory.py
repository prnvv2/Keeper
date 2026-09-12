"""Provenance-preserving agent memory.

This module implements the non-amplification property from the Provenance-
Preserving Memory Firewall paper, which identifies a failure mode that none of
the other controls in this project catch.

The failure, restated: an agent reads an untrusted web page in task A. It does
not store the raw page — it *consolidates* it, via the model, into a compact
memory: "user workflow: resume PM-A011 when handling monitor setup". The
consolidation strips the malicious phrasing, which is what content filters look
for. It also strips the *source*, which is what actually limited the content's
authority. In task B the memory is retrieved and reads as user history, and it
authorises a tool call the original web page could never have authorised. The
trigger survived; the provenance was laundered.

Two mechanisms, and the second is the one that matters:

1. **Platform-maintained provenance.** Every memory is written with the trust
   level of the boundary it crossed, recorded by Keeper — not by the model, not
   from anything in the text. Consolidation is recorded as a transformation
   over parent records, and a derived record's authority is the *minimum* of
   its parents. Summarising may lose information; it cannot gain authority.

2. **Risk-authority binding at execution.** Before a tool call runs, the
   memories that actually support it are identified and their authority is
   compared to the call's risk tier. The paper is emphatic that storing
   provenance is not enough on its own — the authority has to be bound to the
   specific call arguments at execution time, or an unrelated high-authority
   memory in the same context silently vouches for the action.

External-derived memory stays useful as context. It just cannot, by itself,
authorise a purchase, an email, a credential change, or a deletion.
"""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from ..types import (
    Action,
    Decision,
    Finding,
    MemoryRecord,
    RequestContext,
    RiskTier,
    Severity,
    Stage,
    ToolCall,
    TrustLevel,
)

_WORD = re.compile(r"[a-z0-9_.\-]{3,}")
_STOP = frozenset(
    "the and for with from that this when where what have has was were are you your our their".split()
)


def _terms(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOP}


@dataclass(slots=True)
class MemoryGateResult:
    """Outcome of the risk-authority gate for one tool call."""

    allowed: bool
    reason: str
    required_authority: int
    available_authority: int
    supporting: tuple[MemoryRecord, ...] = ()
    blocking: tuple[MemoryRecord, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "required_authority": self.required_authority,
            "available_authority": self.available_authority,
            "supporting": [
                {
                    "memory_id": m.memory_id,
                    "trust": m.trust.value,
                    "source": m.source,
                    "authority": m.authority(),
                    "transformations": list(m.transformations),
                    "derived_from": list(m.derived_from),
                }
                for m in self.supporting
            ],
            "blocking": [
                {"memory_id": m.memory_id, "trust": m.trust.value, "source": m.source}
                for m in self.blocking
            ],
        }


@dataclass
class MemoryFirewall:
    """Provenance-preserving memory store and execution gate."""

    pipeline: Any = None  # keeper_firewall.pipeline.Pipeline; optional
    records: dict[str, MemoryRecord] = field(default_factory=dict)
    #: Tool-call risk tiers that require memory-backed authority at all. LOW
    #: risk reads do not need a provenance argument to proceed.
    gated_tiers: frozenset[RiskTier] = frozenset({RiskTier.HIGH, RiskTier.CRITICAL})
    #: How much term overlap makes a memory "relevant" to a call's arguments.
    relevance_threshold: float = 0.2
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    # -- writing -----------------------------------------------------------

    def write(
        self,
        content: str,
        *,
        trust: TrustLevel,
        source: str = "unknown",
        context: RequestContext | None = None,
        derived_from: Sequence[str] = (),
        transformations: Sequence[str] = (),
        user_confirmed: bool = False,
        metadata: dict[str, Any] | None = None,
    ) -> tuple[MemoryRecord, Decision | None]:
        """Persist a memory with platform-maintained provenance.

        ``trust`` is what the *caller's integration point* knows about where
        the content came from — the web fetch tool passes EXTERNAL, the chat
        handler passes USER. It is never inferred from ``content``.
        """
        effective_trust = self._floor(trust, derived_from)

        decision: Decision | None = None
        if self.pipeline is not None and context is not None:
            decision = self.pipeline.evaluate(
                Stage.MEMORY_WRITE,
                content,
                context,
                trust=effective_trust,
                metadata={"source": source, "derived_from": list(derived_from)},
            )
            if decision.blocked:
                return (
                    MemoryRecord(content=content, trust=effective_trust, source=source),
                    decision,
                )
            if decision.action is Action.REDACT and decision.payload is not None:
                content = decision.payload
                transformations = tuple(transformations) + ("keeper_redaction",)

        record = MemoryRecord(
            content=content,
            trust=effective_trust,
            source=source,
            derived_from=tuple(derived_from),
            transformations=tuple(transformations),
            # Confirmation is only honoured when the platform observed it. A
            # `user_confirmed=True` derived from model output would be exactly
            # the laundering this class exists to prevent.
            user_confirmed=bool(user_confirmed) and effective_trust.authority() >= TrustLevel.USER.authority(),
            metadata=dict(metadata or {}),
        )
        with self._lock:
            self.records[record.memory_id] = record
        return record, decision

    def consolidate(
        self,
        content: str,
        parents: Sequence[MemoryRecord | str],
        *,
        source: str = "consolidation",
        context: RequestContext | None = None,
        transformation: str = "llm_consolidation",
    ) -> tuple[MemoryRecord, Decision | None]:
        """Write a memory derived from existing ones.

        The consolidated record's trust is the minimum over its parents,
        whatever the consolidating model produced as text. This single line is
        the non-amplification property.
        """
        resolved = [self._resolve(p) for p in parents]
        present = [r for r in resolved if r is not None]
        trust = min(
            (r.trust for r in present),
            key=lambda t: t.authority(),
            default=TrustLevel.EXTERNAL,
        )
        return self.write(
            content,
            trust=trust,
            source=source,
            context=context,
            derived_from=tuple(r.memory_id for r in present),
            transformations=(transformation,),
        )

    def _floor(self, trust: TrustLevel, derived_from: Sequence[str]) -> TrustLevel:
        """A derived record can never outrank the least trusted ancestor."""
        lowest = trust
        for parent_id in derived_from:
            parent = self.records.get(parent_id)
            if parent is not None and parent.trust.authority() < lowest.authority():
                lowest = parent.trust
        return lowest

    def _resolve(self, ref: MemoryRecord | str) -> MemoryRecord | None:
        if isinstance(ref, MemoryRecord):
            return ref
        return self.records.get(ref)

    # -- reading -----------------------------------------------------------

    def recall(self, query: str, *, limit: int = 5, min_trust: TrustLevel | None = None) -> list[MemoryRecord]:
        """Retrieve relevant memories, lowest-authority last."""
        query_terms = _terms(query)
        with self._lock:
            candidates = list(self.records.values())
        scored: list[tuple[float, MemoryRecord]] = []
        for record in candidates:
            if min_trust and record.authority() < min_trust.authority():
                continue
            score = self._relevance(query_terms, record)
            if score > 0:
                scored.append((score, record))
        scored.sort(key=lambda pair: (-pair[1].authority(), -pair[0]))
        return [record for _score, record in scored[:limit]]

    @staticmethod
    def _relevance(query_terms: set[str], record: MemoryRecord) -> float:
        if not query_terms:
            return 0.0
        record_terms = _terms(record.content)
        if not record_terms:
            return 0.0
        return len(query_terms & record_terms) / len(query_terms)

    # -- the execution gate -----------------------------------------------

    def authorize_call(
        self,
        call: ToolCall,
        *,
        context: RequestContext | None = None,
        candidates: Iterable[MemoryRecord] | None = None,
        user_confirmed: bool = False,
    ) -> MemoryGateResult:
        """Check that memories supporting this call carry enough authority.

        Relevance is computed against the call's *arguments*, not the whole
        conversation. That is the binding step: an unrelated USER-authority
        memory sitting in the same context does not vouch for a call whose
        arguments came from a web page.
        """
        risk = call.risk or RiskTier.MEDIUM
        if risk not in self.gated_tiers:
            return MemoryGateResult(
                allowed=True,
                reason=f"{risk.value}-risk call does not require memory-backed authority",
                required_authority=risk.required_authority(),
                available_authority=TrustLevel.SYSTEM.authority(),
            )

        if user_confirmed:
            return MemoryGateResult(
                allowed=True,
                reason="user confirmed this action out of band",
                required_authority=risk.required_authority(),
                available_authority=TrustLevel.USER_CONFIRMED.authority(),
            )

        pool = list(candidates) if candidates is not None else self.recall(call.argument_text(), limit=10)
        argument_terms = _terms(call.argument_text())
        supporting = [
            r for r in pool if self._relevance(argument_terms, r) >= self.relevance_threshold
        ]

        required = risk.required_authority()
        if not supporting:
            return MemoryGateResult(
                allowed=False,
                reason=(
                    f"no memory supports this {risk.value}-risk call; "
                    "high-risk actions require explicit user authority"
                ),
                required_authority=required,
                available_authority=-1,
            )

        available = max(r.authority() for r in supporting)
        blocking = tuple(r for r in supporting if r.authority() < required)
        if available >= required:
            return MemoryGateResult(
                allowed=True,
                reason="supporting memory carries sufficient authority",
                required_authority=required,
                available_authority=available,
                supporting=tuple(supporting),
            )
        return MemoryGateResult(
            allowed=False,
            reason=(
                f"this {risk.value}-risk call is supported only by "
                f"{min(supporting, key=lambda r: r.authority()).trust.value}-authority memory; "
                "source authority cannot be amplified by consolidation"
            ),
            required_authority=required,
            available_authority=available,
            supporting=tuple(supporting),
            blocking=blocking,
        )

    def decision_for(self, result: MemoryGateResult, call: ToolCall, context: RequestContext) -> Decision:
        """Turn a gate result into an auditable decision."""
        finding = Finding(
            detector="memory_provenance",
            detected=not result.allowed,
            score=1.0 if not result.allowed else 0.0,
            severity=Severity.CRITICAL if not result.allowed else Severity.INFO,
            action=Action.BLOCK if not result.allowed else Action.ALLOW,
            summary=result.reason,
            category="memory_provenance_laundering",
            evidence=result.to_dict(),
        )
        decision = Decision(
            action=finding.action,
            stage=Stage.MEMORY_READ,
            correlation_id=context.correlation_id,
            findings=(finding,),
        )
        if self.pipeline is not None:
            self.pipeline.emit(
                decision,
                context,
                prompt=call.argument_text(),
                extra_tags={"tool": call.name, "risk": (call.risk or RiskTier.MEDIUM).value},
            )
        return decision

    # -- maintenance -------------------------------------------------------

    def forget(self, memory_id: str) -> bool:
        with self._lock:
            return self.records.pop(memory_id, None) is not None

    def lineage(self, memory_id: str) -> list[MemoryRecord]:
        """Full ancestry of a memory, for incident investigation."""
        out: list[MemoryRecord] = []
        stack = [memory_id]
        seen: set[str] = set()
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            record = self.records.get(current)
            if record is None:
                continue
            out.append(record)
            stack.extend(record.derived_from)
        return out

    def stats(self) -> dict[str, Any]:
        with self._lock:
            records = list(self.records.values())
        by_trust: dict[str, int] = {}
        for record in records:
            by_trust[record.trust.value] = by_trust.get(record.trust.value, 0) + 1
        return {
            "total": len(records),
            "by_trust": by_trust,
            "derived": sum(1 for r in records if r.derived_from),
            "user_confirmed": sum(1 for r in records if r.user_confirmed),
        }
