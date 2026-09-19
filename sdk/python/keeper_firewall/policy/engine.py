"""Policy evaluation.

An engine takes the facts about one pipeline stage — which detectors fired, who
the principal is, what stage we are at — and returns an ordered list of
:class:`~keeper_firewall.types.PolicyTrace` records. It never mutates anything
and never decides the final action on its own: the pipeline combines policy
traces with detector findings by escalation.

Two implementations share one interface:

:class:`EmbeddedEngine`
    In-process evaluation of the declarative policy in
    :mod:`keeper_firewall.policy.models`. Microseconds, no dependencies.

:class:`OPAEngine`
    Delegates to an OPA sidecar over HTTP for organisations that already run
    Rego. Adds a network hop, so it is opt-in and caches aggressively.
"""

from __future__ import annotations

import time
from typing import Any, Mapping, Protocol, Sequence

from ..errors import PolicyError
from ..types import (
    Action,
    Finding,
    PolicyTrace,
    RequestContext,
    Severity,
    Stage,
    ToolCall,
    TrustLevel,
)
from .models import Policy


def build_facts(
    stage: Stage,
    context: RequestContext,
    findings: Sequence[Finding],
    *,
    payload: str | None = None,
    trust: TrustLevel = TrustLevel.USER,
    tool_call: ToolCall | None = None,
    risk: Any = None,
) -> dict[str, Any]:
    """Flatten one stage's state into the mapping the condition language reads.

    Built once per stage and reused across every rule, so rule evaluation is
    dictionary lookups rather than repeated traversal of the finding list.
    """
    fired = [f for f in findings if f.detected]
    return {
        "stage": stage.value,
        "environment": context.environment,
        "application": context.application,
        "model": context.model,
        "provider": context.provider,
        "tenant": context.principal.tenant,
        "principal_id": context.principal.id,
        "roles": list(context.principal.roles),
        "authenticated": context.principal.authenticated,
        "trust": trust.value,
        "tool": tool_call.name if tool_call else None,
        "detectors_fired": [f.detector for f in fired],
        "categories": sorted({f.category for f in fired}),
        "labels": sorted({s.label for f in fired for s in f.spans}),
        "severity": max((f.severity for f in fired), key=lambda s: s.rank(), default=Severity.INFO).value,
        "max_score": max((f.score for f in fired), default=0.0),
        "tags": dict(context.tags),
        "payload": payload,
        "turn_count": len(context.messages),
        "threats": sorted({t for f in fired for t in f.threats}),
        "risk_score": getattr(risk, "score", 0),
        "risk_band": getattr(getattr(risk, "band", None), "value", "none"),
    }


class PolicyEngine(Protocol):
    """What the pipeline requires of any policy engine."""

    def evaluate(self, facts: Mapping[str, Any]) -> list[PolicyTrace]: ...

    @property
    def policy(self) -> Policy: ...


class EmbeddedEngine:
    """Evaluates a :class:`Policy` in process."""

    def __init__(self, policy: Policy, *, dry_run: bool = False) -> None:
        self._policy = policy
        self.dry_run = dry_run
        for rule in policy.rules:
            rule.compile()  # fail fast: a bad policy must not fail per-request

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, facts: Mapping[str, Any]) -> list[PolicyTrace]:
        traces: list[PolicyTrace] = []
        start = time.perf_counter()
        for rule in self._policy.rules:
            rule_start = time.perf_counter()
            try:
                matched = rule.matches(facts)
            except PolicyError:
                raise
            except Exception as exc:  # noqa: BLE001 - a broken rule is a policy bug
                raise PolicyError(f"rule {rule.id!r} failed to evaluate: {exc}") from exc
            elapsed = (time.perf_counter() - rule_start) * 1000
            if not matched:
                continue
            # In dry-run every matched rule is recorded with its would-be
            # action but downgraded to ALLOW, so a policy change can be
            # measured against live traffic before it starts blocking anyone.
            action = Action.ALLOW if self.dry_run else rule.action
            traces.append(
                PolicyTrace(
                    policy_id=self._policy.id,
                    policy_version=self._policy.version,
                    rule_id=rule.id,
                    matched=True,
                    action=action,
                    elapsed_ms=elapsed,
                    note=(f"[dry-run: would {rule.action.value}] " if self.dry_run else "")
                    + (rule.message or rule.description),
                )
            )
            if rule.stop and not self.dry_run:
                break

        if not traces:
            traces.append(
                PolicyTrace(
                    policy_id=self._policy.id,
                    policy_version=self._policy.version,
                    rule_id=None,
                    matched=self._policy.default_action is not Action.ALLOW,
                    action=self._policy.default_action,
                    elapsed_ms=(time.perf_counter() - start) * 1000,
                    note="no rule matched; policy default applied",
                )
            )
        return traces

    def message_for(self, traces: Sequence[PolicyTrace]) -> str | None:
        """The user-facing message of the first blocking rule, if any."""
        for trace in traces:
            if trace.matched and trace.action is Action.BLOCK and trace.note:
                return trace.note
        return None


class OPAEngine:
    """Adapter for an external OPA server.

    The request maps ``facts`` to OPA's ``input`` document and expects the
    policy to return ``{"action": "...", "rule": "...", "message": "..."}`` or a
    list of such objects from the configured decision path. Keeping the
    response contract narrow means the pipeline treats both engines identically.

    OPA is *not* on the hot path by accident: a decision is cached per distinct
    fact-fingerprint for ``cache_ttl_s``, and a failure to reach OPA raises so
    the pipeline's documented policy-unavailable behaviour takes over rather
    than this class silently allowing traffic.
    """

    def __init__(
        self,
        url: str,
        policy: Policy,
        *,
        decision_path: str = "keeper/decision",
        timeout_ms: int = 100,
        cache_ttl_s: float = 5.0,
        client: Any = None,
    ) -> None:
        self.url = url.rstrip("/")
        self._policy = policy
        self.decision_path = decision_path.strip("/")
        self.timeout_ms = timeout_ms
        self.cache_ttl_s = cache_ttl_s
        self._cache: dict[str, tuple[float, list[PolicyTrace]]] = {}
        if client is None:
            from ..transport.client import ControlPlaneClient

            client = ControlPlaneClient(self.url, timeout_ms=timeout_ms)
        self._client = client

    @property
    def policy(self) -> Policy:
        return self._policy

    def evaluate(self, facts: Mapping[str, Any]) -> list[PolicyTrace]:
        key = self._fingerprint(facts)
        cached = self._cache.get(key)
        now = time.monotonic()
        if cached and now - cached[0] < self.cache_ttl_s:
            return cached[1]

        start = time.perf_counter()
        response = self._client.post_json(f"/v1/data/{self.decision_path}", {"input": dict(facts)})
        if not response.ok:
            raise PolicyError(f"OPA returned HTTP {response.status}")
        body = response.json() or {}
        result = body.get("result")
        if result is None:
            raise PolicyError(f"OPA decision path {self.decision_path!r} returned no result")

        elapsed = (time.perf_counter() - start) * 1000
        decisions = result if isinstance(result, list) else [result]
        traces = [self._to_trace(d, elapsed) for d in decisions if isinstance(d, Mapping)]
        if not traces:
            traces = [
                PolicyTrace(
                    policy_id=self._policy.id,
                    policy_version=self._policy.version,
                    rule_id=None,
                    matched=False,
                    action=Action.ALLOW,
                    elapsed_ms=elapsed,
                    note="OPA returned no decision",
                )
            ]
        self._cache[key] = (now, traces)
        if len(self._cache) > 512:
            self._cache.clear()
        return traces

    def _to_trace(self, decision: Mapping[str, Any], elapsed: float) -> PolicyTrace:
        try:
            action = Action(str(decision.get("action", "allow")))
        except ValueError as exc:
            raise PolicyError(f"OPA returned unknown action {decision.get('action')!r}") from exc
        return PolicyTrace(
            policy_id=self._policy.id,
            policy_version=self._policy.version,
            rule_id=decision.get("rule"),
            matched=action is not Action.ALLOW,
            action=action,
            elapsed_ms=elapsed,
            note=str(decision.get("message", "")),
        )

    @staticmethod
    def _fingerprint(facts: Mapping[str, Any]) -> str:
        # The payload is excluded: it is unique per request and would make the
        # cache useless, and content-matching rules belong in detectors anyway.
        relevant = {k: v for k, v in facts.items() if k != "payload"}
        return repr(sorted((k, repr(v)) for k, v in relevant.items()))


def build_engine(policy: Policy, *, engine: str = "embedded", opa_url: str | None = None, dry_run: bool = False) -> PolicyEngine:
    if engine == "embedded":
        return EmbeddedEngine(policy, dry_run=dry_run)
    if engine == "opa":
        if not opa_url:
            raise PolicyError("the OPA engine requires policy.opa_url")
        return OPAEngine(opa_url, policy)
    raise PolicyError(f"unknown policy engine {engine!r}")
