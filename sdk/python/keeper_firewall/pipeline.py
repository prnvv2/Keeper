"""The enforcement pipeline.

One class, :class:`Pipeline`, evaluates a single stage: run the detectors that
apply, evaluate policy against what they found, combine everything by
escalation, apply redaction if that is the outcome, emit exactly one audit
event, and return a :class:`~keeper_firewall.types.Decision`.

Three design decisions worth stating, because they are the ones a reviewer will
ask about:

**Detector execution is sequential by default.** The built-in detectors are
regex and arithmetic over a few kilobytes — tens of microseconds each. A thread
pool would cost more in scheduling than it saves, and it would make the latency
profile harder to reason about. Detectors whose configured ``timeout_ms``
exceeds :data:`THREADED_TIMEOUT_MS` (network-bound ones, chiefly
``llm_classifier``) are run on a pool with a real timeout instead.

**A detector that blows its timeout cannot be killed.** Python has no safe way
to interrupt a running function, so an over-budget threaded detector is
*abandoned*: we stop waiting, apply its fail mode, and let the thread finish
into the void. Pretending otherwise would be worse. The pool is bounded, so a
persistently hanging detector degrades to "this detector no longer contributes"
rather than exhausting the process.

**The stage budget is a real budget.** Once the accumulated cost of a stage
exceeds ``input_budget_ms``/``output_budget_ms``, remaining detectors are
skipped and the pipeline fail mode is engaged and recorded on the decision.
Detection depth degrades under load; latency does not grow without bound.
"""

from __future__ import annotations

import concurrent.futures
import time
from typing import Any, Callable, Mapping, Sequence

from .config import FAIL_CLOSED, FAIL_OPEN, KeeperConfig
from .detectors import (
    DEFAULT_INPUT_DETECTORS,
    DEFAULT_OUTPUT_DETECTORS,
    DEFAULT_RUNTIME_DETECTORS,
    Detector,
    DetectorInput,
)
from .detectors import build as build_detector
from .errors import DetectorError, PolicyError
from .observability.events import EventBuilder, FanoutSink
from .observability.metrics import Metrics
from .policy.engine import build_facts
from .policy.loader import PolicyProvider
from .risk import RiskAssessment, RiskEngine
from .taxonomy import THREATS, annotate
from .types import (
    Action,
    Decision,
    Document,
    Finding,
    Message,
    PolicyTrace,
    RequestContext,
    Severity,
    Stage,
    ToolCall,
    TrustLevel,
)

#: Detectors with a configured timeout above this are run on a thread pool.
THREADED_TIMEOUT_MS = 400

STAGE_DEFAULTS: dict[Stage, tuple[str, ...]] = {
    Stage.INPUT: DEFAULT_INPUT_DETECTORS,
    Stage.OUTPUT: DEFAULT_OUTPUT_DETECTORS,
    Stage.STREAM: ("secret_leakage", "system_prompt_leakage", "unsafe_output", "banned_topics", "prompt_injection"),
    Stage.TOOL_CALL: DEFAULT_RUNTIME_DETECTORS,
    Stage.TOOL_RESULT: DEFAULT_RUNTIME_DETECTORS,
    Stage.RETRIEVAL: ("prompt_injection", "authority_claim", "secrets", "token_flow"),
    Stage.MEMORY_WRITE: ("token_flow", "prompt_injection", "secrets", "pii"),
    Stage.MEMORY_READ: (),
    Stage.TOOL_DEFINITION: ("tool_poisoning", "secrets"),
}


class Pipeline:
    """Evaluates stages and emits audit events."""

    def __init__(
        self,
        config: KeeperConfig,
        *,
        policy: PolicyProvider,
        metrics: Metrics,
        events: EventBuilder,
        sink: FanoutSink,
        shipper: Any = None,
        extra_detectors: Sequence[Detector] = (),
        on_event: Callable[[Any], None] | None = None,
    ) -> None:
        self.config = config
        self.policy = policy
        self.metrics = metrics
        self.events = events
        self.sink = sink
        self.shipper = shipper
        self.on_event = on_event

        self._detectors: dict[str, Detector] = {}
        self._build_detectors(extra_detectors)
        self._pool = concurrent.futures.ThreadPoolExecutor(
            max_workers=4, thread_name_prefix="keeper-detector"
        )

    # -- construction ------------------------------------------------------

    def _build_detectors(self, extra: Sequence[Detector]) -> None:
        overrides = self.policy.policy.detector_overrides
        for name, det_config in self.config.detectors.items():
            if not det_config.enabled:
                continue
            merged = det_config
            if name in overrides:
                # A policy bundle may tune a detector, but it cannot enable one
                # the operator disabled locally: the control plane must not be
                # able to switch on a detector inside someone's process.
                import dataclasses

                merged = dataclasses.replace(det_config, **{
                    k: v for k, v in overrides[name].items()
                    if k in {"threshold", "action", "timeout_ms", "fail_mode"}
                })
                if "options" in overrides[name]:
                    merged.options = {**det_config.options, **overrides[name]["options"]}
            try:
                self._detectors[name] = build_detector(name, merged)
            except Exception as exc:  # noqa: BLE001 - surfaced at startup, not per-request
                raise PolicyError(f"could not build detector {name!r}: {exc}") from exc
        for det in extra:
            self._detectors[det.name] = det

    def detector(self, name: str) -> Detector | None:
        return self._detectors.get(name)

    @property
    def detector_names(self) -> tuple[str, ...]:
        return tuple(self._detectors)

    # -- evaluation --------------------------------------------------------

    def evaluate(
        self,
        stage: Stage,
        payload: str,
        context: RequestContext,
        *,
        trust: TrustLevel = TrustLevel.USER,
        history: Sequence[Message] = (),
        documents: Sequence[Document] = (),
        tool_call: ToolCall | None = None,
        grounding: Sequence[str] = (),
        detectors: Sequence[str] | None = None,
        metadata: Mapping[str, Any] | None = None,
        emit: bool = True,
        latency_ms: float = 0.0,
        tokens_in: int | None = None,
        tokens_out: int | None = None,
    ) -> Decision:
        """Run one pipeline stage and return its decision."""
        start = time.perf_counter()
        names = list(detectors if detectors is not None else STAGE_DEFAULTS.get(stage, ()))
        budget_ms = self._budget_for(stage)

        data = DetectorInput(
            payload=payload,
            stage=stage,
            context=context,
            trust=trust,
            history=history or context.messages,
            documents=documents,
            tool_call=tool_call,
            grounding=grounding,
            metadata=dict(metadata or {}),
        )

        findings, fail_mode = self._run_detectors(names, data, budget_ms)
        # Name every finding in OWASP terms, then place the stage on the risk
        # matrix *before* policy runs, so rules can match on threat and band.
        annotate(findings, stage)
        risk_engine = RiskEngine(self.policy.policy.risk)
        risk = risk_engine.assess(findings, stage, tool_call=tool_call, application=context.application)
        traces, policy_fail = self._evaluate_policy(stage, context, findings, payload, trust, tool_call, risk)
        fail_mode = fail_mode or policy_fail
        risk_trace = risk_engine.trace(
            risk,
            policy_id=self.policy.policy.id,
            policy_version=self.policy.policy.version,
            dry_run=bool(getattr(self.policy.engine, "dry_run", False)),
        )
        if risk_trace is not None:
            traces.append(risk_trace)

        decision = Decision.combine(stage, context.correlation_id, findings, traces, payload=payload)
        decision.original_payload = payload
        decision.fail_mode_engaged = fail_mode
        decision.risk = risk

        if fail_mode == FAIL_CLOSED and decision.action is Action.ALLOW:
            # Fail-closed engaged but nothing fired: the *reason* we are here is
            # that we could not evaluate properly, so do not report a clean
            # allow. Block and say why.
            decision.action = Action.BLOCK
            decision.findings = decision.findings + (
                Finding(
                    detector="pipeline",
                    detected=True,
                    score=1.0,
                    severity=Severity.HIGH,
                    action=Action.BLOCK,
                    summary="evaluation could not complete and this stage is configured fail-closed",
                    category="firewall_internal",
                ),
            )

        if decision.action is Action.REDACT:
            decision.payload = self._apply_redaction(payload, decision.findings)

        if self.config.monitor_only and decision.action in (Action.BLOCK, Action.CHALLENGE):
            # Monitor-only is how a team rolls the firewall out: everything is
            # detected, scored, logged and dashboarded, nothing is stopped.
            decision.payload = payload
            decision.findings = tuple(
                f if not f.detected else _tagged(f, "monitor_only") for f in decision.findings
            )
            decision.action = Action.FLAG

        decision.elapsed_ms = (time.perf_counter() - start) * 1000
        self._record_metrics(stage, decision, context)

        if emit:
            self.emit(
                decision,
                context,
                prompt=payload if stage in _PROMPT_STAGES else None,
                response=payload if stage in _RESPONSE_STAGES else None,
                latency_ms=latency_ms or decision.elapsed_ms,
                tokens_in=tokens_in,
                tokens_out=tokens_out,
                extra_tags=self._stage_tags(trust, tool_call, documents),
            )
        return decision

    def _budget_for(self, stage: Stage) -> float:
        if stage is Stage.INPUT:
            return float(self.config.input_budget_ms)
        if stage in (Stage.OUTPUT, Stage.STREAM):
            return float(self.config.output_budget_ms)
        return float(self.config.runtime.timeout_ms)

    # -- detectors ---------------------------------------------------------

    def _run_detectors(
        self, names: Sequence[str], data: DetectorInput, budget_ms: float
    ) -> tuple[list[Finding], str | None]:
        findings: list[Finding] = []
        fail_mode: str | None = None
        spent = 0.0

        for name in names:
            detector = self._detectors.get(name)
            if detector is None or not detector.supports(data.stage):
                continue

            if spent >= budget_ms:
                findings.append(self._budget_finding(name, spent, budget_ms))
                if self.config.fail_mode == FAIL_CLOSED:
                    fail_mode = FAIL_CLOSED
                else:
                    fail_mode = fail_mode or FAIL_OPEN
                continue

            start = time.perf_counter()
            try:
                finding = self._invoke(detector, data, budget_ms - spent)
            except Exception as exc:  # noqa: BLE001 - converted to a fail-mode finding
                elapsed = (time.perf_counter() - start) * 1000
                spent += elapsed
                mode = detector.config.fail_mode
                fail_mode = FAIL_CLOSED if FAIL_CLOSED in (fail_mode, mode) else FAIL_OPEN
                findings.append(self._error_finding(detector, exc, elapsed, mode))
                self.metrics.inc("detector_errors_total", detector=name, fail_mode=mode)
                self.metrics.inc("detector_runs_total", detector=name, stage=data.stage.value, outcome="error")
                continue

            elapsed = (time.perf_counter() - start) * 1000
            spent += elapsed
            finding.elapsed_ms = elapsed
            findings.append(finding)

            self.metrics.observe("detector_latency_ms", elapsed, detector=name)
            self.metrics.inc(
                "detector_runs_total",
                detector=name,
                stage=data.stage.value,
                outcome="detected" if finding.detected else "clean",
            )
            if finding.detected:
                self.metrics.inc(
                    "detector_hits_total",
                    detector=name,
                    severity=finding.severity.value,
                    action=finding.action.value,
                )
                # Short-circuit: once something is definitively blocked, the
                # remaining detectors cannot change the outcome and their cost
                # is pure latency on a request that is already refused.
                if finding.action is Action.BLOCK and finding.score >= 0.99:
                    break

        return findings, fail_mode

    def _invoke(self, detector: Detector, data: DetectorInput, remaining_ms: float) -> Finding:
        timeout_ms = min(detector.config.timeout_ms, max(1.0, remaining_ms))
        if detector.config.timeout_ms < THREADED_TIMEOUT_MS:
            return detector.detect(data)
        future = self._pool.submit(detector.detect, data)
        try:
            return future.result(timeout=timeout_ms / 1000)
        except concurrent.futures.TimeoutError as exc:
            future.cancel()  # best effort; a started thread keeps running
            raise DetectorError(detector.name, f"timed out after {timeout_ms:.0f}ms") from exc

    def _error_finding(self, detector: Detector, exc: BaseException, elapsed: float, mode: str) -> Finding:
        failed_closed = mode == FAIL_CLOSED
        return Finding(
            detector=detector.name,
            detected=failed_closed,
            score=1.0 if failed_closed else 0.0,
            severity=Severity.HIGH if failed_closed else Severity.LOW,
            action=Action.BLOCK if failed_closed else Action.FLAG,
            summary=(
                f"detector {detector.name!r} failed and is configured fail-{mode}"
                if failed_closed
                else f"detector {detector.name!r} failed; continuing (fail-open)"
            ),
            category="firewall_internal",
            elapsed_ms=elapsed,
            error=str(exc),
        )

    def _budget_finding(self, name: str, spent: float, budget: float) -> Finding:
        closed = self.config.fail_mode == FAIL_CLOSED
        return Finding(
            detector=name,
            detected=closed,
            score=1.0 if closed else 0.0,
            severity=Severity.MEDIUM,
            action=Action.BLOCK if closed else Action.FLAG,
            summary=f"skipped: stage budget exhausted ({spent:.1f}ms of {budget:.0f}ms)",
            category="firewall_internal",
            error="budget_exhausted",
        )

    # -- policy ------------------------------------------------------------

    def _evaluate_policy(
        self,
        stage: Stage,
        context: RequestContext,
        findings: Sequence[Finding],
        payload: str,
        trust: TrustLevel,
        tool_call: ToolCall | None,
        risk: RiskAssessment | None = None,
    ) -> tuple[list[PolicyTrace], str | None]:
        engine = self.policy.engine
        facts = build_facts(
            stage, context, findings, payload=payload, trust=trust, tool_call=tool_call, risk=risk
        )
        start = time.perf_counter()
        try:
            traces = engine.evaluate(facts)
        except Exception as exc:  # noqa: BLE001 - policy failure is a fail-mode event
            elapsed = (time.perf_counter() - start) * 1000
            self.metrics.observe("policy_latency_ms", elapsed, policy_id=engine.policy.id)
            mode = self.config.fail_mode
            return (
                [
                    PolicyTrace(
                        policy_id=engine.policy.id,
                        policy_version=engine.policy.version,
                        rule_id=None,
                        matched=mode == FAIL_CLOSED,
                        action=Action.BLOCK if mode == FAIL_CLOSED else Action.FLAG,
                        elapsed_ms=elapsed,
                        note=f"policy evaluation failed ({exc}); fail-{mode}",
                    )
                ],
                mode,
            )

        elapsed = (time.perf_counter() - start) * 1000
        self.metrics.observe("policy_latency_ms", elapsed, policy_id=engine.policy.id)
        for trace in traces:
            self.metrics.inc(
                "policy_evaluations_total", policy_id=trace.policy_id, action=trace.action.value
            )
        return traces, None

    # -- effects -----------------------------------------------------------

    def _apply_redaction(self, payload: str, findings: Sequence[Finding]) -> str:
        out = payload
        for finding in findings:
            if not finding.detected or not finding.spans:
                continue
            detector = self._detectors.get(finding.detector)
            if detector is None or not detector.mutates:
                continue
            out, _labels = detector.redact(out, finding)
        return out

    def _record_metrics(self, stage: Stage, decision: Decision, context: RequestContext) -> None:
        self.metrics.observe("pipeline_latency_ms", decision.elapsed_ms, stage=stage.value)
        self.metrics.inc("requests_total", stage=stage.value, action=decision.action.value)
        for finding in decision.findings:
            for tid in finding.threats:
                threat = THREATS[tid]
                self.metrics.inc(
                    "threat_detections_total",
                    threat=tid,
                    framework=threat.framework,
                    stage=stage.value,
                    action=decision.action.value,
                )
        if decision.risk is not None and decision.risk.score:
            self.metrics.observe("risk_score", float(decision.risk.score), stage=stage.value)
            self.metrics.inc("risk_decisions_total", band=decision.risk.band.value, stage=stage.value)
        if decision.action is Action.BLOCK:
            reasons = decision.reasons
            self.metrics.inc(
                "blocked_total",
                stage=stage.value,
                category=reasons[0].category if reasons else "policy",
            )

    def emit(self, decision: Decision, context: RequestContext, **kwargs: Any) -> None:
        """Build and dispatch the audit event for a decision."""
        self.events.policy_version = self.policy.policy.ref
        event = self.events.build(decision, context, **kwargs)
        self.sink.emit(event)
        if self.shipper is not None:
            self.shipper.emit(event)
        if self.on_event is not None:
            try:
                self.on_event(event)
            except Exception:  # noqa: BLE001 - listeners must not break requests
                pass

    @staticmethod
    def _stage_tags(
        trust: TrustLevel, tool_call: ToolCall | None, documents: Sequence[Document]
    ) -> dict[str, Any]:
        tags: dict[str, Any] = {"trust": trust.value}
        if tool_call:
            tags["tool"] = tool_call.name
            tags["tool_call_id"] = tool_call.call_id
            if tool_call.agent:
                tags["agent"] = tool_call.agent
        if documents:
            tags["document_sources"] = sorted({d.source for d in documents})[:10]
        return tags

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


def _tagged(finding: Finding, note: str) -> Finding:
    evidence = dict(finding.evidence)
    evidence[note] = True
    return Finding(
        detector=finding.detector,
        detected=finding.detected,
        score=finding.score,
        severity=finding.severity,
        action=finding.action,
        summary=finding.summary,
        category=finding.category,
        spans=finding.spans,
        evidence=evidence,
        elapsed_ms=finding.elapsed_ms,
        error=finding.error,
        threats=finding.threats,
    )


_PROMPT_STAGES = frozenset(
    {Stage.INPUT, Stage.RETRIEVAL, Stage.TOOL_CALL, Stage.TOOL_RESULT, Stage.MEMORY_WRITE, Stage.TOOL_DEFINITION}
)
_RESPONSE_STAGES = frozenset({Stage.OUTPUT, Stage.STREAM})
