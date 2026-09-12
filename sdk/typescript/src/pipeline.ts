/**
 * The enforcement pipeline.
 *
 * Evaluates one stage: run the detectors that apply, evaluate policy against
 * what they found, combine by escalation, apply redaction if that is the
 * outcome, emit exactly one audit event, return a decision.
 *
 * Detectors run sequentially and synchronously. The built-ins are regex and
 * arithmetic over a few kilobytes — tens of microseconds each — so there is
 * nothing to gain from concurrency and a great deal of predictability to lose.
 * The stage budget is real: once the accumulated cost exceeds it, remaining
 * detectors are skipped and the fail mode is engaged and recorded on the
 * decision. Detection depth degrades under load; latency does not grow without
 * bound.
 */

import { FAIL_CLOSED, FAIL_OPEN, type KeeperConfig } from "./config";
import {
  DEFAULT_INPUT_DETECTORS,
  DEFAULT_OUTPUT_DETECTORS,
  DEFAULT_RUNTIME_DETECTORS,
  build as buildDetector,
  detectorInput,
  type Detector,
  type DetectorInput,
} from "./detectors";
import { PolicyError } from "./errors";
import type { EventBuilder, FanoutSink, Metrics } from "./observability";
import { buildFacts, type PolicyProvider } from "./policy";
import type { TelemetryShipper } from "./transport";
import {
  combineDecision,
  type Action,
  type AuditEvent,
  type Decision,
  type Document,
  type Finding,
  type Message,
  type PolicyTrace,
  type RequestContext,
  type Stage,
  type ToolCall,
  type TrustLevel,
} from "./types";

const STAGE_DEFAULTS: Partial<Record<Stage, readonly string[]>> = {
  input: DEFAULT_INPUT_DETECTORS,
  output: DEFAULT_OUTPUT_DETECTORS,
  stream: ["secret_leakage", "banned_topics", "prompt_injection"],
  tool_call: DEFAULT_RUNTIME_DETECTORS,
  tool_result: DEFAULT_RUNTIME_DETECTORS,
  retrieval: ["prompt_injection", "authority_claim", "secrets", "token_flow"],
  memory_write: ["token_flow", "prompt_injection", "secrets", "pii"],
  memory_read: [],
};

const PROMPT_STAGES = new Set<Stage>(["input", "retrieval", "tool_call", "tool_result", "memory_write"]);
const RESPONSE_STAGES = new Set<Stage>(["output", "stream"]);

export interface EvaluateOptions {
  trust?: TrustLevel;
  history?: Message[];
  documents?: Document[];
  toolCall?: ToolCall;
  grounding?: string[];
  detectors?: readonly string[];
  metadata?: Record<string, unknown>;
  emit?: boolean;
  latencyMs?: number;
  tokensIn?: number;
  tokensOut?: number;
}

export class Pipeline {
  private readonly detectors = new Map<string, Detector>();

  constructor(
    readonly config: KeeperConfig,
    private readonly policy: PolicyProvider,
    private readonly metrics: Metrics,
    private readonly events: EventBuilder,
    private readonly sink: FanoutSink,
    private readonly shipper?: TelemetryShipper,
    extraDetectors: Detector[] = [],
    private readonly onEvent?: (event: AuditEvent) => void,
  ) {
    this.buildDetectors(extraDetectors);
  }

  private buildDetectors(extra: Detector[]): void {
    const overrides = this.policy.policy.detectorOverrides;
    for (const [name, detectorConfig] of Object.entries(this.config.detectors)) {
      if (!detectorConfig.enabled) continue;
      let merged = detectorConfig;
      const override = overrides[name];
      if (override) {
        // A policy bundle may tune a detector but cannot enable one the
        // operator disabled locally: the control plane must not be able to
        // switch on a detector inside someone else's process.
        const allowed = ["threshold", "action", "timeoutMs", "failMode"] as const;
        merged = { ...detectorConfig };
        for (const key of allowed) {
          if (key in override) (merged as any)[key] = override[key];
        }
        if (override.options) merged.options = { ...detectorConfig.options, ...(override.options as object) };
      }
      try {
        this.detectors.set(name, buildDetector(name, merged));
      } catch (error) {
        throw new PolicyError(`could not build detector '${name}': ${String(error)}`);
      }
    }
    for (const detector of extra) this.detectors.set(detector.name, detector);
  }

  detector(name: string): Detector | undefined {
    return this.detectors.get(name);
  }

  get detectorNames(): string[] {
    return [...this.detectors.keys()];
  }

  evaluate(stage: Stage, payload: string, context: RequestContext, options: EvaluateOptions = {}): Decision {
    const start = performance.now();
    const names = options.detectors ?? STAGE_DEFAULTS[stage] ?? [];
    const budgetMs = this.budgetFor(stage);
    const trust = options.trust ?? "user";

    const data = detectorInput(payload, stage, context, {
      trust,
      history: options.history ?? context.messages,
      documents: options.documents ?? [],
      toolCall: options.toolCall,
      grounding: options.grounding ?? [],
      metadata: options.metadata ?? {},
    });

    const { findings, failMode: detectorFailMode } = this.runDetectors(names, data, budgetMs);
    const { traces, failMode: policyFailMode } = this.evaluatePolicy(stage, context, findings, payload, trust, options.toolCall);
    const failMode = detectorFailMode ?? policyFailMode;

    const decision = combineDecision(stage, context.correlationId, findings, traces, payload);
    decision.originalPayload = payload;
    decision.failModeEngaged = failMode;

    if (failMode === FAIL_CLOSED && decision.action === "allow") {
      // Fail-closed engaged but nothing fired: the reason we are here is that
      // we could not evaluate properly, so do not report a clean allow.
      decision.action = "block";
      decision.findings.push({
        detector: "pipeline",
        detected: true,
        score: 1,
        severity: "high",
        action: "block",
        summary: "evaluation could not complete and this stage is configured fail-closed",
        category: "firewall_internal",
        spans: [],
        evidence: {},
        elapsedMs: 0,
      });
    }

    if (decision.action === "redact") decision.payload = this.applyRedaction(payload, decision.findings);

    if (this.config.monitorOnly && (decision.action === "block" || decision.action === "challenge")) {
      // Monitor-only is how a team rolls the firewall out: everything is
      // detected, scored, logged and dashboarded, nothing is stopped.
      decision.payload = payload;
      for (const finding of decision.findings) {
        if (finding.detected) finding.evidence = { ...finding.evidence, monitor_only: true };
      }
      decision.action = "flag";
    }

    decision.elapsedMs = performance.now() - start;
    this.recordMetrics(stage, decision);

    if (options.emit !== false) {
      this.emit(decision, context, {
        prompt: PROMPT_STAGES.has(stage) ? payload : null,
        response: RESPONSE_STAGES.has(stage) ? payload : null,
        latencyMs: options.latencyMs ?? decision.elapsedMs,
        tokensIn: options.tokensIn ?? null,
        tokensOut: options.tokensOut ?? null,
        extraTags: this.stageTags(trust, options.toolCall, options.documents ?? []),
      });
    }
    return decision;
  }

  private budgetFor(stage: Stage): number {
    if (stage === "input") return this.config.inputBudgetMs;
    if (stage === "output" || stage === "stream") return this.config.outputBudgetMs;
    return this.config.runtime.timeoutMs;
  }

  private runDetectors(
    names: readonly string[],
    data: DetectorInput,
    budgetMs: number,
  ): { findings: Finding[]; failMode: string | null } {
    const findings: Finding[] = [];
    let failMode: string | null = null;
    let spent = 0;

    for (const name of names) {
      const detector = this.detectors.get(name);
      if (!detector || !detector.supports(data.stage)) continue;

      if (spent >= budgetMs) {
        const closed = this.config.failMode === FAIL_CLOSED;
        findings.push({
          detector: name,
          detected: closed,
          score: closed ? 1 : 0,
          severity: "medium",
          action: closed ? "block" : "flag",
          summary: `skipped: stage budget exhausted (${spent.toFixed(1)}ms of ${budgetMs}ms)`,
          category: "firewall_internal",
          spans: [],
          evidence: {},
          elapsedMs: 0,
          error: "budget_exhausted",
        });
        failMode = closed ? FAIL_CLOSED : (failMode ?? FAIL_OPEN);
        continue;
      }

      const detectorStart = performance.now();
      try {
        const finding = detector.detect(data);
        const elapsed = performance.now() - detectorStart;
        spent += elapsed;
        finding.elapsedMs = elapsed;
        findings.push(finding);

        this.metrics.observe("detector_latency_ms", elapsed, { detector: name });
        this.metrics.inc("detector_runs_total", 1, {
          detector: name,
          stage: data.stage,
          outcome: finding.detected ? "detected" : "clean",
        });
        if (finding.detected) {
          this.metrics.inc("detector_hits_total", 1, {
            detector: name,
            severity: finding.severity,
            action: finding.action,
          });
          // Once something is definitively blocked the remaining detectors
          // cannot change the outcome; their cost is pure latency on a
          // request that is already refused.
          if (finding.action === "block" && finding.score >= 0.99) break;
        }
      } catch (error) {
        const elapsed = performance.now() - detectorStart;
        spent += elapsed;
        const mode = detector.config.failMode;
        const closed = mode === FAIL_CLOSED;
        failMode = failMode === FAIL_CLOSED || closed ? FAIL_CLOSED : FAIL_OPEN;
        findings.push({
          detector: name,
          detected: closed,
          score: closed ? 1 : 0,
          severity: closed ? "high" : "low",
          action: closed ? "block" : "flag",
          summary: closed
            ? `detector '${name}' failed and is configured fail-${mode}`
            : `detector '${name}' failed; continuing (fail-open)`,
          category: "firewall_internal",
          spans: [],
          evidence: {},
          elapsedMs: elapsed,
          error: String(error),
        });
        this.metrics.inc("detector_errors_total", 1, { detector: name, fail_mode: mode });
        this.metrics.inc("detector_runs_total", 1, { detector: name, stage: data.stage, outcome: "error" });
      }
    }
    return { findings, failMode };
  }

  private evaluatePolicy(
    stage: Stage,
    context: RequestContext,
    findings: Finding[],
    payload: string,
    trust: TrustLevel,
    toolCall?: ToolCall,
  ): { traces: PolicyTrace[]; failMode: string | null } {
    const engine = this.policy.engine;
    const facts = buildFacts(stage, context, findings, { payload, trust, toolCall });
    const start = performance.now();
    try {
      const traces = engine.evaluate(facts);
      this.metrics.observe("policy_latency_ms", performance.now() - start, { policy_id: engine.policy.id });
      for (const trace of traces) {
        this.metrics.inc("policy_evaluations_total", 1, { policy_id: trace.policyId, action: trace.action });
      }
      return { traces, failMode: null };
    } catch (error) {
      const elapsed = performance.now() - start;
      this.metrics.observe("policy_latency_ms", elapsed, { policy_id: engine.policy.id });
      const mode = this.config.failMode;
      return {
        traces: [
          {
            policyId: engine.policy.id,
            policyVersion: engine.policy.version,
            ruleId: null,
            matched: mode === FAIL_CLOSED,
            action: mode === FAIL_CLOSED ? "block" : "flag",
            elapsedMs: elapsed,
            note: `policy evaluation failed (${String(error)}); fail-${mode}`,
          },
        ],
        failMode: mode,
      };
    }
  }

  private applyRedaction(payload: string, findings: Finding[]): string {
    let out = payload;
    for (const finding of findings) {
      if (!finding.detected || !finding.spans.length) continue;
      const detector = this.detectors.get(finding.detector);
      if (!detector?.mutates) continue;
      out = detector.redact(out, finding).payload;
    }
    return out;
  }

  private recordMetrics(stage: Stage, decision: Decision): void {
    this.metrics.observe("pipeline_latency_ms", decision.elapsedMs, { stage });
    this.metrics.inc("requests_total", 1, { stage, action: decision.action });
    if (decision.action === "block") {
      const reason = decision.findings.find((f) => f.detected);
      this.metrics.inc("blocked_total", 1, { stage, category: reason?.category ?? "policy" });
    }
  }

  emit(decision: Decision, context: RequestContext, options: Parameters<EventBuilder["build"]>[2] = {}): void {
    this.events.policyVersion = `${this.policy.policy.id}@${this.policy.policy.version}`;
    const event = this.events.build(decision, context, options);
    this.sink.emit(event);
    this.shipper?.emit(event);
    if (this.onEvent) {
      try {
        this.onEvent(event);
      } catch {
        /* listeners must not break requests */
      }
    }
  }

  private stageTags(trust: TrustLevel, toolCall?: ToolCall, documents: Document[] = []): Record<string, unknown> {
    const tags: Record<string, unknown> = { trust };
    if (toolCall) {
      tags.tool = toolCall.name;
      tags.tool_call_id = toolCall.callId;
      if (toolCall.agent) tags.agent = toolCall.agent;
    }
    if (documents.length) tags.document_sources = [...new Set(documents.map((d) => d.source))].slice(0, 10);
    return tags;
  }
}

export type { Action };
