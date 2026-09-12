/**
 * Detector contract and registry.
 *
 * Same contract as the Python SDK: a detector receives a `DetectorInput` and
 * returns a `Finding`. It must not throw for "nothing found", must be side
 * effect free, and must stay inside its latency budget.
 */

import type { DetectorConfig } from "../config";
import type {
  Action,
  Document,
  Finding,
  Message,
  RequestContext,
  Severity,
  Span,
  Stage,
  ToolCall,
  TrustLevel,
} from "../types";
import { ConfigurationError } from "../errors";

export interface DetectorInput {
  payload: string;
  stage: Stage;
  context: RequestContext;
  trust: TrustLevel;
  history: Message[];
  documents: Document[];
  toolCall?: ToolCall;
  grounding: string[];
  metadata: Record<string, unknown>;
}

export function detectorInput(
  payload: string,
  stage: Stage,
  context: RequestContext,
  over: Partial<DetectorInput> = {},
): DetectorInput {
  return {
    payload,
    stage,
    context,
    trust: "user",
    history: context.messages ?? [],
    documents: [],
    grounding: [],
    metadata: {},
    ...over,
  };
}

export abstract class Detector {
  /** Stable identifier: the config key and the name in audit events. */
  abstract readonly name: string;
  /** Pipeline stages this detector is eligible for. */
  abstract readonly stages: Stage[];
  readonly category: string = "unspecified";
  /** Whether the detector can rewrite the payload (redaction). */
  readonly mutates: boolean = false;

  constructor(readonly config: DetectorConfig) {}

  abstract detect(data: DetectorInput): Finding;

  supports(stage: Stage): boolean {
    return this.stages.includes(stage);
  }

  /**
   * Replace matched spans with typed placeholders, right to left so earlier
   * offsets stay valid.
   */
  redact(payload: string, finding: Finding): { payload: string; labels: string[] } {
    if (!finding.spans.length) return { payload, labels: [] };
    const ordered = [...finding.spans].sort((a, b) => b.start - a.start);
    let out = payload;
    const labels: string[] = [];
    for (const span of ordered) {
      out = `${out.slice(0, span.start)}[REDACTED:${span.label}]${out.slice(span.end)}`;
      labels.push(span.label);
    }
    return { payload: out, labels: [...new Set(labels.reverse())] };
  }

  protected clean(summary = "", evidence: Record<string, unknown> = {}): Finding {
    return {
      detector: this.name,
      detected: false,
      score: 0,
      severity: "info",
      action: "allow",
      summary,
      category: this.category,
      spans: [],
      evidence,
      elapsedMs: 0,
    };
  }

  protected hit(options: {
    score: number;
    summary: string;
    severity?: Severity;
    action?: Action;
    spans?: Span[];
    evidence?: Record<string, unknown>;
  }): Finding {
    let action: Action = options.action ?? "block";
    if (this.config.action) {
      const override = this.config.action as Action;
      if (!["allow", "flag", "redact", "challenge", "block"].includes(override)) {
        throw new ConfigurationError(`detector '${this.name}': unknown action override '${override}'`);
      }
      action = override;
    }
    return {
      detector: this.name,
      detected: true,
      score: Math.max(0, Math.min(1, options.score)),
      severity: options.severity ?? "medium",
      action,
      summary: options.summary,
      category: this.category,
      spans: options.spans ?? [],
      evidence: options.evidence ?? {},
      elapsedMs: 0,
    };
  }
}

export type DetectorFactory = (config: DetectorConfig) => Detector;

const REGISTRY = new Map<string, DetectorFactory>();

/**
 * Register a detector factory. Re-registering a name replaces it, which is how
 * an organisation swaps our regex PII detector for their own without forking.
 */
export function register(name: string, factory: DetectorFactory): void {
  REGISTRY.set(name, factory);
}

export function registered(): string[] {
  return [...REGISTRY.keys()].sort();
}

export function build(name: string, config: DetectorConfig): Detector {
  const factory = REGISTRY.get(name);
  if (!factory) {
    throw new ConfigurationError(
      `unknown detector '${name}'; registered detectors: ${registered().join(", ") || "none"}`,
    );
  }
  return factory(config);
}

/** Run a detector and stamp its wall-clock cost onto the finding. */
export function timed(detector: Detector, data: DetectorInput): Finding {
  const start = performance.now();
  const finding = detector.detect(data);
  finding.elapsedMs = performance.now() - start;
  return finding;
}
