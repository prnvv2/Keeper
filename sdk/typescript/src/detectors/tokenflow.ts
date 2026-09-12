/**
 * Token-flow auditing: source-to-sink mediation at semantic boundaries.
 *
 * The Token-Flow Firewall paper's core mechanism. Almost every
 * security-relevant state change in an agent is carried by natural-language
 * tokens crossing a boundary — a tool argument, a memory write, a retrieved
 * passage, an outbound message. Each transfer is reduced to a structured
 * source→sink record and inspected *before* it happens, with the authority of
 * the source and the risk of the sink both in view.
 *
 * A `shell.exec` argument assembled from a web page is a different event from
 * the identical string typed by the authenticated user. Content classifiers
 * cannot see that difference; this can.
 */

import type { DetectorConfig } from "../config";
import type { Finding, RiskTier, Stage, TrustLevel } from "../types";
import { requiredAuthority, trustAuthority } from "../types";
import { Detector, type DetectorInput, register } from "./base";

/** Sinks by blast radius. Keys match as substrings of the tool name. */
export const DEFAULT_SINK_RISK: Record<string, RiskTier> = {
  shell: "critical",
  exec: "critical",
  subprocess: "critical",
  "file.write": "high",
  "file.delete": "critical",
  "fs.": "high",
  "db.write": "high",
  "db.delete": "critical",
  sql: "high",
  "http.post": "high",
  "http.put": "high",
  request: "high",
  email: "high",
  send: "high",
  payment: "critical",
  transfer: "critical",
  purchase: "critical",
  credential: "critical",
  iam: "critical",
  "memory.write": "medium",
  search: "low",
  read: "low",
  get: "low",
  lookup: "low",
};

/** Argument content that is structurally dangerous whatever the sink. */
const DANGEROUS_ARGUMENT: [string, RegExp][] = [
  ["shell_chaining", /(?:;|&&|\|\||\$\(|`)\s*(?:curl|wget|nc|bash|sh|python|powershell|cmd)\b/i],
  ["path_traversal", /\.\.\/\.\.\/|(?:^|[\s'"])\/(?:etc|root|proc|sys)\/|%2e%2e%2f/i],
  ["credential_path", /(?:\.ssh\/|\.aws\/|\.env\b|id_rsa|credentials\.json|\.kube\/config|secrets?\.ya?ml)/i],
  ["destructive", /\b(?:rm\s+-[rf]{1,2}|drop\s+(?:table|database)|truncate\s+table|delete\s+from\s+\w+\s*(?:;|$)|format\s+[a-z]:)\b/i],
  ["sql_injection", /(?:'\s*or\s*'?1'?\s*=\s*'?1|union\s+select|--\s*$)/i],
  ["outbound_exfil", /https?:\/\/(?!localhost|127\.0\.0\.1)[^\s'"]{4,}/i],
];

const RISK_ORDER: Record<RiskTier, number> = { low: 0, medium: 1, high: 2, critical: 3 };

export interface FlowRecord {
  sourceTrust: TrustLevel;
  sink: string;
  sinkRisk: RiskTier;
  boundary: Stage;
  persistent: boolean;
  externalEffect: boolean;
  taintedBy: string[];
}

class TokenFlowDetector extends Detector {
  readonly name = "token_flow";
  readonly stages: Stage[] = ["tool_call", "tool_result", "memory_write", "retrieval"];
  override readonly category = "unsafe_flow";

  /** Boundaries where content flows into context rather than into a sink. */
  static readonly INGRESS_STAGES: Stage[] = ["retrieval", "tool_result"];

  /**
   * The only boundary where the authority gap applies: an action with an
   * effect. Ingress is not an action, and neither is a memory write — the
   * PPMF paper is explicit that external content may be remembered, just
   * never allowed to authorise. Gating storage would block every RAG corpus
   * while leaving the actual laundering path (runtime/memory.ts) untouched.
   */
  static readonly ACTION_STAGES: Stage[] = ["tool_call"];

  private readonly sinkRisk: Record<string, RiskTier>;
  private readonly defaultRisk: RiskTier;
  private readonly challengeInsteadOfBlock: boolean;

  constructor(config: DetectorConfig) {
    super(config);
    this.sinkRisk = { ...DEFAULT_SINK_RISK, ...(config.options.sinkRisk ?? {}) };
    this.defaultRisk = (config.options.defaultRisk as RiskTier) ?? "medium";
    this.challengeInsteadOfBlock = Boolean(config.options.challengeInsteadOfBlock);
  }

  resolveRisk(sink: string): RiskTier {
    const lowered = sink.toLowerCase();
    let best: RiskTier | null = null;
    for (const [prefix, tier] of Object.entries(this.sinkRisk)) {
      if (lowered.includes(prefix) && (best === null || RISK_ORDER[tier] > RISK_ORDER[best])) best = tier;
    }
    return best ?? this.defaultRisk;
  }

  buildRecord(data: DetectorInput): FlowRecord {
    const call = data.toolCall;
    let sink: string;
    let risk: RiskTier;
    if (TokenFlowDetector.INGRESS_STAGES.includes(data.stage)) {
      // Direction, not the presence of a tool object, decides this: a result
      // from http.get is ingress even though the call was egress.
      sink = call ? `model_context<-${call.name}` : "model_context";
      risk = "low";
    } else {
      sink = call ? call.name : data.stage;
      risk = call?.risk ?? this.resolveRisk(sink);
    }
    return {
      sourceTrust: data.trust,
      sink,
      sinkRisk: risk,
      boundary: data.stage,
      persistent: data.stage === "memory_write" || sink.toLowerCase().includes("write"),
      externalEffect: data.stage === "tool_call" && (risk === "high" || risk === "critical"),
      taintedBy: (data.metadata.taintedBy as string[]) ?? [],
    };
  }

  detect(data: DetectorInput): Finding {
    const record = this.buildRecord(data);
    const dangerous = DANGEROUS_ARGUMENT.filter(([, pattern]) => pattern.test(data.payload)).map(([name]) => name);

    const authority = trustAuthority(record.sourceTrust);
    const required = requiredAuthority(record.sinkRisk);
    const authorityGap = required - authority;
    const evidence = { flow: record, dangerousPatterns: dangerous, authority, requiredAuthority: required };

    // 1. Structural danger in the argument: block regardless of source.
    if (dangerous.length && (record.sinkRisk === "high" || record.sinkRisk === "critical")) {
      return this.hit({
        score: 1,
        summary: `dangerous argument pattern(s) ${dangerous.join(", ")} flowing into ${record.sinkRisk}-risk sink '${record.sink}'`,
        severity: "critical",
        action: "block",
        evidence,
      });
    }

    // 2. Authority gap at an action boundary — the case a content classifier
    //    cannot see, because the text itself may be entirely benign.
    if (authorityGap > 0 && TokenFlowDetector.ACTION_STAGES.includes(record.boundary)) {
      return this.hit({
        score: Math.min(1, 0.6 + 0.15 * authorityGap),
        summary: `${record.sourceTrust}-authority content is driving a ${record.sinkRisk}-risk transfer into '${record.sink}'`,
        severity: record.sinkRisk === "critical" ? "critical" : "high",
        action: this.challengeInsteadOfBlock ? "challenge" : "block",
        evidence: { ...evidence, authorityGap },
      });
    }

    // 3. Permitted, but worth recording.
    if (dangerous.length) {
      return this.hit({
        score: 0.4,
        summary: `suspicious argument pattern(s) ${dangerous.join(", ")} on low-risk sink '${record.sink}'`,
        severity: "low",
        action: "flag",
        evidence,
      });
    }
    if (record.persistent && trustAuthority(record.sourceTrust) <= trustAuthority("retrieved")) {
      return this.hit({
        score: 0.35,
        summary: `${record.sourceTrust} content persisted to '${record.sink}'`,
        severity: "low",
        action: "flag",
        evidence: { ...evidence, escalate: true },
      });
    }
    return this.clean(`flow into '${record.sink}' within authority`, evidence);
  }
}

register("token_flow", (config) => new TokenFlowDetector(config));
export { TokenFlowDetector };
