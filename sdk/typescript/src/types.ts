/**
 * Core data model — the TypeScript mirror of `keeper_firewall.types`.
 *
 * The two SDKs are ports of one design, not two designs that happen to share a
 * name. The audit event schema, the action and trust ladders, and the
 * escalation combination rule are identical by construction, because the
 * control plane cannot tell (and must not care) which language produced an
 * event. Where the languages differ it is in idiom only: discriminated unions
 * and const objects here, enums and dataclasses there.
 */

export const SCHEMA_VERSION = "keeper.audit.v1";
export const SDK_VERSION = "0.1.0";

export type Action = "allow" | "flag" | "redact" | "challenge" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export type Stage =
  | "input"
  | "output"
  | "stream"
  | "tool_call"
  | "tool_result"
  | "retrieval"
  | "memory_write"
  | "memory_read"
  | "access";

export type TrustLevel = "system" | "user_confirmed" | "user" | "tool" | "retrieved" | "external";
export type RiskTier = "low" | "medium" | "high" | "critical";

const ACTION_SEVERITY: Record<Action, number> = {
  allow: 0,
  flag: 1,
  redact: 2,
  challenge: 3,
  block: 4,
};

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

/**
 * Authority ladder. Consolidation, summarisation and paraphrase may move
 * content between records but must never move it *up* this ladder — see
 * `runtime/memory.ts`.
 */
const TRUST_AUTHORITY: Record<TrustLevel, number> = {
  system: 5,
  user_confirmed: 4,
  user: 3,
  tool: 2,
  retrieved: 1,
  external: 0,
};

const RISK_REQUIRED_AUTHORITY: Record<RiskTier, number> = {
  low: TRUST_AUTHORITY.retrieved,
  medium: TRUST_AUTHORITY.user,
  high: TRUST_AUTHORITY.user_confirmed,
  critical: TRUST_AUTHORITY.user_confirmed,
};

export const actionSeverity = (action: Action): number => ACTION_SEVERITY[action];
export const severityRank = (severity: Severity): number => SEVERITY_RANK[severity];
export const trustAuthority = (trust: TrustLevel): number => TRUST_AUTHORITY[trust];
export const requiredAuthority = (risk: RiskTier): number => RISK_REQUIRED_AUTHORITY[risk];
export const escalates = (candidate: Action, current: Action): boolean =>
  ACTION_SEVERITY[candidate] > ACTION_SEVERITY[current];

export function newId(prefix = ""): string {
  const bytes = new Uint8Array(16);
  globalThis.crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  return prefix ? `${prefix}${hex}` : hex;
}

export const nowMs = (): number => Date.now();

export interface Principal {
  id: string;
  roles: string[];
  tenant?: string;
  attributes?: Record<string, unknown>;
  authenticated: boolean;
  authMethod?: string;
}

export const anonymous = (): Principal => ({
  id: "anonymous",
  roles: ["anonymous"],
  authenticated: false,
});

export interface Message {
  role: string;
  content: string;
  name?: string;
  trust?: TrustLevel;
}

export interface Span {
  start: number;
  end: number;
  label: string;
  snippet?: string;
}

export interface Finding {
  detector: string;
  detected: boolean;
  score: number;
  severity: Severity;
  action: Action;
  summary: string;
  category: string;
  spans: Span[];
  evidence: Record<string, unknown>;
  elapsedMs: number;
  error?: string | null;
}

export interface PolicyTrace {
  policyId: string;
  policyVersion: string;
  ruleId: string | null;
  matched: boolean;
  action: Action;
  elapsedMs: number;
  note: string;
}

export interface Decision {
  action: Action;
  stage: Stage;
  correlationId: string;
  findings: Finding[];
  policyTraces: PolicyTrace[];
  payload?: string;
  originalPayload?: string;
  elapsedMs: number;
  failModeEngaged?: string | null;
}

export const isBlocked = (decision: Decision): boolean => decision.action === "block";

export function decisionReasons(decision: Decision): Finding[] {
  return decision.findings
    .filter((f) => f.detected)
    .sort((a, b) => actionSeverity(b.action) - actionSeverity(a.action) || b.score - a.score);
}

export function decisionSeverity(decision: Decision): Severity {
  const fired = decision.findings.filter((f) => f.detected);
  if (!fired.length) return "info";
  return fired.reduce<Severity>((worst, f) => (severityRank(f.severity) > severityRank(worst) ? f.severity : worst), "info");
}

/**
 * Escalation combination: the most severe signal wins outright.
 *
 * Identical to the Python implementation, and for the same reason — averaging
 * independent safety verdicts lets a quorum of "fine" out-vote one confident
 * "this is an attack".
 */
export function combineDecision(
  stage: Stage,
  correlationId: string,
  findings: Finding[],
  policyTraces: PolicyTrace[] = [],
  payload?: string,
): Decision {
  let action: Action = "allow";
  for (const finding of findings) {
    if (finding.detected && escalates(finding.action, action)) action = finding.action;
  }
  for (const trace of policyTraces) {
    if (trace.matched && escalates(trace.action, action)) action = trace.action;
  }
  return { action, stage, correlationId, findings, policyTraces, payload, elapsedMs: 0 };
}

export interface RequestContext {
  correlationId: string;
  sessionId?: string;
  principal: Principal;
  application: string;
  environment: string;
  model?: string;
  provider?: string;
  messages: Message[];
  traceId?: string;
  spanId?: string;
  tags: Record<string, unknown>;
  startedMs: number;
}

export interface AuditEvent {
  event_id: string;
  correlation_id: string;
  timestamp_ms: number;
  stage: Stage;
  action: Action;
  severity: Severity;
  application: string;
  environment: string;
  sdk_version: string;
  schema_version: string;
  instance_id: string;
  session_id?: string | null;
  principal_id?: string | null;
  principal_roles: string[];
  tenant?: string | null;
  model?: string | null;
  provider?: string | null;
  trace_id?: string | null;
  span_id?: string | null;
  policy_version?: string | null;
  findings: SerialisedFinding[];
  policy_traces: SerialisedTrace[];
  prompt?: string | null;
  response?: string | null;
  redacted_fields: string[];
  latency_ms: number;
  tokens_in?: number | null;
  tokens_out?: number | null;
  error?: string | null;
  tags: Record<string, unknown>;
}

/**
 * Wire shapes use snake_case because the control plane's ingest schema does.
 * Converting at the boundary keeps idiomatic camelCase inside the SDK without
 * forking the cross-language event contract.
 */
export interface SerialisedFinding {
  detector: string;
  detected: boolean;
  score: number;
  severity: Severity;
  action: Action;
  summary: string;
  category: string;
  spans: { start: number; end: number; label: string }[];
  evidence: Record<string, unknown>;
  elapsed_ms: number;
  error: string | null;
}

export interface SerialisedTrace {
  policy_id: string;
  policy_version: string;
  rule_id: string | null;
  matched: boolean;
  action: Action;
  elapsed_ms: number;
  note: string;
}

export const serialiseFinding = (finding: Finding): SerialisedFinding => ({
  detector: finding.detector,
  detected: finding.detected,
  score: Number(finding.score.toFixed(4)),
  severity: finding.severity,
  action: finding.action,
  summary: finding.summary,
  category: finding.category,
  spans: finding.spans.map((s) => ({ start: s.start, end: s.end, label: s.label })),
  evidence: finding.evidence,
  elapsed_ms: Number(finding.elapsedMs.toFixed(3)),
  error: finding.error ?? null,
});

export const serialiseTrace = (trace: PolicyTrace): SerialisedTrace => ({
  policy_id: trace.policyId,
  policy_version: trace.policyVersion,
  rule_id: trace.ruleId,
  matched: trace.matched,
  action: trace.action,
  elapsed_ms: Number(trace.elapsedMs.toFixed(3)),
  note: trace.note,
});

export interface ToolCall {
  name: string;
  arguments: Record<string, unknown>;
  callId: string;
  agent?: string;
  risk?: RiskTier;
}

export function toolCall(name: string, args: Record<string, unknown> = {}, extra: Partial<ToolCall> = {}): ToolCall {
  return { name, arguments: args, callId: newId("call_"), ...extra };
}

export function argumentText(call: ToolCall): string {
  const parts = Object.keys(call.arguments)
    .sort()
    .map((key) => `${key}=${JSON.stringify(call.arguments[key])}`);
  return `${call.name}(${parts.join(", ")})`;
}

export interface Document {
  content: string;
  source: string;
  docId: string;
  trust: TrustLevel;
  metadata?: Record<string, unknown>;
}

export function doc(content: string, source = "unknown", trust: TrustLevel = "retrieved"): Document {
  return { content, source, docId: newId("doc_"), trust };
}

export interface MemoryRecord {
  memoryId: string;
  content: string;
  trust: TrustLevel;
  source: string;
  derivedFrom: string[];
  transformations: string[];
  userConfirmed: boolean;
  createdMs: number;
  metadata?: Record<string, unknown>;
}

export function memoryAuthority(record: MemoryRecord): number {
  const base = trustAuthority(record.trust);
  return record.userConfirmed ? Math.max(base, trustAuthority("user_confirmed")) : base;
}

export interface LLMResponse {
  text: string;
  model: string;
  raw?: unknown;
  tokensIn?: number;
  tokensOut?: number;
  finishReason?: string;
  toolCalls?: ToolCall[];
}

export interface GuardedResponse {
  text: string;
  correlationId: string;
  model?: string;
  inputDecision?: Decision;
  outputDecision?: Decision;
  blocked: boolean;
  raw?: unknown;
  tokensIn?: number;
  tokensOut?: number;
  latencyMs: number;
}
