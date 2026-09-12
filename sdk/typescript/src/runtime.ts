/**
 * Runtime protection: tool guardrails, streaming circuit breaker, and
 * provenance-preserving memory.
 *
 * These cover what input filtering structurally cannot see: what arrives
 * mid-execution from a tool result, a retrieved document, or an agent's own
 * memory. That is where most real agent compromises land.
 */

import { BlockedError } from "./errors";
import type { Pipeline } from "./pipeline";
import {
  argumentText,
  memoryAuthority,
  newId,
  nowMs,
  requiredAuthority,
  trustAuthority,
  type Action,
  type Decision,
  type Document,
  type MemoryRecord,
  type RequestContext,
  type RiskTier,
  type Stage,
  type ToolCall,
  type TrustLevel,
} from "./types";

// ---------------------------------------------------------------------------
// Tool guardrails
// ---------------------------------------------------------------------------

export interface ToolSpec {
  name: string;
  risk: RiskTier;
  description?: string;
  /** Roles permitted to invoke it. Empty means governed by policy/RBAC only. */
  roles?: string[];
  /** Whether results from this tool are trusted. A web fetch is not. */
  resultTrust?: TrustLevel;
  requiresConfirmation?: boolean;
  sandbox?: boolean;
}

const globMatch = (value: string, pattern: string): boolean =>
  new RegExp(`^${pattern.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`).test(value);

/**
 * Halts an in-progress agent run, scoped per correlation id.
 *
 * Once tripped, every subsequent guarded operation for that run is refused —
 * which is the point. An agent that just tried to exfiltrate a credential
 * should not get to try nineteen more things.
 */
export class KillSwitch {
  private readonly tripped = new Map<string, string>();

  trip(correlationId: string, reason: string): void {
    if (!this.tripped.has(correlationId)) this.tripped.set(correlationId, reason);
  }
  reason(correlationId: string): string | undefined {
    return this.tripped.get(correlationId);
  }
  isTripped(correlationId: string): boolean {
    return this.tripped.has(correlationId);
  }
  reset(correlationId: string): void {
    this.tripped.delete(correlationId);
  }
  active(): Record<string, string> {
    return Object.fromEntries(this.tripped);
  }
}

/**
 * A starting risk classification for tool names people actually use. Not a
 * substitute for classifying your own tools, but it means an agent wired up in
 * five minutes is not running with everything at medium.
 */
export function defaultToolSpecs(): ToolSpec[] {
  return [
    { name: "shell.exec", risk: "critical", description: "Run a shell command", sandbox: true },
    { name: "file.read", risk: "low", description: "Read a file" },
    { name: "file.write", risk: "high", description: "Write a file" },
    { name: "file.delete", risk: "critical", description: "Delete a file", requiresConfirmation: true },
    { name: "http.get", risk: "low", description: "Fetch a URL", resultTrust: "external" },
    { name: "http.post", risk: "high", description: "Post to a URL", resultTrust: "external" },
    { name: "web.search", risk: "low", description: "Search the web", resultTrust: "external" },
    { name: "db.query", risk: "medium", description: "Read from a database" },
    { name: "db.execute", risk: "critical", description: "Write to a database", requiresConfirmation: true },
    { name: "email.send", risk: "high", description: "Send an email", requiresConfirmation: true },
    { name: "payment.charge", risk: "critical", description: "Charge a payment method", requiresConfirmation: true },
    { name: "memory.write", risk: "medium", description: "Persist an agent memory" },
  ];
}

export interface ToolGuardOptions {
  allowlist?: string[];
  denylist?: string[];
  authorizer?: { check(principal: any, resourceType: string, resource: string): [boolean, string] };
  confirm?: (call: ToolCall, decision: Decision) => boolean | Promise<boolean>;
  sandboxRunner?: (call: ToolCall, execute: (...args: any[]) => any) => any;
  tripOnBlock?: boolean;
}

export class ToolGuard {
  readonly tools = new Map<string, ToolSpec>();
  readonly killSwitch = new KillSwitch();
  authorizer?: ToolGuardOptions["authorizer"];
  confirm?: ToolGuardOptions["confirm"];
  private readonly allowlist: string[];
  private readonly denylist: string[];
  private readonly sandboxRunner?: ToolGuardOptions["sandboxRunner"];
  private readonly tripOnBlock: boolean;

  constructor(private readonly pipeline: Pipeline, options: ToolGuardOptions = {}) {
    this.allowlist = options.allowlist ?? [];
    this.denylist = options.denylist ?? [];
    this.authorizer = options.authorizer;
    this.confirm = options.confirm;
    this.sandboxRunner = options.sandboxRunner;
    this.tripOnBlock = options.tripOnBlock ?? true;
  }

  register(spec: ToolSpec): void {
    this.tools.set(spec.name, spec);
  }
  registerMany(specs: ToolSpec[]): void {
    for (const spec of specs) this.register(spec);
  }

  /** Allowlist, denylist and RBAC, before any content is inspected. */
  inScope(tool: string, context: RequestContext): [boolean, string] {
    if (this.killSwitch.isTripped(context.correlationId)) {
      return [false, `agent run halted: ${this.killSwitch.reason(context.correlationId)}`];
    }
    for (const pattern of this.denylist) {
      if (globMatch(tool, pattern)) return [false, `tool matches denylist entry '${pattern}'`];
    }
    if (this.allowlist.length && !this.allowlist.some((p) => globMatch(tool, p))) {
      return [false, "tool is not on the allowlist"];
    }
    const spec = this.tools.get(tool);
    if (spec?.roles?.length && !spec.roles.some((r) => context.principal.roles.includes(r))) {
      return [false, `tool requires one of roles ${spec.roles.join(", ")}`];
    }
    if (this.authorizer) {
      const [allowed, reason] = this.authorizer.check(context.principal, "tool", tool);
      if (!allowed) return [false, reason];
    }
    return [true, "in scope"];
  }

  /**
   * Mediate a tool call before execution. `trust` is the authority of the
   * content that *caused* the call — if the agent decided to send an email
   * because a retrieved document said so, pass "retrieved". That is the whole
   * signal.
   */
  async checkCall(call: ToolCall, context: RequestContext, trust: TrustLevel = "user", taintedBy: string[] = []): Promise<Decision> {
    const spec = this.tools.get(call.name);
    if (!call.risk && spec) call.risk = spec.risk;

    const [allowed, reason] = this.inScope(call.name, context);
    if (!allowed) {
      const decision = refused(context, "tool_call", `tool '${call.name}' refused: ${reason}`, call);
      this.pipeline.emit(decision, context, {
        prompt: argumentText(call),
        extraTags: { tool: call.name, trust, scope_reason: reason },
      });
      if (this.tripOnBlock) this.killSwitch.trip(context.correlationId, reason);
      return decision;
    }

    let decision = this.pipeline.evaluate("tool_call", argumentText(call), context, {
      trust,
      toolCall: call,
      metadata: { taintedBy },
    });

    if (decision.action === "challenge") decision = await this.resolveChallenge(call, decision, context);

    if (decision.action === "block" && this.tripOnBlock) {
      const first = decision.findings.find((f) => f.detected);
      this.killSwitch.trip(context.correlationId, first?.summary ?? `blocked tool call '${call.name}'`);
    }
    return decision;
  }

  /**
   * A challenge needs a human. Without one wired up it is a block — "ask the
   * user", silently becoming "go ahead" when nobody is listening, is not a
   * control.
   */
  private async resolveChallenge(call: ToolCall, decision: Decision, context: RequestContext): Promise<Decision> {
    if (!this.confirm) {
      decision.action = "block";
      return decision;
    }
    let approved = false;
    try {
      approved = await this.confirm(call, decision);
    } catch {
      approved = false; // a failed confirmation is not an approval
    }
    decision.action = approved ? "allow" : "block";
    this.pipeline.emit(decision, context, {
      prompt: argumentText(call),
      extraTags: { tool: call.name, challenge_resolved: approved ? "approved" : "denied" },
    });
    return decision;
  }

  /** Screen a tool result before it enters the model's context. */
  checkResult(call: ToolCall, result: string, context: RequestContext): Decision {
    const trust = this.tools.get(call.name)?.resultTrust ?? "tool";
    return this.pipeline.evaluate("tool_result", result, context, { trust, toolCall: call });
  }

  /**
   * Screen retrieved documents, one at a time. The useful outcome is usually
   * "drop the poisoned passage and answer from the other four", not "fail the
   * whole query".
   */
  filterDocuments(documents: Document[], context: RequestContext): { safe: Document[]; rejected: [Document, Decision][] } {
    const safe: Document[] = [];
    const rejected: [Document, Decision][] = [];
    for (const document of documents) {
      const decision = this.pipeline.evaluate("retrieval", document.content, context, {
        trust: document.trust,
        documents: [document],
        metadata: { source: document.source, docId: document.docId },
      });
      if (decision.action === "block") rejected.push([document, decision]);
      else if (decision.action === "redact" && decision.payload !== undefined) {
        safe.push({ ...document, content: decision.payload, metadata: { ...document.metadata, redacted: true } });
      } else safe.push(document);
    }
    return { safe, rejected };
  }

  /** Check, execute, and screen the result. Throws on a block. */
  async guardedCall<T>(
    call: ToolCall,
    execute: (args: Record<string, unknown>) => T | Promise<T>,
    context: RequestContext,
    trust: TrustLevel = "user",
  ): Promise<T | string> {
    const decision = await this.checkCall(call, context, trust);
    if (decision.action === "block") throw new BlockedError(decision);

    const spec = this.tools.get(call.name);
    const result =
      spec?.sandbox && this.sandboxRunner
        ? await this.sandboxRunner(call, execute)
        : await execute(call.arguments);

    if (typeof result === "string") {
      const resultDecision = this.checkResult(call, result, context);
      if (resultDecision.action === "block") throw new BlockedError(resultDecision);
      if (resultDecision.action === "redact" && resultDecision.payload !== undefined) return resultDecision.payload;
    }
    return result;
  }
}

function refused(context: RequestContext, stage: Stage, summary: string, call?: ToolCall): Decision {
  return {
    action: "block",
    stage,
    correlationId: context.correlationId,
    findings: [
      {
        detector: "tool_guard",
        detected: true,
        score: 1,
        severity: "high",
        action: "block",
        summary,
        category: "excessive_agency",
        spans: [],
        evidence: { tool: call?.name },
        elapsedMs: 0,
      },
    ],
    policyTraces: [],
    elapsedMs: 0,
  };
}

// ---------------------------------------------------------------------------
// Streaming
// ---------------------------------------------------------------------------

export interface StreamResult {
  text: string;
  broken: boolean;
  breakDecision?: Decision;
  finalDecision?: Decision;
  checkpoints: number;
  escalations: number;
  replacement?: string;
}

const FAST_STREAM_DETECTORS = ["secret_leakage", "banned_topics"];
const FULL_STREAM_DETECTORS = ["secret_leakage", "banned_topics", "pii", "prompt_injection"];

/**
 * Evaluates a token stream incrementally and can break it mid-generation.
 *
 * Filtering only after the stream finishes defeats the point of streaming: by
 * then the user has read it. Evaluating every detector on every token is
 * unaffordable. So: check every `checkEveryChars`, run the cheap deterministic
 * detectors, break at `breakThreshold`, and escalate once to the full set in
 * the ambiguous band.
 *
 * `holdWindow` (default true) buffers one window so nothing is released until
 * it has been checked — one window of latency in exchange for the guarantee.
 * Set it false for the fastest first token, accepting that up to one window of
 * unsafe text may reach the user before the break.
 */
export class StreamGuard {
  constructor(
    private readonly pipeline: Pipeline,
    readonly options: {
      checkEveryChars?: number;
      fastThreshold?: number;
      breakThreshold?: number;
      holdWindow?: boolean;
      breakMessage?: string;
    } = {},
  ) {}

  private get checkEveryChars(): number {
    return this.options.checkEveryChars ?? 120;
  }
  private get breakMessage(): string {
    return this.options.breakMessage ?? "[response withheld by the AI firewall]";
  }

  async *stream(
    chunks: AsyncIterable<string> | Iterable<string>,
    context: RequestContext,
    options: { grounding?: string[]; onBreak?: (decision: Decision) => void; result?: StreamResult } = {},
  ): AsyncGenerator<string> {
    const holdWindow = this.options.holdWindow ?? true;
    const result: StreamResult = options.result ?? { text: "", broken: false, checkpoints: 0, escalations: 0 };
    let pending = "";
    let sinceCheck = 0;

    for await (const chunk of chunks as AsyncIterable<string>) {
      result.text += chunk;
      pending += chunk;
      sinceCheck += chunk.length;

      if (sinceCheck < this.checkEveryChars) {
        if (!holdWindow) {
          yield chunk;
          pending = "";
        }
        continue;
      }
      sinceCheck = 0;

      const decision = this.checkpoint(result, context, options.grounding ?? []);
      if (decision) {
        result.broken = true;
        result.breakDecision = decision;
        result.replacement = this.breakMessage;
        options.onBreak?.(decision);
        yield this.breakMessage; // nothing unsafe was released; drop the held window
        return;
      }
      if (holdWindow && pending) {
        yield pending;
        pending = "";
      }
    }

    if (holdWindow && pending) {
      const decision = this.checkpoint(result, context, options.grounding ?? []);
      if (decision) {
        result.broken = true;
        result.breakDecision = decision;
        result.replacement = this.breakMessage;
        options.onBreak?.(decision);
        yield this.breakMessage;
        return;
      }
      yield pending;
    }

    // The incremental pass is an early-exit optimisation, never a replacement:
    // the complete response always goes through the full output pipeline.
    result.finalDecision = this.pipeline.evaluate("output", result.text, context, {
      trust: "system",
      grounding: options.grounding ?? [],
    });
  }

  private checkpoint(result: StreamResult, context: RequestContext, grounding: string[]): Decision | null {
    result.checkpoints += 1;
    const decision = this.pipeline.evaluate("stream", result.text, context, {
      trust: "system",
      detectors: FAST_STREAM_DETECTORS,
      grounding,
      emit: false, // only checkpoints that act are worth an audit event
    });
    const score = Math.max(0, ...decision.findings.filter((f) => f.detected).map((f) => f.score));

    if (decision.action === "block" || score >= (this.options.breakThreshold ?? 0.75)) {
      this.pipeline.emit(decision, context, {
        response: result.text,
        extraTags: { stream_checkpoint: result.checkpoints, stream_action: "break" },
      });
      return decision;
    }

    if (score >= (this.options.fastThreshold ?? 0.45)) {
      result.escalations += 1;
      const escalated = this.pipeline.evaluate("stream", result.text, context, {
        trust: "system",
        detectors: FULL_STREAM_DETECTORS,
        grounding,
        emit: false,
      });
      if (escalated.action === "block" || escalated.action === "challenge") {
        escalated.action = "block";
        this.pipeline.emit(escalated, context, {
          response: result.text,
          extraTags: { stream_checkpoint: result.checkpoints, stream_action: "break_escalated" },
        });
        return escalated;
      }
    }
    return null;
  }

  /** Consume a stream fully and return the result. */
  async collect(
    chunks: AsyncIterable<string> | Iterable<string>,
    context: RequestContext,
    grounding: string[] = [],
  ): Promise<StreamResult> {
    const result: StreamResult = { text: "", broken: false, checkpoints: 0, escalations: 0 };
    const pieces: string[] = [];
    for await (const piece of this.stream(chunks, context, { grounding, result })) pieces.push(piece);
    // When broken, the last yielded piece is the break message, not output.
    result.text = result.broken ? pieces.slice(0, -1).join("") : pieces.join("");
    return result;
  }
}

// ---------------------------------------------------------------------------
// Provenance-preserving memory
// ---------------------------------------------------------------------------

export interface MemoryGateResult {
  allowed: boolean;
  reason: string;
  requiredAuthority: number;
  availableAuthority: number;
  supporting: MemoryRecord[];
  blocking: MemoryRecord[];
}

const STOP = new Set("the and for with from that this when where what have has was were are you your our their".split(" "));
const terms = (text: string): Set<string> =>
  new Set((text.toLowerCase().match(/[a-z0-9_.-]{3,}/g) ?? []).filter((w) => !STOP.has(w)));

function relevance(queryTerms: Set<string>, record: MemoryRecord): number {
  if (!queryTerms.size) return 0;
  const recordTerms = terms(record.content);
  if (!recordTerms.size) return 0;
  return [...queryTerms].filter((t) => recordTerms.has(t)).length / queryTerms.size;
}

/**
 * Provenance-preserving memory store and execution gate.
 *
 * Implements the non-amplification property from the Provenance-Preserving
 * Memory Firewall paper. The failure it prevents: an agent reads an untrusted
 * page, consolidates it into "user workflow: resume PM-A011", and in a later
 * task that memory reads as user history and authorises a tool call the page
 * never could. The trigger survived; the provenance was laundered.
 *
 * Two mechanisms, the second being the one that matters:
 *  1. Trust is set from the boundary the content crossed, by Keeper, never
 *     from what the model says about the memory. A consolidated record's trust
 *     is the minimum over its parents.
 *  2. Before a tool call runs, the memories that actually support *those
 *     arguments* are identified and their authority compared to the call's
 *     risk. Storing provenance is not enough on its own — it has to be bound
 *     to the specific call at execution time, or an unrelated high-authority
 *     memory in the same context silently vouches for the action.
 */
export class MemoryFirewall {
  readonly records = new Map<string, MemoryRecord>();
  /** Risk tiers that require memory-backed authority at all. */
  gatedTiers: RiskTier[] = ["high", "critical"];
  relevanceThreshold = 0.2;

  constructor(private readonly pipeline?: Pipeline) {}

  write(
    content: string,
    options: {
      trust: TrustLevel;
      source?: string;
      context?: RequestContext;
      derivedFrom?: string[];
      transformations?: string[];
      userConfirmed?: boolean;
    },
  ): { record: MemoryRecord; decision?: Decision } {
    const derivedFrom = options.derivedFrom ?? [];
    const trust = this.floor(options.trust, derivedFrom);
    let text = content;
    let transformations = options.transformations ?? [];
    let decision: Decision | undefined;

    if (this.pipeline && options.context) {
      decision = this.pipeline.evaluate("memory_write", content, options.context, {
        trust,
        metadata: { source: options.source, derivedFrom },
      });
      if (decision.action === "block") {
        return {
          record: {
            memoryId: newId("mem_"),
            content,
            trust,
            source: options.source ?? "unknown",
            derivedFrom,
            transformations,
            userConfirmed: false,
            createdMs: nowMs(),
          },
          decision,
        };
      }
      if (decision.action === "redact" && decision.payload !== undefined) {
        text = decision.payload;
        transformations = [...transformations, "keeper_redaction"];
      }
    }

    const record: MemoryRecord = {
      memoryId: newId("mem_"),
      content: text,
      trust,
      source: options.source ?? "unknown",
      derivedFrom,
      transformations,
      // Confirmation is honoured only when the platform observed it. A flag
      // derived from model output would be exactly the laundering this class
      // exists to prevent.
      userConfirmed: Boolean(options.userConfirmed) && trustAuthority(trust) >= trustAuthority("user"),
      createdMs: nowMs(),
    };
    this.records.set(record.memoryId, record);
    return { record, decision };
  }

  /**
   * Write a memory derived from existing ones. The consolidated record's trust
   * is the minimum over its parents, whatever text the consolidating model
   * produced. This single rule is the non-amplification property.
   */
  consolidate(
    content: string,
    parents: (MemoryRecord | string)[],
    options: { source?: string; context?: RequestContext; transformation?: string } = {},
  ): { record: MemoryRecord; decision?: Decision } {
    const resolved = parents
      .map((p) => (typeof p === "string" ? this.records.get(p) : p))
      .filter((r): r is MemoryRecord => Boolean(r));
    const trust = resolved.length
      ? resolved.reduce<TrustLevel>((lowest, r) => (trustAuthority(r.trust) < trustAuthority(lowest) ? r.trust : lowest), "system")
      : "external";
    return this.write(content, {
      trust,
      source: options.source ?? "consolidation",
      context: options.context,
      derivedFrom: resolved.map((r) => r.memoryId),
      transformations: [options.transformation ?? "llm_consolidation"],
    });
  }

  /** A derived record can never outrank its least trusted ancestor. */
  private floor(trust: TrustLevel, derivedFrom: string[]): TrustLevel {
    let lowest = trust;
    for (const parentId of derivedFrom) {
      const parent = this.records.get(parentId);
      if (parent && trustAuthority(parent.trust) < trustAuthority(lowest)) lowest = parent.trust;
    }
    return lowest;
  }

  recall(query: string, limit = 5): MemoryRecord[] {
    const queryTerms = terms(query);
    return [...this.records.values()]
      .map((record) => ({ record, score: relevance(queryTerms, record) }))
      .filter(({ score }) => score > 0)
      .sort((a, b) => memoryAuthority(b.record) - memoryAuthority(a.record) || b.score - a.score)
      .slice(0, limit)
      .map(({ record }) => record);
  }

  /**
   * Check that memories supporting this call carry enough authority.
   *
   * Relevance is computed against the call's *arguments*, not the whole
   * conversation. That is the binding step.
   */
  authorizeCall(
    call: ToolCall,
    options: { candidates?: MemoryRecord[]; userConfirmed?: boolean } = {},
  ): MemoryGateResult {
    const risk = call.risk ?? "medium";
    const required = requiredAuthority(risk);

    if (!this.gatedTiers.includes(risk)) {
      return {
        allowed: true,
        reason: `${risk}-risk call does not require memory-backed authority`,
        requiredAuthority: required,
        availableAuthority: trustAuthority("system"),
        supporting: [],
        blocking: [],
      };
    }
    if (options.userConfirmed) {
      return {
        allowed: true,
        reason: "user confirmed this action out of band",
        requiredAuthority: required,
        availableAuthority: trustAuthority("user_confirmed"),
        supporting: [],
        blocking: [],
      };
    }

    const pool = options.candidates ?? this.recall(argumentText(call), 10);
    const argumentTerms = terms(argumentText(call));
    const supporting = pool.filter((r) => relevance(argumentTerms, r) >= this.relevanceThreshold);

    if (!supporting.length) {
      return {
        allowed: false,
        reason: `no memory supports this ${risk}-risk call; high-risk actions require explicit user authority`,
        requiredAuthority: required,
        availableAuthority: -1,
        supporting: [],
        blocking: [],
      };
    }

    const available = Math.max(...supporting.map(memoryAuthority));
    if (available >= required) {
      return {
        allowed: true,
        reason: "supporting memory carries sufficient authority",
        requiredAuthority: required,
        availableAuthority: available,
        supporting,
        blocking: [],
      };
    }
    const weakest = supporting.reduce((a, b) => (memoryAuthority(a) <= memoryAuthority(b) ? a : b));
    return {
      allowed: false,
      reason: `this ${risk}-risk call is supported only by ${weakest.trust}-authority memory; source authority cannot be amplified by consolidation`,
      requiredAuthority: required,
      availableAuthority: available,
      supporting,
      blocking: supporting.filter((r) => memoryAuthority(r) < required),
    };
  }

  /** Full ancestry of a memory, for incident investigation. */
  lineage(memoryId: string): MemoryRecord[] {
    const out: MemoryRecord[] = [];
    const seen = new Set<string>();
    const stack = [memoryId];
    while (stack.length) {
      const current = stack.pop()!;
      if (seen.has(current)) continue;
      seen.add(current);
      const record = this.records.get(current);
      if (!record) continue;
      out.push(record);
      stack.push(...record.derivedFrom);
    }
    return out;
  }

  stats(): Record<string, unknown> {
    const records = [...this.records.values()];
    const byTrust: Record<string, number> = {};
    for (const record of records) byTrust[record.trust] = (byTrust[record.trust] ?? 0) + 1;
    return {
      total: records.length,
      byTrust,
      derived: records.filter((r) => r.derivedFrom.length).length,
      userConfirmed: records.filter((r) => r.userConfirmed).length,
    };
  }
}

export type { Action };
