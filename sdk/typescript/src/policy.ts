/**
 * Declarative policy: documents, the condition language, evaluation, and
 * distribution. Byte-compatible with the Python SDK's policy format — the same
 * bundle published from the control plane loads in both.
 *
 * The condition language is deliberately total: no loops, no user-supplied
 * code, no way for a policy to hang the request path. Unknown keys are a
 * load-time error, never a silently-true condition, which is what makes it
 * safe to accept a document from the control plane at all.
 */

import { bandRank, parseRiskConfig, type RiskAssessment, type RiskBand, type RiskConfig } from "./risk.js";
import { PolicyError } from "./errors.js";
import type { Action, Finding, PolicyTrace, RequestContext, Severity, Stage, ToolCall, TrustLevel } from "./types.js";
import { escalates, nowMs, severityRank } from "./types.js";

// ---------------------------------------------------------------------------
// Condition language
// ---------------------------------------------------------------------------

export type Facts = Record<string, unknown>;
export type Predicate = (facts: Facts) => boolean;

const asList = (value: unknown): unknown[] =>
  value === null || value === undefined ? [] : Array.isArray(value) ? value : [value];

/** Glob-aware membership test used by every string-valued predicate. */
function matchAny(actual: unknown, expected: unknown[]): boolean {
  const values = asList(actual);
  for (const want of expected) {
    const pattern = new RegExp(
      `^${String(want).replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".")}$`,
    );
    for (const have of values) {
      if (String(have) === String(want) || pattern.test(String(have))) return true;
    }
  }
  return false;
}

const stringPredicate =
  (key: string) =>
  (value: unknown): Predicate =>
  (facts) =>
    matchAny(facts[key], asList(value));

/** The closed set of leaf predicates a policy may use. */
const LEAF_BUILDERS: Record<string, (value: unknown) => Predicate> = {
  stage: stringPredicate("stage"),
  environment: stringPredicate("environment"),
  application: stringPredicate("application"),
  model: stringPredicate("model"),
  provider: stringPredicate("provider"),
  tenant: stringPredicate("tenant"),
  principal: stringPredicate("principalId"),
  role: stringPredicate("roles"),
  trust: stringPredicate("trust"),
  tool: stringPredicate("tool"),
  detector_fired: stringPredicate("detectorsFired"),
  category: stringPredicate("categories"),
  label: stringPredicate("labels"),
  not_role: (value) => (facts) => !matchAny(facts.roles, asList(value)),
  detector_not_fired: (value) => (facts) => !matchAny(facts.detectorsFired, asList(value)),
  authenticated: (value) => (facts) => Boolean(facts.authenticated) === Boolean(value),
  severity_at_least: (value) => (facts) =>
    severityRank((facts.severity as Severity) ?? "info") >= severityRank(value as Severity),
  score_at_least: (value) => (facts) => Number(facts.maxScore ?? 0) >= Number(value),
  threat: stringPredicate("threats"),
  risk_at_least: (value) => {
    if (!["none", "low", "medium", "high", "critical"].includes(String(value))) {
      throw new PolicyError(`unknown risk band '${String(value)}'; use none/low/medium/high/critical`);
    }
    return (facts) => bandRank((facts.riskBand as RiskBand) ?? "none") >= bandRank(value as RiskBand);
  },
  risk_score_at_least: (value) => (facts) => Number(facts.riskScore ?? 0) >= Number(value),
  always: (value) => () => Boolean(value),
  tag: (value) => {
    if (typeof value !== "object" || value === null) {
      throw new PolicyError("'tag' expects a mapping of tag name to expected value(s)");
    }
    const wanted = Object.entries(value as Record<string, unknown>).map(([k, v]) => [k, asList(v)] as const);
    return (facts) => {
      const tags = (facts.tags ?? {}) as Record<string, unknown>;
      return wanted.every(([name, values]) => matchAny(tags[name], values));
    };
  },
  content_matches: (value) => {
    const patterns = asList(value).map((p) => new RegExp(String(p), "i"));
    return (facts) => patterns.some((p) => p.test(String(facts.payload ?? "")));
  },
};

/**
 * Compile a `when` clause. A mapping with several leaf keys is an implicit
 * `all`; `all` / `any` / `not` nest arbitrarily.
 */
export function compileCondition(spec: unknown): Predicate {
  if (spec === null || spec === undefined) return () => true;
  if (typeof spec === "boolean") return () => spec;
  if (Array.isArray(spec)) {
    const parts = spec.map(compileCondition);
    return (facts) => parts.every((p) => p(facts));
  }
  if (typeof spec !== "object") throw new PolicyError(`condition must be a mapping or list, got ${typeof spec}`);

  const predicates: Predicate[] = [];
  for (const [key, value] of Object.entries(spec as Record<string, unknown>)) {
    if (key === "all") {
      const parts = asList(value).map(compileCondition);
      predicates.push((facts) => parts.every((p) => p(facts)));
    } else if (key === "any") {
      const parts = asList(value).map(compileCondition);
      predicates.push((facts) => parts.some((p) => p(facts)));
    } else if (key === "not" || key === "none") {
      const part = compileCondition(value);
      predicates.push((facts) => !part(facts));
    } else if (key in LEAF_BUILDERS) {
      predicates.push(LEAF_BUILDERS[key](value));
    } else {
      throw new PolicyError(
        `unknown condition '${key}'; supported: ${[...Object.keys(LEAF_BUILDERS), "all", "any", "not"].sort().join(", ")}`,
      );
    }
  }
  if (predicates.length === 1) return predicates[0];
  return (facts) => predicates.every((p) => p(facts));
}

// ---------------------------------------------------------------------------
// Documents
// ---------------------------------------------------------------------------

export interface Rule {
  id: string;
  action: Action;
  when?: unknown;
  description: string;
  severity?: Severity;
  stop: boolean;
  message: string;
  predicate: Predicate;
}

export interface Policy {
  id: string;
  version: string;
  description: string;
  rules: Rule[];
  detectorOverrides: Record<string, Record<string, unknown>>;
  defaultAction: Action;
  rateLimits: Record<string, Record<string, unknown>>;
  modelAccess: Record<string, string[]>;
  toolAccess: Record<string, string[]>;
  /** The `risk:` section: band actions and impact overrides for the matrix. */
  risk: RiskConfig;
  etag?: string;
  loadedAtMs: number;
  source: string;
}

const ACTIONS: Action[] = ["allow", "flag", "redact", "challenge", "block"];

function parseRule(data: Record<string, any>): Rule {
  if (!data.id) throw new PolicyError("rule is missing required key 'id'");
  if (!data.action) throw new PolicyError(`rule '${data.id}' is missing required key 'action'`);
  if (!ACTIONS.includes(data.action)) throw new PolicyError(`rule '${data.id}': unknown action '${data.action}'`);
  return {
    id: String(data.id),
    action: data.action as Action,
    when: data.when,
    description: String(data.description ?? ""),
    severity: data.severity as Severity | undefined,
    stop: data.stop ?? true,
    message: String(data.message ?? ""),
    predicate: compileCondition(data.when),
  };
}

export function parsePolicy(document: Record<string, any>, source = "unknown"): Policy {
  if (!document || typeof document !== "object") throw new PolicyError("policy document must be a mapping");
  const known = new Set([
    "id", "version", "description", "rules", "detectors", "defaults",
    "rate_limits", "model_access", "tool_access", "metadata", "risk",
  ]);
  const unknown = Object.keys(document).filter((k) => !known.has(k));
  if (unknown.length) throw new PolicyError(`unknown policy keys: ${unknown.sort().join(", ")}`);

  const rules = (document.rules ?? []).map(parseRule);
  const seen = new Set<string>();
  for (const rule of rules) {
    if (seen.has(rule.id)) throw new PolicyError(`duplicate rule id '${rule.id}'`);
    seen.add(rule.id);
  }

  return {
    id: String(document.id ?? "default"),
    version: String(document.version ?? "0"),
    description: String(document.description ?? ""),
    rules,
    detectorOverrides: document.detectors ?? {},
    defaultAction: (document.defaults?.action as Action) ?? "allow",
    rateLimits: document.rate_limits ?? {},
    modelAccess: document.model_access ?? {},
    toolAccess: document.tool_access ?? {},
    risk: parseRiskConfig(document.risk),
    loadedAtMs: nowMs(),
    source,
  };
}

export const policyRef = (policy: Policy): string => `${policy.id}@${policy.version}`;

/**
 * The policy enforced when nothing else is available. Intentionally minimal:
 * block credential egress and confirmed injection, redact PII, allow the rest.
 * A firewall that fails into "block everything" on a cold start is one nobody
 * deploys.
 */
export const SAFE_DEFAULT_POLICY: Record<string, any> = {
  id: "keeper.safe-default",
  version: "1.0.0",
  description: "Built-in fallback policy used when no other policy is available.",
  defaults: { action: "allow" },
  rules: [
    {
      id: "block-credential-egress",
      description: "Never let live credentials reach a model provider.",
      when: { detector_fired: ["secrets", "secret_leakage"] },
      action: "block",
      severity: "critical",
      message: "This request contains credential material and was blocked.",
    },
    {
      id: "block-injection",
      description: "Block confirmed prompt injection at any boundary.",
      when: { detector_fired: "prompt_injection", severity_at_least: "high" },
      action: "block",
      severity: "high",
      message: "This request was identified as a prompt injection attempt.",
    },
    {
      id: "block-unsafe-flow",
      description: "Block low-authority content driving privileged tools.",
      when: { detector_fired: "token_flow", severity_at_least: "high" },
      action: "block",
      severity: "critical",
      message: "This action was not authorised by a sufficiently trusted source.",
    },
    {
      id: "redact-pii",
      description: "Strip personal data rather than failing the request.",
      when: { detector_fired: "pii" },
      action: "redact",
      severity: "medium",
      stop: false,
    },
    {
      id: "flag-authority-claims",
      description: "Unverified authority claims are recorded for review.",
      when: { detector_fired: "authority_claim" },
      action: "flag",
      severity: "low",
      stop: false,
    },
  ],
};

export const safeDefaultPolicy = (): Policy => parsePolicy(SAFE_DEFAULT_POLICY, "builtin");

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

/** Flatten one stage's state into the mapping the condition language reads. */
export function buildFacts(
  stage: Stage,
  context: RequestContext,
  findings: Finding[],
  options: { payload?: string; trust?: TrustLevel; toolCall?: ToolCall; risk?: RiskAssessment } = {},
): Facts {
  const fired = findings.filter((f) => f.detected);
  return {
    stage,
    environment: context.environment,
    application: context.application,
    model: context.model,
    provider: context.provider,
    tenant: context.principal.tenant,
    principalId: context.principal.id,
    roles: context.principal.roles,
    authenticated: context.principal.authenticated,
    trust: options.trust ?? "user",
    tool: options.toolCall?.name,
    detectorsFired: fired.map((f) => f.detector),
    categories: [...new Set(fired.map((f) => f.category))].sort(),
    labels: [...new Set(fired.flatMap((f) => f.spans.map((s) => s.label)))].sort(),
    severity: fired.reduce<Severity>((worst, f) => (severityRank(f.severity) > severityRank(worst) ? f.severity : worst), "info"),
    maxScore: fired.reduce((max, f) => Math.max(max, f.score), 0),
    tags: context.tags,
    payload: options.payload,
    turnCount: context.messages.length,
    threats: [...new Set(fired.flatMap((f) => f.threats ?? []))].sort(),
    riskScore: options.risk?.score ?? 0,
    riskBand: options.risk?.band ?? "none",
  };
}

export class PolicyEngine {
  constructor(readonly policy: Policy, readonly dryRun = false) {}

  evaluate(facts: Facts): PolicyTrace[] {
    const traces: PolicyTrace[] = [];
    const start = performance.now();

    for (const rule of this.policy.rules) {
      const ruleStart = performance.now();
      let matched: boolean;
      try {
        matched = rule.predicate(facts);
      } catch (error) {
        throw new PolicyError(`rule '${rule.id}' failed to evaluate: ${String(error)}`);
      }
      const elapsedMs = performance.now() - ruleStart;
      if (!matched) continue;

      // In dry run every matched rule is recorded with its would-be action but
      // downgraded to allow, so a change can be measured against live traffic
      // before it starts blocking anyone.
      traces.push({
        policyId: this.policy.id,
        policyVersion: this.policy.version,
        ruleId: rule.id,
        matched: true,
        action: this.dryRun ? "allow" : rule.action,
        elapsedMs,
        note: (this.dryRun ? `[dry-run: would ${rule.action}] ` : "") + (rule.message || rule.description),
      });
      if (rule.stop && !this.dryRun) break;
    }

    if (!traces.length) {
      traces.push({
        policyId: this.policy.id,
        policyVersion: this.policy.version,
        ruleId: null,
        matched: this.policy.defaultAction !== "allow",
        action: this.policy.defaultAction,
        elapsedMs: performance.now() - start,
        note: "no rule matched; policy default applied",
      });
    }
    return traces;
  }
}

// ---------------------------------------------------------------------------
// Distribution
// ---------------------------------------------------------------------------

export interface PolicyProviderOptions {
  source: "local" | "control_plane";
  document?: Record<string, any>;
  bundle: string;
  refreshIntervalS: number;
  unreachableBehavior: "last_known_good" | "safe_default" | "fail_open";
  maxStalenessS: number;
  dryRun: boolean;
}

export interface PolicyFetcher {
  fetchPolicy(bundle: string, etag?: string): Promise<{ status: number; etag?: string; policy?: Record<string, any> }>;
}

/**
 * Owns the active policy and keeps it fresh.
 *
 * Pull, not push: the control plane authors and versions, SDK instances poll
 * with an ETag. Push would invert the dependency — every instance holding an
 * open connection, a control-plane restart becoming a fleet-wide event. Pull
 * keeps the data plane's failure domain strictly smaller than the control
 * plane's, which is what lets us promise the firewall keeps working when the
 * dashboard is down. The cost is a propagation delay bounded by
 * `refreshIntervalS`, stated rather than hidden.
 */
export class PolicyProvider {
  private engineRef: PolicyEngine;
  private etag?: string;
  private lastSuccessMs?: number;
  private lastError?: string;
  private degradedReason: string | null = null;
  private timer?: ReturnType<typeof setInterval>;
  private refreshes = 0;

  constructor(
    private readonly options: PolicyProviderOptions,
    private readonly fetcher?: PolicyFetcher,
    private readonly onChange?: (policy: Policy) => void,
  ) {
    const initial =
      options.source === "local" && options.document
        ? parsePolicy(options.document, "local")
        : safeDefaultPolicy();
    if (options.source === "local") this.lastSuccessMs = nowMs();
    this.engineRef = new PolicyEngine(initial, options.dryRun);

    if (options.source === "control_plane" && fetcher) {
      this.degradedReason = "control plane not yet reached; using safe default policy";
      void this.refresh();
      this.timer = setInterval(() => void this.refresh(), options.refreshIntervalS * 1000);
      // Never keep a Node process alive just to poll for policy.
      (this.timer as any)?.unref?.();
    }
  }

  get engine(): PolicyEngine {
    return this.engineRef;
  }

  get policy(): Policy {
    return this.engineRef.policy;
  }

  get degraded(): string | null {
    return this.degradedReason;
  }

  async refresh(): Promise<boolean> {
    if (!this.fetcher) return false;
    try {
      const response = await this.fetcher.fetchPolicy(this.options.bundle, this.etag);
      this.lastSuccessMs = nowMs();
      this.refreshes += 1;
      this.degradedReason = null;
      if (response.status === 304 || !response.policy) return false;

      const policy = parsePolicy(response.policy, `control-plane:${this.options.bundle}`);
      policy.etag = response.etag;
      this.etag = response.etag;
      const previous = policyRef(this.engineRef.policy);
      this.engineRef = new PolicyEngine(policy, this.options.dryRun);
      if (previous !== policyRef(policy)) this.onChange?.(policy);
      return previous !== policyRef(policy);
    } catch (error) {
      this.lastError = String(error);
      this.applyUnreachableBehavior();
      return false;
    }
  }

  private applyUnreachableBehavior(): void {
    const ageS = this.lastSuccessMs ? (nowMs() - this.lastSuccessMs) / 1000 : Infinity;
    const { unreachableBehavior: behavior, maxStalenessS } = this.options;

    if (behavior === "last_known_good" && ageS <= maxStalenessS) {
      this.degradedReason = `control plane unreachable; enforcing last-known-good policy (${ageS.toFixed(0)}s old, limit ${maxStalenessS}s)`;
      return;
    }
    if (behavior === "fail_open") {
      if (this.engineRef.policy.id !== "keeper.disabled") {
        this.engineRef = new PolicyEngine(
          parsePolicy({ id: "keeper.disabled", version: "0", rules: [] }, "fail_open"),
        );
      }
      this.degradedReason = "control plane unreachable; policy enforcement disabled (fail_open)";
      return;
    }
    if (this.engineRef.policy.id !== "keeper.safe-default") {
      this.engineRef = new PolicyEngine(safeDefaultPolicy(), this.options.dryRun);
    }
    this.degradedReason =
      behavior === "last_known_good"
        ? `policy stale for ${ageS.toFixed(0)}s (limit ${maxStalenessS}s); enforcing safe default policy`
        : "control plane unreachable; enforcing safe default policy";
  }

  setPolicy(policy: Policy | Record<string, any>): void {
    const parsed = "rules" in policy && Array.isArray((policy as Policy).rules) && "predicate" in ((policy as Policy).rules[0] ?? { predicate: undefined })
      ? (policy as Policy)
      : parsePolicy(policy as Record<string, any>, "setPolicy");
    this.engineRef = new PolicyEngine(parsed, this.options.dryRun);
    this.degradedReason = null;
    this.lastSuccessMs = nowMs();
    this.onChange?.(parsed);
  }

  health(): Record<string, unknown> {
    return {
      source: this.options.source,
      policyId: this.policy.id,
      policyVersion: this.policy.version,
      rules: this.policy.rules.length,
      dryRun: this.options.dryRun,
      etag: this.etag,
      ageSeconds: this.lastSuccessMs ? (nowMs() - this.lastSuccessMs) / 1000 : null,
      refreshes: this.refreshes,
      degraded: this.degradedReason,
      lastError: this.lastError,
    };
  }

  close(): void {
    if (this.timer) clearInterval(this.timer);
  }
}

/** Combine policy traces into the strongest action they imply. */
export function strongestAction(traces: PolicyTrace[]): Action {
  let action: Action = "allow";
  for (const trace of traces) {
    if (trace.matched && escalates(trace.action, action)) action = trace.action;
  }
  return action;
}
