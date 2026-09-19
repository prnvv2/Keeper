/**
 * The developer-facing API.
 *
 * ```ts
 * import { Keeper } from "keeper-firewall";
 *
 * const keeper = new Keeper({ application: "support-bot" });
 * const reply = await keeper.chat("Summarise ticket 4182");
 * ```
 *
 * Design constraint: the ten-minute quickstart has to be true. Keeper works
 * with zero configuration (no control plane, no policy file, no API key),
 * enforces something sensible out of the box, and wraps an existing model call
 * without the application changing its architecture.
 */

import { Authorizer, RateLimiter, authorizerFromPolicy } from "./accesscontrol.js";
import { loadConfig, type KeeperConfig, type KeeperOptions } from "./config.js";
import { newCanary, toolText, type Detector } from "./detectors/index.js";
import { AuthorizationError, BlockedError, RateLimitError } from "./errors.js";
import {
  EventBuilder,
  FanoutSink,
  MemorySink,
  Metrics,
  Redactor,
  StreamSink,
  type Sink,
} from "./observability.js";
import { Pipeline } from "./pipeline.js";
import { PolicyProvider, type Policy } from "./policy.js";
import { coverageReport, type CoverageRow } from "./taxonomy.js";
import { CallableProvider, EchoProvider, type Provider } from "./providers.js";
import { MemoryFirewall, StreamGuard, ToolGuard, defaultToolSpecs, type ToolSpec } from "./runtime.js";
import { ControlPlaneClient, TelemetryShipper } from "./transport.js";
import {
  SDK_VERSION,
  anonymous,
  argumentText,
  newId,
  nowMs,
  toolCall as makeToolCall,
  type AuditEvent,
  type Decision,
  type Document,
  type GuardedResponse,
  type Message,
  type Principal,
  type RequestContext,
  type TrustLevel,
} from "./types.js";

export interface KeeperInit extends KeeperOptions {
  provider?: Provider | ((messages: Record<string, unknown>[], options?: Record<string, any>) => any);
  extraDetectors?: Detector[];
  onEvent?: (event: AuditEvent) => void;
}

export interface ContextOptions {
  principal?: Principal;
  user?: string;
  roles?: string[];
  tenant?: string;
  session?: string;
  model?: string;
  tags?: Record<string, unknown>;
}

export class Keeper {
  readonly config: KeeperConfig;
  readonly metrics: Metrics;
  readonly redactor: Redactor;
  readonly sink: FanoutSink;
  readonly memorySink: MemorySink;
  readonly client?: ControlPlaneClient;
  readonly shipper: TelemetryShipper;
  readonly policyProvider: PolicyProvider;
  readonly pipeline: Pipeline;
  readonly tools: ToolGuard;
  readonly streamGuard: StreamGuard;
  readonly memory: MemoryFirewall;
  readonly limiter: RateLimiter;
  authorizer: Authorizer;
  provider: Provider;

  private readonly events: EventBuilder;
  private readonly startedMs = nowMs();

  constructor(init: KeeperInit = {}) {
    const { provider, extraDetectors = [], onEvent, ...options } = init;
    this.config = loadConfig(options);

    // Observability first: everything below it is observed.
    this.metrics = new Metrics(this.config.metrics, this.config.application);
    this.metrics.gaugeSet("info", 1, {
      application: this.config.application,
      sdk_version: SDK_VERSION,
      environment: this.config.environment,
    });
    this.redactor = new Redactor(this.config.redaction);

    this.memorySink = new MemorySink();
    this.sink = new FanoutSink([this.memorySink]);
    if (this.config.telemetry.localLogStdout) this.sink.add(new StreamSink());

    this.client = this.config.telemetry.endpoint
      ? new ControlPlaneClient(this.config.telemetry.endpoint, {
          apiKey: this.config.telemetry.apiKey,
          timeoutMs: this.config.telemetry.timeoutMs,
        })
      : undefined;
    this.shipper = new TelemetryShipper(this.config.telemetry, this.config.instanceId, this.client, this.metrics);

    this.policyProvider = new PolicyProvider(this.config.policy, this.client, (policy) => this.onPolicyChange(policy));

    this.authorizer = authorizerFromPolicy(this.policyProvider.policy.modelAccess, this.policyProvider.policy.toolAccess);
    this.limiter = new RateLimiter(
      { rpm: this.config.accessControl.defaultRpm, burst: this.config.accessControl.defaultBurst },
      false,
    );
    this.limiter.applyPolicy(this.policyProvider.policy.rateLimits);

    this.events = new EventBuilder(this.redactor, this.config.instanceId, `${this.policyProvider.policy.id}@${this.policyProvider.policy.version}`);
    this.pipeline = new Pipeline(
      this.config,
      this.policyProvider,
      this.metrics,
      this.events,
      this.sink,
      this.shipper,
      extraDetectors,
      onEvent,
    );

    this.tools = new ToolGuard(this.pipeline, {
      allowlist: this.config.runtime.toolAllowlist,
      denylist: this.config.runtime.toolDenylist,
      authorizer: this.authorizer,
    });
    this.tools.registerMany(defaultToolSpecs());
    this.streamGuard = new StreamGuard(this.pipeline, {
      checkEveryChars: this.config.runtime.streamCheckEveryChars,
      fastThreshold: this.config.runtime.streamFastThreshold,
      breakThreshold: this.config.runtime.streamBreakThreshold,
    });
    this.memory = new MemoryFirewall(this.pipeline);

    this.provider =
      provider === undefined
        ? new EchoProvider()
        : typeof provider === "function"
          ? new CallableProvider(provider as any)
          : provider;

    if (this.client) void this.registerInstance();
  }

  /** Re-derive everything a policy bundle can influence. */
  private onPolicyChange(policy: Policy): void {
    this.events.policyVersion = `${policy.id}@${policy.version}`;
    this.limiter.applyPolicy(policy.rateLimits);
    this.authorizer = authorizerFromPolicy(policy.modelAccess, policy.toolAccess);
    this.tools.authorizer = this.authorizer;
  }

  /** Announce this instance to the fleet inventory. Best effort. */
  private async registerInstance(): Promise<void> {
    try {
      await this.client!.registerInstance({
        instance_id: this.config.instanceId,
        application: this.config.application,
        environment: this.config.environment,
        sdk_version: SDK_VERSION,
        language: "typescript",
        policy_id: this.policyProvider.policy.id,
        policy_version: this.policyProvider.policy.version,
        detectors: this.pipeline.detectorNames,
        monitor_only: this.config.monitorOnly,
      });
    } catch {
      /* inventory is not on the critical path */
    }
  }

  // -- context ------------------------------------------------------------

  context(options: ContextOptions = {}): RequestContext {
    const principal =
      options.principal ??
      (options.user
        ? { id: options.user, roles: options.roles ?? [], tenant: options.tenant, authenticated: false }
        : anonymous());
    return {
      correlationId: newId("req_"),
      sessionId: options.session,
      principal,
      application: this.config.application,
      environment: this.config.environment,
      model: options.model,
      provider: this.provider.name,
      messages: [],
      tags: options.tags ?? {},
      startedMs: nowMs(),
    };
  }

  // -- access control -----------------------------------------------------

  authorize(context: RequestContext, model?: string, cost = 1): void {
    const settings = this.config.accessControl;
    if (!settings.enabled) return;

    if (settings.requireAuthentication && !context.principal.authenticated) {
      this.metrics.inc("access_denied_total", 1, { reason: "unauthenticated" });
      this.emitAccessDenied(context, "unauthenticated principal");
      throw new AuthorizationError("authentication required", context.principal.id);
    }

    const target = model ?? context.model;
    if (target) {
      const [allowed, reason] = this.authorizer.check(context.principal, "model", target);
      if (!allowed) {
        this.metrics.inc("access_denied_total", 1, { reason: "model_forbidden" });
        this.emitAccessDenied(context, `model '${target}': ${reason}`);
        throw new AuthorizationError(
          `principal '${context.principal.id}' may not use model '${target}': ${reason}`,
          context.principal.id,
          `model:${target}`,
        );
      }
    }

    if (settings.rateLimitEnabled) {
      try {
        this.limiter.check(context.principal, target, cost);
      } catch (error) {
        if (error instanceof RateLimitError) {
          this.metrics.inc("access_denied_total", 1, { reason: "rate_limited" });
          this.emitAccessDenied(context, error.message);
        }
        throw error;
      }
    }
  }

  private emitAccessDenied(context: RequestContext, summary: string): void {
    this.pipeline.emit(
      {
        action: "block",
        stage: "access",
        correlationId: context.correlationId,
        findings: [
          {
            detector: "access_control",
            detected: true,
            score: 1,
            severity: "medium",
            action: "block",
            summary,
            category: "access_control",
            spans: [],
            evidence: {},
            elapsedMs: 0,
          },
        ],
        policyTraces: [],
        elapsedMs: 0,
      },
      context,
    );
  }

  // -- filtering ----------------------------------------------------------

  checkInput(text: string, context = this.context(), options: { trust?: TrustLevel; history?: Message[] } = {}): Decision {
    return this.pipeline.evaluate("input", text, context, options);
  }

  checkOutput(text: string, context = this.context(), options: { grounding?: string[] } = {}): Decision {
    return this.pipeline.evaluate("output", text, context, { trust: "system", ...options });
  }

  checkDocuments(documents: Document[], context = this.context()): { safe: Document[]; rejected: [Document, Decision][] } {
    return this.tools.filterDocuments(documents, context);
  }

  checkToolCall(
    name: string,
    args: Record<string, unknown> = {},
    context = this.context(),
    trust: TrustLevel = "user",
  ): Promise<Decision> {
    return this.tools.checkCall(makeToolCall(name, args), context, trust);
  }

  /**
   * Screen MCP / function-calling tool definitions before the model sees them
   * (OWASP MCP03). Accepts MCP `{name, description, inputSchema}`, OpenAI
   * `{type: "function", function: {...}}` or Anthropic `{name, description,
   * input_schema}` shapes. Definitions are pinned: a later change to a pinned
   * definition is reported as a rug pull. Drop the blocked ones.
   */
  checkToolDefinitions(
    tools: Record<string, any>[],
    context = this.context(),
    server = "default",
    pin?: boolean,
  ): [Record<string, any>, Decision][] {
    return tools.map((raw) => {
      const definition = (raw?.function ?? raw) as Record<string, any>;
      const decision = this.pipeline.evaluate("tool_definition", toolText(definition), context, {
        trust: "external",
        metadata: { toolDefinition: definition, server, tool: definition.name, pin },
      });
      return [raw, decision];
    });
  }

  /**
   * A fresh canary token to embed in your system prompt. If it ever appears in
   * model output, `system_prompt_leakage` blocks the response (OWASP LLM07).
   */
  canary(): string {
    const token = newCanary();
    const detector = this.pipeline.detector("system_prompt_leakage") as { addCanary?(t: string): void } | undefined;
    detector?.addCanary?.(token);
    return token;
  }

  /** OWASP LLM / Agentic / MCP coverage given the detectors enabled here. */
  coverage(): CoverageRow[] {
    return coverageReport(this.pipeline.detectorNames);
  }

  // -- the main entry point ------------------------------------------------

  async chat(
    input: string | Message[],
    options: {
      context?: RequestContext;
      provider?: Provider;
      model?: string;
      grounding?: string[];
      raiseOnBlock?: boolean;
      [key: string]: unknown;
    } = {},
  ): Promise<GuardedResponse> {
    const { context: given, provider: override, model, grounding = [], raiseOnBlock = false, ...providerOptions } = options;
    const provider = override ?? this.provider;
    const turns = normaliseMessages(input);
    const context = given ?? this.context({ model });
    context.model = model ?? context.model;
    context.provider = provider.name;
    context.messages = turns;
    const start = nowMs();

    this.authorize(context, model);

    const prompt = turns[turns.length - 1]?.content ?? "";
    const inputDecision = this.pipeline.evaluate("input", prompt, context, {
      trust: turns[turns.length - 1]?.trust ?? "user",
      history: turns.slice(0, -1),
      metadata: { maxTokens: providerOptions.max_tokens ?? providerOptions.maxTokens },
    });

    if (inputDecision.action === "block") {
      if (raiseOnBlock) throw new BlockedError(inputDecision);
      return {
        text: this.blockMessage(inputDecision),
        correlationId: context.correlationId,
        model,
        inputDecision,
        blocked: true,
        latencyMs: nowMs() - start,
      };
    }

    let outbound = turns;
    if (inputDecision.action === "redact" && inputDecision.payload !== undefined) {
      outbound = [...turns.slice(0, -1), { ...turns[turns.length - 1], content: inputDecision.payload }];
    }

    const modelStart = nowMs();
    const llm = await provider.complete(outbound, { model, ...providerOptions });
    const modelMs = nowMs() - modelStart;
    this.metrics.observe("model_latency_ms", modelMs, { provider: provider.name });

    const outputDecision = this.pipeline.evaluate("output", llm.text, context, {
      trust: "system",
      grounding,
      latencyMs: modelMs,
      tokensIn: llm.tokensIn,
      tokensOut: llm.tokensOut,
    });

    let text = llm.text;
    if (outputDecision.action === "block") {
      if (raiseOnBlock) throw new BlockedError(outputDecision);
      text = this.blockMessage(outputDecision);
    } else if (outputDecision.action === "redact" && outputDecision.payload !== undefined) {
      text = outputDecision.payload;
    }

    return {
      text,
      correlationId: context.correlationId,
      model: llm.model,
      inputDecision,
      outputDecision,
      blocked: outputDecision.action === "block",
      raw: llm.raw,
      tokensIn: llm.tokensIn,
      tokensOut: llm.tokensOut,
      latencyMs: nowMs() - start,
    };
  }

  /** Stream a response with mid-generation enforcement. */
  async *stream(
    input: string | Message[],
    options: { context?: RequestContext; provider?: Provider; model?: string; grounding?: string[]; [key: string]: unknown } = {},
  ): AsyncGenerator<string> {
    const { context: given, provider: override, model, grounding = [], ...providerOptions } = options;
    const provider = override ?? this.provider;
    const turns = normaliseMessages(input);
    const context = given ?? this.context({ model });
    context.model = model ?? context.model;
    context.messages = turns;

    this.authorize(context, model);
    const prompt = turns[turns.length - 1]?.content ?? "";
    const inputDecision = this.pipeline.evaluate("input", prompt, context, { history: turns.slice(0, -1) });
    if (inputDecision.action === "block") {
      yield this.blockMessage(inputDecision);
      return;
    }

    if (!provider.stream) {
      yield (await provider.complete(turns, { model, ...providerOptions })).text;
      return;
    }
    yield* this.streamGuard.stream(provider.stream(turns, { model, ...providerOptions }), context, { grounding });
  }

  /** Wrap an existing LLM call so it runs behind the firewall. */
  wrap(
    fn: (messages: Record<string, unknown>[], options?: Record<string, any>) => any,
    options: { model?: string } = {},
  ): (input: string | Message[], callOptions?: Record<string, unknown>) => Promise<GuardedResponse> {
    const provider = new CallableProvider(fn, "wrapped", options.model);
    return (input, callOptions = {}) => this.chat(input, { provider, model: options.model, ...callOptions });
  }

  // -- registration --------------------------------------------------------

  /**
   * Tell the firewall a value is confidential so it can catch leaks. Register
   * the system prompt, tenant identifiers, and any config secret the model
   * could plausibly echo. Only salted digests are retained.
   */
  registerSecret(value: string, label = "registered_secret"): void {
    const detector = this.pipeline.detector("secret_leakage") as { register?(v: string, l: string): void } | undefined;
    detector?.register?.(value, label);
  }

  registerTool(spec: ToolSpec): void {
    this.tools.register(spec);
  }

  addSink(sink: Sink): void {
    this.sink.add(sink);
  }

  setPolicy(policy: Policy | Record<string, any>): void {
    this.policyProvider.setPolicy(policy);
  }

  // -- observability surface ------------------------------------------------

  /** Prometheus exposition text, for the host app's /metrics handler. */
  metricsText(): string {
    return this.metrics.render();
  }

  /** Everything an ops team needs to monitor the firewall itself. */
  health(): Record<string, unknown> {
    return {
      status: this.policyProvider.degraded ? "degraded" : "ok",
      sdkVersion: SDK_VERSION,
      application: this.config.application,
      environment: this.config.environment,
      instanceId: this.config.instanceId,
      uptimeMs: nowMs() - this.startedMs,
      monitorOnly: this.config.monitorOnly,
      detectors: this.pipeline.detectorNames,
      policy: this.policyProvider.health(),
      telemetry: this.shipper.health(),
      rateLimiter: this.limiter.state(),
      memory: this.memory.stats(),
      killSwitchesActive: Object.keys(this.tools.killSwitch.active()).length,
      redaction: { mode: this.config.redaction.mode, ephemeralSalt: this.redactor.usesEphemeralSalt },
    };
  }

  recentEvents(limit = 50): AuditEvent[] {
    return this.memorySink.events.slice(-limit);
  }

  /** Block until queued telemetry is delivered. Call before exit. */
  flush(timeoutMs = 5000): Promise<boolean> {
    this.sink.flush();
    return this.shipper.flush(timeoutMs);
  }

  async close(): Promise<void> {
    await this.shipper.close();
    this.policyProvider.close();
    this.sink.close();
  }

  /**
   * The user-visible text when something is blocked. Prefers the policy rule's
   * own message so a compliance team controls the wording; falls back to a
   * generic line plus the correlation id — deliberately not the detector's
   * evidence, which would tell an attacker which signal fired.
   */
  blockMessage(decision: Decision): string {
    for (const trace of decision.policyTraces) {
      if (trace.matched && trace.action === "block" && trace.note) return trace.note;
    }
    return `This request was blocked by the AI firewall. Reference: ${decision.correlationId}`;
  }
}

function normaliseMessages(input: string | Message[]): Message[] {
  if (typeof input === "string") return [{ role: "user", content: input }];
  return input.map((m) => ({ role: m.role ?? "user", content: String(m.content ?? ""), name: m.name, trust: m.trust }));
}

export { argumentText };
