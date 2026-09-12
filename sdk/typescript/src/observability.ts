/**
 * Observability: redaction, audit events, metrics.
 *
 * Co-equal with enforcement, not a byproduct of it. The three concerns here
 * answer what happened (audit events), how it is behaving (metrics), and what
 * of the payload is allowed to leave the process at all (redaction).
 */

import type { RedactionConfig, MetricsConfig } from "./config";
import {
  SCHEMA_VERSION,
  SDK_VERSION,
  type AuditEvent,
  type Decision,
  type Finding,
  type RequestContext,
  type Span,
  decisionSeverity,
  newId,
  nowMs,
  serialiseFinding,
  serialiseTrace,
  severityRank,
} from "./types";

// ---------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------

/**
 * Applied in `redacted` mode regardless of which detectors ran. A disabled PII
 * detector must not silently become a data leak into the audit store.
 */
const SAFETY_NET: [string, RegExp][] = [
  ["email", /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ["card_like", /\b(?:\d[ -]?){13,19}\b/g],
  ["token_like", /\b(?:sk|pk|gh[pousr]|xox[abprs]|glpat)[-_][A-Za-z0-9_-]{16,}\b/g],
  ["bearer", /\bbearer\s+[A-Za-z0-9._-]{16,}/gi],
  ["private_key", /-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]*?-----END[^-]{0,40}PRIVATE KEY-----/g],
];

/**
 * Replace spans with typed placeholders, right to left. Overlapping spans are
 * merged so two detectors flagging the same card number produce one
 * placeholder rather than a nested, mangled pair.
 */
export function replaceSpans(payload: string, spans: Span[]): { payload: string; labels: string[] } {
  if (!spans.length) return { payload, labels: [] };
  const merged: Span[] = [];
  for (const span of [...spans].sort((a, b) => a.start - b.start || b.end - a.end)) {
    const last = merged[merged.length - 1];
    if (last && span.start < last.end) {
      if (span.end > last.end) merged[merged.length - 1] = { start: last.start, end: span.end, label: `${last.label}+${span.label}` };
      continue;
    }
    merged.push(span);
  }
  let out = payload;
  for (const span of [...merged].reverse()) {
    if (span.start < 0 || span.end > out.length || span.start > span.end) continue;
    out = `${out.slice(0, span.start)}[REDACTED:${span.label}]${out.slice(span.end)}`;
  }
  return { payload: out, labels: [...new Set(merged.map((s) => s.label))] };
}

/**
 * Applies a redaction policy to payloads bound for the audit trail.
 *
 * An AI firewall that ships every prompt verbatim to a central store has
 * created a new, highly concentrated data-protection problem in the name of
 * solving a security one. The default is therefore the conservative option.
 */
export class Redactor {
  private readonly salt: string;
  readonly usesEphemeralSalt: boolean;

  constructor(readonly config: RedactionConfig) {
    this.usesEphemeralSalt = !config.hashSalt;
    this.salt = config.hashSalt ?? newId();
  }

  /** FNV-1a. Correlation identity, not a cryptographic commitment. */
  digest(payload: string): string {
    const input = this.salt + payload;
    let hash = 0x811c9dc5;
    for (let i = 0; i < input.length; i++) {
      hash ^= input.charCodeAt(i);
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    let secondary = 0x27d4eb2f;
    for (let i = input.length - 1; i >= 0; i--) {
      secondary ^= input.charCodeAt(i);
      secondary = Math.imul(secondary, 0x85ebca6b) >>> 0;
    }
    return hash.toString(16).padStart(8, "0") + secondary.toString(16).padStart(8, "0");
  }

  apply(payload: string | null | undefined, findings: Finding[] = [], kind: "prompt" | "response" = "prompt"):
    { payload: string | null; labels: string[] } {
    if (payload === null || payload === undefined) return { payload: null, labels: [] };
    if (kind === "prompt" && !this.config.includePrompt) return { payload: null, labels: [] };
    if (kind === "response" && !this.config.includeResponse) return { payload: null, labels: [] };

    switch (this.config.mode) {
      case "none":
        return { payload: null, labels: [] };
      case "hash_only":
        return { payload: `fnv:${this.digest(payload)}`, labels: ["*"] };
      case "full":
        return { payload: this.truncate(payload), labels: [] };
      default: {
        const { payload: redacted, labels } = this.redact(payload, findings);
        return { payload: this.truncate(redacted), labels };
      }
    }
  }

  redact(payload: string, findings: Finding[] = []): { payload: string; labels: string[] } {
    const spans = findings.filter((f) => f.detected).flatMap((f) => f.spans);
    let { payload: out, labels } = replaceSpans(payload, spans);
    const extra: string[] = [];
    for (const [label, pattern] of SAFETY_NET) {
      const before = out;
      out = out.replace(new RegExp(pattern.source, pattern.flags), `[REDACTED:${label}]`);
      if (out !== before) extra.push(label);
    }
    for (const raw of this.config.extraPatterns) {
      const before = out;
      out = out.replace(new RegExp(raw, "g"), "[REDACTED:custom]");
      if (out !== before) extra.push("custom");
    }
    return { payload: out, labels: [...new Set([...labels, ...extra])] };
  }

  private truncate(payload: string): string {
    const limit = this.config.maxChars;
    if (limit <= 0 || payload.length <= limit) return payload;
    return `${payload.slice(0, limit)}…[truncated ${payload.length - limit} chars]`;
  }
}

// ---------------------------------------------------------------------------
// Audit events
// ---------------------------------------------------------------------------

export interface Sink {
  emit(event: AuditEvent): void;
  flush(): void;
  close(): void;
}

export class MemorySink implements Sink {
  readonly events: AuditEvent[] = [];
  constructor(readonly capacity = 1000) {}
  emit(event: AuditEvent): void {
    this.events.push(event);
    if (this.events.length > this.capacity) this.events.splice(0, this.events.length - this.capacity);
  }
  blocked(): AuditEvent[] {
    return this.events.filter((e) => e.action === "block");
  }
  flush(): void {}
  close(): void {}
}

/** JSON lines to a stream. Never routed through a logger: an audit trail must
 * not inherit the host application's log level or filters. */
export class StreamSink implements Sink {
  constructor(private readonly write: (line: string) => void = (line) => console.log(line)) {}
  emit(event: AuditEvent): void {
    this.write(JSON.stringify(event));
  }
  flush(): void {}
  close(): void {}
}

export class CallbackSink implements Sink {
  constructor(private readonly callback: (event: AuditEvent) => void) {}
  emit(event: AuditEvent): void {
    try {
      this.callback(event);
    } catch {
      /* a broken listener must not break the request */
    }
  }
  flush(): void {}
  close(): void {}
}

export class FanoutSink implements Sink {
  constructor(readonly sinks: Sink[] = []) {}
  add(sink: Sink): void {
    this.sinks.push(sink);
  }
  emit(event: AuditEvent): void {
    for (const sink of this.sinks) {
      try {
        sink.emit(event);
      } catch {
        continue;
      }
    }
  }
  flush(): void {
    for (const sink of this.sinks) {
      try {
        sink.flush();
      } catch {
        continue;
      }
    }
  }
  close(): void {
    for (const sink of this.sinks) {
      try {
        sink.close();
      } catch {
        continue;
      }
    }
  }
}

/** Events that must never be dropped or sampled away. */
export const securityRelevant = (event: AuditEvent): boolean =>
  event.action === "block" ||
  event.action === "challenge" ||
  severityRank(event.severity) >= severityRank("high") ||
  event.error != null;

export interface BuildEventOptions {
  prompt?: string | null;
  response?: string | null;
  latencyMs?: number;
  tokensIn?: number | null;
  tokensOut?: number | null;
  error?: string | null;
  extraTags?: Record<string, unknown>;
}

export class EventBuilder {
  policyVersion?: string;

  constructor(
    private readonly redactor: Redactor,
    private readonly instanceId: string,
    policyVersion?: string,
  ) {
    this.policyVersion = policyVersion;
  }

  build(decision: Decision, context: RequestContext, options: BuildEventOptions = {}): AuditEvent {
    const prompt = this.redactor.apply(options.prompt, decision.findings, "prompt");
    const response = this.redactor.apply(options.response, decision.findings, "response");

    const tags: Record<string, unknown> = { ...context.tags, ...(options.extraTags ?? {}) };
    if (decision.failModeEngaged) tags.fail_mode_engaged = decision.failModeEngaged;
    if (this.redactor.config.hashPayloads && options.prompt) tags.prompt_sha256 = this.redactor.digest(options.prompt);
    if (this.redactor.config.hashPayloads && options.response) tags.response_sha256 = this.redactor.digest(options.response);

    return {
      event_id: newId("evt_"),
      correlation_id: decision.correlationId || context.correlationId,
      timestamp_ms: nowMs(),
      stage: decision.stage,
      action: decision.action,
      severity: decisionSeverity(decision),
      application: context.application,
      environment: context.environment,
      sdk_version: SDK_VERSION,
      schema_version: SCHEMA_VERSION,
      instance_id: this.instanceId,
      session_id: context.sessionId ?? null,
      principal_id: context.principal.id,
      principal_roles: context.principal.roles,
      tenant: context.principal.tenant ?? null,
      model: context.model ?? null,
      provider: context.provider ?? null,
      trace_id: context.traceId ?? null,
      span_id: context.spanId ?? null,
      policy_version: this.policyVersion ?? null,
      findings: decision.findings.map(serialiseFinding),
      policy_traces: decision.policyTraces.map(serialiseTrace),
      prompt: prompt.payload,
      response: response.payload,
      redacted_fields: [...new Set([...prompt.labels, ...response.labels])],
      latency_ms: options.latencyMs ?? decision.elapsedMs,
      tokens_in: options.tokensIn ?? null,
      tokens_out: options.tokensOut ?? null,
      error: options.error ?? null,
      tags,
    };
  }
}

// ---------------------------------------------------------------------------
// Metrics
// ---------------------------------------------------------------------------

interface Series {
  name: string;
  help: string;
  type: "counter" | "gauge" | "histogram";
  labelNames: string[];
  values: Map<string, any>;
  buckets: number[];
}

/**
 * Prometheus-compatible metrics with no dependency.
 *
 * Cardinality is controlled deliberately: labels are bounded sets. Principal
 * ids, correlation ids and caller-supplied model names never become labels —
 * those belong in the audit trail, which is built for high cardinality, not in
 * a time series.
 */
export class Metrics {
  private readonly series = new Map<string, Series>();

  constructor(
    readonly config: MetricsConfig,
    readonly application = "unknown",
  ) {
    if (!config.enabled) return;
    const b = config.latencyBucketsMs;
    this.counter("requests_total", "AI requests processed by the firewall.", ["stage", "action", "application"]);
    this.counter("detector_runs_total", "Detector executions.", ["detector", "stage", "outcome", "application"]);
    this.counter("detector_hits_total", "Detector detections.", ["detector", "severity", "action", "application"]);
    this.counter("detector_errors_total", "Detector failures.", ["detector", "fail_mode", "application"]);
    this.counter("policy_evaluations_total", "Policy evaluations.", ["policy_id", "action", "application"]);
    this.counter("blocked_total", "Interactions blocked.", ["stage", "category", "application"]);
    this.counter("access_denied_total", "Access control rejections.", ["reason", "application"]);
    this.counter("telemetry_events_total", "Audit events emitted.", ["outcome", "application"]);
    this.counter("telemetry_dropped_total", "Audit events dropped.", ["reason", "application"]);
    this.histogram("pipeline_latency_ms", "Firewall overhead per stage.", ["stage", "application"], b);
    this.histogram("detector_latency_ms", "Per-detector latency.", ["detector", "application"], b);
    this.histogram("policy_latency_ms", "Policy evaluation latency.", ["policy_id", "application"], b);
    this.histogram("model_latency_ms", "Upstream model latency.", ["provider", "application"], [10, 50, 100, 250, 500, 1000, 2500, 5000, 10000, 30000]);
    this.gauge("telemetry_queue_depth", "Pending audit events.", ["application"]);
    this.gauge("info", "Build and configuration info.", ["application", "sdk_version", "environment"]);
  }

  private define(name: string, help: string, type: Series["type"], labelNames: string[], buckets: number[] = []): void {
    this.series.set(name, { name: `${this.config.namespace}_${name}`, help, type, labelNames, values: new Map(), buckets });
  }
  private counter(name: string, help: string, labels: string[]): void {
    this.define(name, help, "counter", labels);
  }
  private gauge(name: string, help: string, labels: string[]): void {
    this.define(name, help, "gauge", labels);
  }
  private histogram(name: string, help: string, labels: string[], buckets: number[]): void {
    this.define(name, help, "histogram", labels, buckets);
  }

  private key(series: Series, labels: Record<string, string>): string {
    return series.labelNames.map((n) => String(labels[n] ?? "")).join(" ");
  }

  inc(name: string, amount = 1, labels: Record<string, string> = {}): void {
    const series = this.series.get(name);
    if (!series) return;
    const key = this.key(series, { application: this.application, ...labels });
    series.values.set(key, (series.values.get(key) ?? 0) + amount);
  }

  gaugeSet(name: string, value: number, labels: Record<string, string> = {}): void {
    const series = this.series.get(name);
    if (!series) return;
    series.values.set(this.key(series, { application: this.application, ...labels }), value);
  }

  observe(name: string, value: number, labels: Record<string, string> = {}): void {
    const series = this.series.get(name);
    if (!series) return;
    const key = this.key(series, { application: this.application, ...labels });
    let state = series.values.get(key);
    if (!state) {
      state = { sum: 0, count: 0, buckets: new Array(series.buckets.length).fill(0) };
      series.values.set(key, state);
    }
    state.sum += value;
    state.count += 1;
    series.buckets.forEach((bound, i) => {
      if (value <= bound) state.buckets[i] += 1;
    });
  }

  /** Prometheus text exposition, for the host app's /metrics handler. */
  render(): string {
    const lines: string[] = [];
    for (const series of this.series.values()) {
      lines.push(`# HELP ${series.name} ${series.help}`, `# TYPE ${series.name} ${series.type}`);
      for (const [key, value] of [...series.values.entries()].sort()) {
        const labels = Object.fromEntries(series.labelNames.map((n, i) => [n, key.split(" ")[i]]));
        const rendered = this.formatLabels(labels);
        if (series.type === "histogram") {
          let cumulative = 0;
          series.buckets.forEach((bound, i) => {
            cumulative += value.buckets[i];
            lines.push(`${series.name}_bucket${this.formatLabels({ ...labels, le: String(bound) })} ${cumulative}`);
          });
          lines.push(`${series.name}_bucket${this.formatLabels({ ...labels, le: "+Inf" })} ${value.count}`);
          lines.push(`${series.name}_sum${rendered} ${value.sum}`);
          lines.push(`${series.name}_count${rendered} ${value.count}`);
        } else {
          lines.push(`${series.name}${rendered} ${value}`);
        }
      }
    }
    return lines.join("\n") + "\n";
  }

  private formatLabels(labels: Record<string, string>): string {
    const parts = Object.entries(labels)
      .filter(([, v]) => v !== "")
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}="${String(v).replace(/\\/g, "\\\\").replace(/"/g, '\\"')}"`);
    return parts.length ? `{${parts.join(",")}}` : "";
  }
}
