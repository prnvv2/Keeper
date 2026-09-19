/**
 * Talking to the control plane: HTTP client and asynchronous telemetry
 * shipping.
 *
 * Built on `fetch`, which is standard in Node 18+, Deno, Bun and the browser —
 * no HTTP dependency for a package that gets installed into other people's
 * applications.
 *
 * The single hardest non-functional requirement: the control plane must never
 * be a synchronous dependency of the request path. An AI firewall that adds
 * the control plane's availability to every LLM call has made the application
 * strictly less reliable than it was before.
 */

import type { TelemetryConfig } from "./config.js";
import { TransportError } from "./errors.js";
import type { Metrics } from "./observability.js";
import { securityRelevant } from "./observability.js";
import type { AuditEvent } from "./types.js";
import { SDK_VERSION } from "./types.js";

export interface HttpResponse {
  status: number;
  headers: Headers;
  body: string;
  json<T = unknown>(): T | null;
  ok: boolean;
}

export class ControlPlaneClient {
  constructor(
    readonly baseUrl: string,
    private readonly options: { apiKey?: string; timeoutMs?: number; headers?: Record<string, string> } = {},
  ) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
  }

  async request(method: string, path: string, init: { body?: unknown; headers?: Record<string, string> } = {}): Promise<HttpResponse> {
    const url = path.startsWith("http") ? path : `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.options.timeoutMs ?? 3000);
    const headers: Record<string, string> = {
      "User-Agent": `keeper-firewall-node/${SDK_VERSION}`,
      Accept: "application/json",
      ...this.options.headers,
      ...init.headers,
    };
    if (this.options.apiKey) headers.Authorization = `Bearer ${this.options.apiKey}`;
    if (init.body !== undefined) headers["Content-Type"] = "application/json";

    try {
      const response = await fetch(url, {
        method,
        headers,
        body: init.body === undefined ? undefined : JSON.stringify(init.body),
        signal: controller.signal,
      });
      const body = await response.text();
      return {
        status: response.status,
        headers: response.headers,
        body,
        ok: response.ok,
        json<T>() {
          if (!body) return null;
          try {
            return JSON.parse(body) as T;
          } catch {
            return null;
          }
        },
      };
    } catch (error) {
      throw new TransportError(`${method} ${url} failed: ${String(error)}`);
    } finally {
      clearTimeout(timeout);
    }
  }

  shipEvents(events: AuditEvent[], instanceId: string): Promise<HttpResponse> {
    return this.request("POST", "/v1/telemetry/events", { body: { instance_id: instanceId, events } });
  }

  async fetchPolicy(bundle: string, etag?: string): Promise<{ status: number; etag?: string; policy?: Record<string, any> }> {
    const response = await this.request("GET", `/v1/policies/${encodeURIComponent(bundle)}`, {
      headers: etag ? { "If-None-Match": etag } : {},
    });
    if (response.status === 304) return { status: 304, etag };
    if (!response.ok) throw new TransportError(`policy fetch returned HTTP ${response.status}`);
    const body = response.json<{ policy?: Record<string, any>; etag?: string }>() ?? {};
    return {
      status: response.status,
      etag: response.headers.get("etag") ?? body.etag ?? undefined,
      policy: body.policy ?? (body as Record<string, any>),
    };
  }

  registerInstance(payload: Record<string, unknown>): Promise<HttpResponse> {
    return this.request("POST", "/v1/fleet/register", { body: payload });
  }

  heartbeat(payload: Record<string, unknown>): Promise<HttpResponse> {
    return this.request("POST", "/v1/fleet/heartbeat", { body: payload });
  }

  checkQuota(payload: Record<string, unknown>): Promise<HttpResponse> {
    return this.request("POST", "/v1/quota/check", { body: payload });
  }
}

/**
 * Batches audit events and ships them in the background.
 *
 * `emit` never blocks and never throws. The queue is bounded; when it fills,
 * low-severity events are evicted first, because an audit trail that loses the
 * block records under load is worse than useless. Failed batches retry with
 * backoff and are then dropped rather than retried forever — unbounded retry
 * against a struggling control plane is how a degraded service becomes an
 * outage. Every drop increments a counter, so "we stopped seeing audit events"
 * is itself alertable.
 */
export class TelemetryShipper {
  private readonly queue: AuditEvent[] = [];
  private timer?: ReturnType<typeof setInterval>;
  private sending = false;
  private stopped = false;
  private shipped = 0;
  private dropped = 0;
  private failedBatches = 0;
  private lastError: string | null = null;
  private lastSuccessMs: number | null = null;

  constructor(
    private readonly config: TelemetryConfig,
    private readonly instanceId: string,
    private readonly client?: ControlPlaneClient,
    private readonly metrics?: Metrics,
  ) {
    if (!this.enabled) return;
    this.timer = setInterval(() => void this.drain(), config.flushIntervalMs);
    // Never keep a Node process alive just to flush telemetry.
    (this.timer as any)?.unref?.();
  }

  get enabled(): boolean {
    return Boolean(this.config.enabled && this.client);
  }

  emit(event: AuditEvent): void {
    if (!this.enabled) return;
    if (this.queue.length >= this.config.queueCapacity && !this.makeRoom(event)) {
      this.dropped += 1;
      this.metrics?.inc("telemetry_dropped_total", 1, { reason: "queue_full" });
      return;
    }
    this.queue.push(event);
    this.metrics?.gaugeSet("telemetry_queue_depth", this.queue.length);
    if (this.queue.length >= this.config.batchSize) void this.drain();
  }

  /** Evict a droppable event. Only allow-path events are droppable. */
  private makeRoom(incoming: AuditEvent): boolean {
    const index = this.queue.findIndex((queued) => !securityRelevant(queued));
    if (index >= 0) {
      this.queue.splice(index, 1);
      this.dropped += 1;
      this.metrics?.inc("telemetry_dropped_total", 1, { reason: "evicted_low_severity" });
      return true;
    }
    if (securityRelevant(incoming)) {
      this.queue.shift();
      this.dropped += 1;
      this.metrics?.inc("telemetry_dropped_total", 1, { reason: "evicted_security_event" });
      return true;
    }
    return false;
  }

  private async drain(): Promise<void> {
    if (this.sending || !this.enabled) return;
    this.sending = true;
    try {
      while (this.queue.length) {
        const batch = this.queue.splice(0, this.config.batchSize);
        this.metrics?.gaugeSet("telemetry_queue_depth", this.queue.length);
        await this.send(batch);
      }
    } finally {
      this.sending = false;
    }
  }

  private async send(batch: AuditEvent[]): Promise<void> {
    let delay = 250;
    for (let attempt = 0; attempt <= this.config.maxRetries; attempt++) {
      try {
        const response = await this.client!.shipEvents(batch, this.instanceId);
        if (response.ok) {
          this.shipped += batch.length;
          this.lastSuccessMs = Date.now();
          this.metrics?.inc("telemetry_events_total", batch.length, { outcome: "shipped" });
          return;
        }
        if (response.status >= 400 && response.status < 500 && response.status !== 408 && response.status !== 429) {
          // A rejected batch will be rejected again: schema mismatch, bad
          // credentials. Retrying is pure noise.
          this.fail(`control plane rejected batch: HTTP ${response.status}`, batch, "rejected");
          return;
        }
        this.lastError = `HTTP ${response.status}`;
      } catch (error) {
        this.lastError = String(error);
      }
      if (attempt < this.config.maxRetries) {
        await new Promise((resolve) => setTimeout(resolve, delay + Math.random() * delay));
        delay = Math.min(delay * 2, 8000);
      }
    }
    this.fail(`giving up after ${this.config.maxRetries} retries: ${this.lastError}`, batch, "unreachable");
  }

  private fail(message: string, batch: AuditEvent[], reason: string): void {
    this.failedBatches += 1;
    this.lastError = message;
    this.dropped += batch.length;
    this.metrics?.inc("telemetry_dropped_total", batch.length, { reason });
  }

  /** Block until the queue drains or the timeout elapses. Call before exit. */
  async flush(timeoutMs = 5000): Promise<boolean> {
    if (!this.enabled) return true;
    const deadline = Date.now() + timeoutMs;
    await this.drain();
    while (this.queue.length && Date.now() < deadline) {
      await new Promise((resolve) => setTimeout(resolve, 20));
      await this.drain();
    }
    return this.queue.length === 0;
  }

  async close(): Promise<void> {
    if (this.stopped) return;
    this.stopped = true;
    if (this.timer) clearInterval(this.timer);
    await this.flush(this.config.timeoutMs);
  }

  health(): Record<string, unknown> {
    return {
      enabled: this.enabled,
      endpoint: this.config.endpoint,
      queueDepth: this.queue.length,
      queueCapacity: this.config.queueCapacity,
      shipped: this.shipped,
      dropped: this.dropped,
      failedBatches: this.failedBatches,
      lastError: this.lastError,
      lastSuccessMs: this.lastSuccessMs,
      healthy: this.failedBatches === 0 || this.lastSuccessMs !== null,
    };
  }
}
