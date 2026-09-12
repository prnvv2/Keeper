/**
 * Typed client for the control plane's dashboard API.
 *
 * The admin key is held in sessionStorage, not localStorage: it grants read
 * access to the entire audit trail, and sessionStorage at least dies with the
 * tab. Real deployments should front the control plane with SSO and drop this
 * entirely — see docs/deployment.md.
 */

const KEY_STORAGE = "keeper.adminKey";

export type Action = "allow" | "flag" | "redact" | "challenge" | "block";
export type Severity = "info" | "low" | "medium" | "high" | "critical";

export interface Span {
  start: number;
  end: number;
  label: string;
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
  elapsed_ms: number;
  error: string | null;
}

export interface PolicyTrace {
  policy_id: string;
  policy_version: string;
  rule_id: string | null;
  matched: boolean;
  action: Action;
  elapsed_ms: number;
  note: string;
}

export interface AuditEvent {
  event_id: string;
  correlation_id: string;
  timestamp_ms: number;
  received_ms: number;
  stage: string;
  action: Action;
  severity: Severity;
  application: string;
  environment: string;
  instance_id: string | null;
  sdk_version: string | null;
  session_id: string | null;
  principal_id: string | null;
  principal_roles: string[];
  tenant: string | null;
  model: string | null;
  provider: string | null;
  trace_id: string | null;
  policy_version: string | null;
  findings: Finding[];
  policy_traces: PolicyTrace[];
  detectors_fired: string[];
  categories: string[];
  prompt: string | null;
  response: string | null;
  redacted_fields: string[];
  latency_ms: number;
  tokens_in: number | null;
  tokens_out: number | null;
  error: string | null;
  tags: Record<string, unknown>;
}

export interface Overview {
  window_start_ms: number;
  window_hours: number;
  total_events: number;
  by_action: Partial<Record<Action, number>>;
  by_severity: Partial<Record<Severity, number>>;
  top_applications: { application: string; events: number }[];
  blocked: number;
  block_rate: number;
  avg_latency_ms: number;
  max_latency_ms: number;
  active_instances: number;
  top_offenders: { principal_id: string; application: string; blocked_events: number }[];
  recent_alerts: Alert[];
}

export interface TimelineBucket {
  bucket_ms: number;
  total: number;
  allow?: number;
  flag?: number;
  redact?: number;
  challenge?: number;
  block?: number;
}

export interface DetectorStat {
  detector: string;
  runs: number;
  hits: number;
  hit_rate: number;
  errors: number;
  avg_latency_ms: number;
  categories: string[];
  severities: Record<string, number>;
}

export interface PolicyRuleStat {
  policy_id: string;
  rule_id: string | null;
  matches: number;
  actions: Record<string, number>;
  avg_eval_ms: number;
}

export interface AnomalyFinding {
  kind: string;
  title: string;
  description: string;
  severity: Severity;
  score: number;
  entities: Record<string, unknown>;
  evidence: Record<string, unknown>;
  examples: string[];
}

export interface Instance {
  instance_id: string;
  application: string;
  environment: string;
  sdk_version: string | null;
  language: string;
  policy_id: string | null;
  policy_version: string | null;
  detectors: string[];
  monitor_only: boolean;
  first_seen_ms: number;
  last_seen_ms: number;
  events_received: number;
  status: "healthy" | "stale";
  health: Record<string, unknown>;
}

export interface Alert {
  id: string;
  rule_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  created_ms: number;
  acknowledged_ms: number | null;
  acknowledged_by: string | null;
  context: Record<string, any>;
  delivery: { channel: string; status: string; error?: string }[];
}

export interface AlertRule {
  id: string;
  name: string;
  description: string;
  enabled: boolean;
  kind: "match" | "threshold" | "anomaly";
  spec: Record<string, unknown>;
  severity: Severity;
  channels: string[];
  cooldown_s: number;
  last_fired_ms: number | null;
}

export interface PolicyRecord {
  bundle: string;
  version: string;
  etag: string;
  document: Record<string, any>;
  published: boolean;
  created_ms: number;
  created_by: string | null;
  note: string;
}

export interface EventPage {
  events: AuditEvent[];
  total: number;
  limit: number;
  offset: number;
}

export interface CorrelationView {
  correlation_id: string;
  events: AuditEvent[];
  summary: {
    application: string;
    principal_id: string | null;
    session_id: string | null;
    model: string | null;
    trace_id: string | null;
    policy_version: string | null;
    started_ms: number;
    ended_ms: number;
    duration_ms: number;
    stages: string[];
    outcome: Action;
    detectors_fired: string[];
  };
}

export interface DryRunReport {
  policy: string;
  events_replayed: number;
  changed: number;
  transitions: Record<string, number>;
  examples: { event_id: string; correlation_id: string; from: string; to: string; rules: string[] }[];
}

export class ApiError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
  }
  get isAuth() {
    return this.status === 401 || this.status === 403;
  }
}

export function getKey(): string {
  return sessionStorage.getItem(KEY_STORAGE) ?? "";
}

export function setKey(key: string): void {
  if (key) sessionStorage.setItem(KEY_STORAGE, key);
  else sessionStorage.removeItem(KEY_STORAGE);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const key = getKey();
  const response = await fetch(path, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...(key ? { Authorization: `Bearer ${key}` } : {}),
      ...(init.headers ?? {}),
    },
  });
  if (!response.ok) {
    let detail = response.statusText;
    try {
      const body = await response.json();
      detail = body.detail ?? detail;
    } catch {
      /* a non-JSON error body is still an error */
    }
    throw new ApiError(response.status, typeof detail === "string" ? detail : JSON.stringify(detail));
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

function query(params: Record<string, unknown>): string {
  const search = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && value !== "") search.set(key, String(value));
  }
  const qs = search.toString();
  return qs ? `?${qs}` : "";
}

export const api = {
  health: () => request<Record<string, any>>("/health"),

  overview: (hours = 24, environment?: string) =>
    request<Overview>(`/api/overview${query({ hours, environment })}`),

  timeline: (hours = 6, bucketMinutes = 1, application?: string) =>
    request<{ buckets: TimelineBucket[]; bucket_minutes: number }>(
      `/api/timeline${query({ hours, bucket_minutes: bucketMinutes, application })}`,
    ),

  events: (filters: Record<string, unknown>) => request<EventPage>(`/api/events${query(filters)}`),

  event: (id: string) => request<AuditEvent>(`/api/events/${encodeURIComponent(id)}`),

  correlation: (id: string) =>
    request<CorrelationView>(`/api/events/correlation/${encodeURIComponent(id)}`),

  detectorStats: (hours = 24) =>
    request<{ detectors: DetectorStat[] }>(`/api/analytics/detectors${query({ hours })}`),

  policyStats: (hours = 24) =>
    request<{ rules: PolicyRuleStat[] }>(`/api/analytics/policy${query({ hours })}`),

  anomalies: (minutes = 15) =>
    request<{ findings: AnomalyFinding[] }>(`/api/analytics/anomalies${query({ minutes })}`),

  fleet: () =>
    request<{
      instances: Instance[];
      total: number;
      healthy: number;
      stale: number;
      sdk_versions: Record<string, number>;
      policy_versions: Record<string, number>;
      monitor_only: string[];
    }>("/api/fleet"),

  policies: (bundle?: string) =>
    request<{ policies: PolicyRecord[] }>(`/api/policies${query({ bundle })}`),

  publishPolicy: (bundle: string, policy: unknown, publish: boolean, note = "") =>
    request<{ status: string; policy: PolicyRecord }>("/api/policies", {
      method: "POST",
      body: JSON.stringify({ bundle, policy, publish, note }),
    }),

  dryRun: (policy: unknown, hours = 24) =>
    request<DryRunReport>("/api/policies/dry-run", {
      method: "POST",
      body: JSON.stringify({ policy, hours }),
    }),

  alerts: (unacknowledgedOnly = false) =>
    request<{ alerts: Alert[] }>(`/api/alerts${query({ unacknowledged_only: unacknowledgedOnly })}`),

  acknowledge: (id: string) =>
    request<{ status: string }>(`/api/alerts/${encodeURIComponent(id)}/acknowledge`, { method: "POST" }),

  alertRules: () => request<{ rules: AlertRule[] }>("/api/alert-rules"),

  saveAlertRule: (rule: Partial<AlertRule>) =>
    request<{ rule: AlertRule }>("/api/alert-rules", { method: "PUT", body: JSON.stringify(rule) }),

  deleteAlertRule: (id: string) =>
    request<{ status: string }>(`/api/alert-rules/${encodeURIComponent(id)}`, { method: "DELETE" }),

  testAlert: (channels: string[]) =>
    request<{ delivery: { channel: string; status: string }[] }>("/api/alerts/test", {
      method: "POST",
      body: JSON.stringify({ channels }),
    }),
};
