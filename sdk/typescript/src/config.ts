/**
 * Configuration, layered: defaults -> environment (`KEEPER_*`) -> constructor
 * options. Same precedence as the Python SDK, same fail-mode reasoning.
 */

import { ConfigurationError } from "./errors";
import { newId } from "./types";

export const FAIL_OPEN = "open";
export const FAIL_CLOSED = "closed";
export type FailMode = typeof FAIL_OPEN | typeof FAIL_CLOSED;

export interface DetectorConfig {
  enabled: boolean;
  /** What happens when the detector itself fails — not when it detects. */
  failMode: FailMode;
  timeoutMs: number;
  threshold: number;
  action?: string;
  options: Record<string, any>;
}

export interface TelemetryConfig {
  enabled: boolean;
  endpoint?: string;
  apiKey?: string;
  batchSize: number;
  flushIntervalMs: number;
  queueCapacity: number;
  timeoutMs: number;
  maxRetries: number;
  localLogStdout: boolean;
}

export interface RedactionConfig {
  mode: "none" | "redacted" | "full" | "hash_only";
  includePrompt: boolean;
  includeResponse: boolean;
  maxChars: number;
  hashPayloads: boolean;
  hashSalt?: string;
  extraPatterns: string[];
}

export interface MetricsConfig {
  enabled: boolean;
  namespace: string;
  latencyBucketsMs: number[];
}

export interface PolicyConfig {
  source: "local" | "control_plane";
  document?: Record<string, any>;
  bundle: string;
  refreshIntervalS: number;
  unreachableBehavior: "last_known_good" | "safe_default" | "fail_open";
  maxStalenessS: number;
  dryRun: boolean;
}

export interface AccessControlConfig {
  enabled: boolean;
  requireAuthentication: boolean;
  rateLimitEnabled: boolean;
  defaultRpm: number;
  defaultBurst: number;
}

export interface RuntimeConfig {
  toolGuardrailsEnabled: boolean;
  toolAllowlist: string[];
  toolDenylist: string[];
  screenToolResults: boolean;
  screenRetrievedDocuments: boolean;
  streamMonitoringEnabled: boolean;
  streamCheckEveryChars: number;
  streamFastThreshold: number;
  streamBreakThreshold: number;
  memoryProvenanceEnabled: boolean;
  failMode: FailMode;
  timeoutMs: number;
}

export interface KeeperConfig {
  application: string;
  environment: string;
  instanceId: string;
  enabled: boolean;
  monitorOnly: boolean;
  detectors: Record<string, DetectorConfig>;
  telemetry: TelemetryConfig;
  redaction: RedactionConfig;
  metrics: MetricsConfig;
  policy: PolicyConfig;
  accessControl: AccessControlConfig;
  runtime: RuntimeConfig;
  inputBudgetMs: number;
  outputBudgetMs: number;
  failMode: FailMode;
}

export type KeeperOptions = DeepPartial<KeeperConfig>;

type DeepPartial<T> = {
  [K in keyof T]?: T[K] extends Record<string, any> ? (T[K] extends any[] ? T[K] : DeepPartial<T[K]>) : T[K];
};

const detector = (over: Partial<DetectorConfig> = {}): DetectorConfig => ({
  enabled: true,
  failMode: FAIL_OPEN,
  timeoutMs: 150,
  threshold: 0.5,
  options: {},
  ...over,
});

/**
 * Detector defaults.
 *
 * Deterministic local detectors fail closed — if the secret scanner cannot
 * run, we do not know whether a live credential is about to leave. Everything
 * probabilistic or network-bound fails open, because turning a detection
 * outage into a traffic outage is the wrong trade.
 */
export function defaultDetectors(): Record<string, DetectorConfig> {
  return {
    secrets: detector({ failMode: FAIL_CLOSED, timeoutMs: 50 }),
    pii: detector({ failMode: FAIL_CLOSED, timeoutMs: 80 }),
    prompt_injection: detector({ timeoutMs: 120, threshold: 0.6 }),
    authority_claim: detector({ timeoutMs: 50, threshold: 0.5 }),
    trajectory: detector({ timeoutMs: 80, threshold: 0.65 }),
    banned_topics: detector({ timeoutMs: 50 }),
    secret_leakage: detector({ failMode: FAIL_CLOSED, timeoutMs: 50 }),
    groundedness: detector({ enabled: false, timeoutMs: 200 }),
    token_flow: detector({ failMode: FAIL_CLOSED, timeoutMs: 100 }),
  };
}

export function defaultConfig(): KeeperConfig {
  return {
    application: "unknown",
    environment: "production",
    instanceId: newId("inst_"),
    enabled: true,
    monitorOnly: false,
    detectors: defaultDetectors(),
    telemetry: {
      enabled: true,
      batchSize: 50,
      flushIntervalMs: 2000,
      queueCapacity: 10_000,
      timeoutMs: 3000,
      maxRetries: 3,
      localLogStdout: false,
    },
    redaction: {
      mode: "redacted",
      includePrompt: true,
      includeResponse: true,
      maxChars: 4000,
      hashPayloads: true,
      extraPatterns: [],
    },
    metrics: { enabled: true, namespace: "keeper", latencyBucketsMs: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500] },
    policy: {
      source: "local",
      bundle: "default",
      refreshIntervalS: 60,
      unreachableBehavior: "last_known_good",
      maxStalenessS: 3600,
      dryRun: false,
    },
    accessControl: {
      enabled: false,
      requireAuthentication: true,
      rateLimitEnabled: true,
      defaultRpm: 120,
      defaultBurst: 20,
    },
    runtime: {
      toolGuardrailsEnabled: true,
      toolAllowlist: [],
      toolDenylist: [],
      screenToolResults: true,
      screenRetrievedDocuments: true,
      streamMonitoringEnabled: true,
      streamCheckEveryChars: 120,
      streamFastThreshold: 0.45,
      streamBreakThreshold: 0.75,
      memoryProvenanceEnabled: true,
      failMode: FAIL_CLOSED,
      timeoutMs: 500,
    },
    inputBudgetMs: 250,
    outputBudgetMs: 250,
    failMode: FAIL_OPEN,
  };
}

const ENV_MAP: [string, string[]][] = [
  ["KEEPER_APPLICATION", ["application"]],
  ["KEEPER_ENVIRONMENT", ["environment"]],
  ["KEEPER_MONITOR_ONLY", ["monitorOnly"]],
  ["KEEPER_FAIL_MODE", ["failMode"]],
  ["KEEPER_ENDPOINT", ["telemetry", "endpoint"]],
  ["KEEPER_API_KEY", ["telemetry", "apiKey"]],
  ["KEEPER_TELEMETRY_ENABLED", ["telemetry", "enabled"]],
  ["KEEPER_REDACTION_MODE", ["redaction", "mode"]],
  ["KEEPER_REDACTION_SALT", ["redaction", "hashSalt"]],
  ["KEEPER_POLICY_SOURCE", ["policy", "source"]],
  ["KEEPER_POLICY_BUNDLE", ["policy", "bundle"]],
  ["KEEPER_POLICY_DRY_RUN", ["policy", "dryRun"]],
  ["KEEPER_ACCESS_CONTROL_ENABLED", ["accessControl", "enabled"]],
];

const TRUE = new Set(["1", "true", "yes", "on"]);
const FALSE = new Set(["0", "false", "no", "off"]);

function coerce(value: unknown, current: unknown): unknown {
  if (typeof current === "boolean") {
    if (typeof value === "string") {
      const low = value.trim().toLowerCase();
      if (TRUE.has(low)) return true;
      if (FALSE.has(low)) return false;
      throw new ConfigurationError(`cannot read '${value}' as a boolean`);
    }
    return Boolean(value);
  }
  if (typeof current === "number" && typeof value === "string") {
    const parsed = Number(value);
    if (Number.isNaN(parsed)) throw new ConfigurationError(`cannot read '${value}' as a number`);
    return parsed;
  }
  return value;
}

function merge(target: any, source: any): void {
  for (const [key, value] of Object.entries(source ?? {})) {
    if (value === undefined) continue;
    const current = target[key];
    if (key === "detectors" && value && typeof value === "object") {
      for (const [name, override] of Object.entries(value as Record<string, any>)) {
        target.detectors[name] = { ...detector(), ...(target.detectors[name] ?? {}), ...override };
      }
    } else if (current && typeof current === "object" && !Array.isArray(current) && typeof value === "object" && !Array.isArray(value)) {
      merge(current, value);
    } else {
      target[key] = coerce(value, current);
    }
  }
}

function envOverrides(env: Record<string, string | undefined>): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [key, path] of ENV_MAP) {
    const value = env[key];
    if (value === undefined) continue;
    let cursor = out;
    for (const part of path.slice(0, -1)) cursor = cursor[part] ??= {};
    cursor[path[path.length - 1]] = value;
  }
  return out;
}

export function loadConfig(options: KeeperOptions = {}, env = globalThis.process?.env ?? {}): KeeperConfig {
  const config = defaultConfig();
  merge(config, envOverrides(env as Record<string, string | undefined>));
  merge(config, options);
  validate(config);
  return config;
}

export function validate(config: KeeperConfig): void {
  if (config.failMode !== FAIL_OPEN && config.failMode !== FAIL_CLOSED) {
    throw new ConfigurationError(`failMode must be 'open' or 'closed', got '${config.failMode}'`);
  }
  if (!["none", "redacted", "full", "hash_only"].includes(config.redaction.mode)) {
    throw new ConfigurationError(`unknown redaction mode '${config.redaction.mode}'`);
  }
  if (config.policy.source === "control_plane" && !config.telemetry.endpoint) {
    throw new ConfigurationError("policy.source='control_plane' requires telemetry.endpoint");
  }
}
