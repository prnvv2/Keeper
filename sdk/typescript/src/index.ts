/**
 * Keeper — an open-source AI firewall for developers and security teams.
 *
 * ```ts
 * import { Keeper } from "keeper-firewall";
 *
 * const keeper = new Keeper({ application: "support-bot" });
 * const reply = await keeper.chat("Summarise ticket 4182");
 * console.log(reply.text, reply.correlationId);
 * ```
 *
 * Every decision produces a structured audit event. With no control plane
 * configured those stay local; point `telemetry.endpoint` at a Keeper control
 * plane and the same events feed the dashboard, alerting, and your SIEM.
 */

export { Keeper, type ContextOptions, type KeeperInit } from "./client.js";
export {
  FAIL_CLOSED,
  FAIL_OPEN,
  defaultConfig,
  defaultDetectors,
  loadConfig,
  type AccessControlConfig,
  type DetectorConfig,
  type KeeperConfig,
  type KeeperOptions,
  type MetricsConfig,
  type PolicyConfig,
  type RedactionConfig,
  type RuntimeConfig,
  type TelemetryConfig,
} from "./config.js";
export {
  AuthenticationError,
  AuthorizationError,
  BlockedError,
  ConfigurationError,
  DetectorError,
  KeeperError,
  PolicyError,
  RateLimitError,
  TransportError,
} from "./errors.js";
export {
  DEFAULT_INPUT_DETECTORS,
  DEFAULT_OUTPUT_DETECTORS,
  DEFAULT_RUNTIME_DETECTORS,
  Detector,
  build as buildDetector,
  detectorInput,
  register as registerDetector,
  registered as registeredDetectors,
  type DetectorInput,
} from "./detectors/index.js";
export {
  EventBuilder,
  FanoutSink,
  MemorySink,
  Metrics,
  Redactor,
  StreamSink,
  CallbackSink,
  securityRelevant,
  type Sink,
} from "./observability.js";
export { Pipeline, type EvaluateOptions } from "./pipeline.js";
export {
  PolicyEngine,
  PolicyProvider,
  SAFE_DEFAULT_POLICY,
  buildFacts,
  compileCondition,
  parsePolicy,
  policyRef,
  safeDefaultPolicy,
  type Policy,
  type Rule,
} from "./policy.js";
export {
  AnthropicProvider,
  CallableProvider,
  EchoProvider,
  OpenAICompatibleProvider,
  parseToolCalls,
  type Provider,
} from "./providers.js";
export {
  KillSwitch,
  MemoryFirewall,
  StreamGuard,
  ToolGuard,
  defaultToolSpecs,
  type MemoryGateResult,
  type StreamResult,
  type ToolSpec,
} from "./runtime.js";
export {
  CodeExecutionDetector,
  ResourceAbuseDetector,
  SystemPromptLeakageDetector,
  ToolPoisoningDetector,
  UnsafeOutputDetector,
  decodedSegments,
  newCanary,
  toolFingerprint,
  toolText,
} from "./detectors/index.js";
export {
  ATLAS,
  CATEGORY_THREATS,
  FRAMEWORKS,
  OWASP_AGENTIC,
  OWASP_LLM,
  OWASP_MCP,
  THREATS,
  THREAT_ORDER,
  annotate,
  coverageReport,
  threatsFor,
  type Coverage,
  type CoverageRow,
  type Threat,
} from "./taxonomy.js";
export {
  DEFAULT_BAND_ACTIONS,
  RiskEngine,
  bandFor,
  bandRank,
  defaultRiskConfig,
  explainRisk,
  parseRiskConfig,
  riskMatrix,
  serialiseRisk,
  type RiskAssessment,
  type RiskBand,
  type RiskConfig,
  type ThreatRisk,
} from "./risk.js";
export { Authorizer, RateLimiter, authorizerFromPolicy, parsePermission, type Quota } from "./accesscontrol.js";
export { ControlPlaneClient, TelemetryShipper } from "./transport.js";
export * from "./types.js";
