/**
 * Built-in detectors. Importing this module registers all of them.
 *
 * Execution order matters: cheap and deterministic first, so that a credential
 * block short-circuits before the conversation-level gates run at all.
 */

import "./secrets";
import "./pii";
import "./injection";
import "./cognitive";
import "./tokenflow";
import "./output";
import "./owasp";

export { Detector, build, detectorInput, register, registered, timed, type DetectorInput } from "./base";
export { AuthorityClaimDetector, TrajectoryDetector } from "./cognitive";
export { INVISIBLE, PromptInjectionDetector, SIGNALS, normalise } from "./injection";
export { BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector } from "./output";
export { PIIDetector, PII_PATTERNS, luhnValid } from "./pii";
export { SecretDetector, VENDOR_PATTERNS, shannonEntropy } from "./secrets";
export { DEFAULT_SINK_RISK, TokenFlowDetector, type FlowRecord } from "./tokenflow";
export {
  CodeExecutionDetector,
  ResourceAbuseDetector,
  SystemPromptLeakageDetector,
  ToolPoisoningDetector,
  UnsafeOutputDetector,
  newCanary,
  toolFingerprint,
  toolText,
} from "./owasp";
export { decodedSegments } from "./injection";

export const DEFAULT_INPUT_DETECTORS = [
  "resource_abuse",
  "secrets",
  "pii",
  "banned_topics",
  "prompt_injection",
  "authority_claim",
  "trajectory",
] as const;

export const DEFAULT_OUTPUT_DETECTORS = [
  "secret_leakage",
  "system_prompt_leakage",
  "unsafe_output",
  "pii",
  "banned_topics",
  "groundedness",
] as const;

// code_execution first: an outright execution payload should win the
// short-circuit with the more specific ASI05/MCP05 attribution.
export const DEFAULT_RUNTIME_DETECTORS = ["code_execution", "token_flow", "secrets", "prompt_injection", "authority_claim"] as const;
