/**
 * Built-in detectors. Importing this module registers all of them.
 *
 * Execution order matters: cheap and deterministic first, so that a credential
 * block short-circuits before the conversation-level gates run at all.
 */

import "./secrets.js";
import "./pii.js";
import "./injection.js";
import "./cognitive.js";
import "./tokenflow.js";
import "./output.js";
import "./owasp.js";

export { Detector, build, detectorInput, register, registered, timed, type DetectorInput } from "./base.js";
export { AuthorityClaimDetector, TrajectoryDetector } from "./cognitive.js";
export { INVISIBLE, PromptInjectionDetector, SIGNALS, normalise } from "./injection.js";
export { BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector } from "./output.js";
export { PIIDetector, PII_PATTERNS, luhnValid } from "./pii.js";
export { SecretDetector, VENDOR_PATTERNS, shannonEntropy } from "./secrets.js";
export { DEFAULT_SINK_RISK, TokenFlowDetector, type FlowRecord } from "./tokenflow.js";
export {
  CodeExecutionDetector,
  ResourceAbuseDetector,
  SystemPromptLeakageDetector,
  ToolPoisoningDetector,
  UnsafeOutputDetector,
  newCanary,
  toolFingerprint,
  toolText,
} from "./owasp.js";
export { decodedSegments } from "./injection.js";

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
