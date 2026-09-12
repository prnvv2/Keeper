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

export { Detector, build, detectorInput, register, registered, timed, type DetectorInput } from "./base";
export { AuthorityClaimDetector, TrajectoryDetector } from "./cognitive";
export { INVISIBLE, PromptInjectionDetector, SIGNALS, normalise } from "./injection";
export { BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector } from "./output";
export { PIIDetector, PII_PATTERNS, luhnValid } from "./pii";
export { SecretDetector, VENDOR_PATTERNS, shannonEntropy } from "./secrets";
export { DEFAULT_SINK_RISK, TokenFlowDetector, type FlowRecord } from "./tokenflow";

export const DEFAULT_INPUT_DETECTORS = [
  "secrets",
  "pii",
  "banned_topics",
  "prompt_injection",
  "authority_claim",
  "trajectory",
] as const;

export const DEFAULT_OUTPUT_DETECTORS = ["secret_leakage", "pii", "banned_topics", "groundedness"] as const;

export const DEFAULT_RUNTIME_DETECTORS = ["token_flow", "secrets", "prompt_injection", "authority_claim"] as const;
