/**
 * Threat taxonomy: every finding is named in the frameworks a security team
 * reports against — OWASP Top 10 for LLM Applications 2025 (LLM01–LLM10),
 * OWASP Top 10 for Agentic Applications 2026 (ASI01–ASI10) and the OWASP MCP
 * Top 10 2025 (MCP01–MCP10), with MITRE ATLAS technique cross-references.
 *
 * This is a line-for-line port of `keeper_firewall/taxonomy.py`; the two must
 * agree, because the control plane aggregates events from both SDKs by the
 * threat ids they carry. See that module for the reasoning behind each choice.
 */

import type { Finding, Stage } from "./types";

export const OWASP_LLM = "owasp-llm-2025";
export const OWASP_AGENTIC = "owasp-agentic-2026";
export const OWASP_MCP = "owasp-mcp-2025";
export const FRAMEWORKS = [OWASP_LLM, OWASP_AGENTIC, OWASP_MCP] as const;

export type Coverage = "covered" | "partial" | "observed" | "disabled" | "out_of_scope";

export interface Threat {
  id: string;
  framework: string;
  title: string;
  summary: string;
  baseImpact: number;
  atlas: string[];
  detectors: string[];
  controls: string[];
  coverage: Coverage;
  note: string;
}

export const ATLAS: Record<string, string> = {
  "AML.T0051": "LLM Prompt Injection",
  "AML.T0051.000": "LLM Prompt Injection: Direct",
  "AML.T0051.001": "LLM Prompt Injection: Indirect",
  "AML.T0054": "LLM Jailbreak",
  "AML.T0056": "Extract LLM System Prompt",
  "AML.T0057": "LLM Data Leakage",
  "AML.T0053": "AI Agent Tool Invocation",
  "AML.T0070": "RAG Poisoning",
  "AML.T0080": "AI Agent Context Poisoning",
  "AML.T0048": "External Harms",
  "AML.T0029": "Denial of AI Service",
  "AML.T0034": "Cost Harvesting",
  "AML.T0024": "Exfiltration via AI Inference API",
  "AML.T0010": "AI Supply Chain Compromise",
  "AML.T0020": "Poison Training Data",
};

const t = (
  id: string,
  framework: string,
  title: string,
  summary: string,
  baseImpact: number,
  extra: Partial<Pick<Threat, "atlas" | "detectors" | "controls" | "coverage" | "note">> = {},
): Threat => ({
  id,
  framework,
  title,
  summary,
  baseImpact,
  atlas: extra.atlas ?? [],
  detectors: extra.detectors ?? [],
  controls: extra.controls ?? [],
  coverage: extra.coverage ?? "covered",
  note: extra.note ?? "",
});

const LIST: Threat[] = [
  t("LLM01", OWASP_LLM, "Prompt Injection", "User or third-party content alters the model's behaviour against the operator's intent.", 4,
    { atlas: ["AML.T0051", "AML.T0054"], detectors: ["prompt_injection", "llm_classifier", "trajectory", "authority_claim"],
      note: "Direct, indirect (RAG/tool/memory), encoded and multi-turn variants." }),
  t("LLM02", OWASP_LLM, "Sensitive Information Disclosure", "PII, credentials or confidential data exposed in prompts or responses.", 4,
    { atlas: ["AML.T0057", "AML.T0024"], detectors: ["pii", "secrets", "secret_leakage"], controls: ["redaction"] }),
  t("LLM03", OWASP_LLM, "Supply Chain", "Compromised models, datasets, adapters or plugins.", 4,
    { atlas: ["AML.T0010"], detectors: ["tool_poisoning"], controls: ["model_allowlist"], coverage: "partial",
      note: "Keeper governs which models may be called and pins tool definitions; it cannot vet model weights." }),
  t("LLM04", OWASP_LLM, "Data and Model Poisoning", "Training, fine-tuning or embedding data manipulated to implant behaviour.", 4,
    { atlas: ["AML.T0020", "AML.T0070"], detectors: ["prompt_injection"], coverage: "partial",
      note: "Poisoned retrieval content is screened at the retrieval boundary; training-time poisoning is out of reach." }),
  t("LLM05", OWASP_LLM, "Improper Output Handling", "Model output passed to downstream systems without validation (XSS, SQLi, shell, markdown exfiltration).", 4,
    { atlas: ["AML.T0024"], detectors: ["unsafe_output"] }),
  t("LLM06", OWASP_LLM, "Excessive Agency", "The model is given more functionality, permission or autonomy than the task needs.", 4,
    { atlas: ["AML.T0053"], detectors: ["token_flow"], controls: ["tool_rbac", "tool_risk_tiers", "human_confirmation"] }),
  t("LLM07", OWASP_LLM, "System Prompt Leakage", "Instructions, secrets or business logic in the system prompt revealed to users.", 3,
    { atlas: ["AML.T0056"], detectors: ["system_prompt_leakage", "prompt_injection"] }),
  t("LLM08", OWASP_LLM, "Vector and Embedding Weaknesses", "RAG pipelines ingest or return content that injects, leaks across tenants, or poisons context.", 3,
    { atlas: ["AML.T0070"], detectors: ["prompt_injection", "pii", "secrets"], coverage: "partial",
      note: "Retrieved chunks are screened before entering context; vector-store access control is the store's job." }),
  t("LLM09", OWASP_LLM, "Misinformation", "Confident, ungrounded or fabricated output relied on by users.", 2,
    { detectors: ["groundedness"], coverage: "partial", note: "Lexical groundedness screen; flags, never blocks." }),
  t("LLM10", OWASP_LLM, "Unbounded Consumption", "Excessive or adversarial usage causing denial of service, cost blow-up or model extraction.", 3,
    { atlas: ["AML.T0029", "AML.T0034"], detectors: ["resource_abuse"], controls: ["rate_limits", "token_budgets"] }),
  t("ASI01", OWASP_AGENTIC, "Agent Goal Hijack", "Injected content redirects an agent's objectives, plans or decision path.", 4,
    { atlas: ["AML.T0051.001"], detectors: ["prompt_injection", "trajectory", "token_flow"] }),
  t("ASI02", OWASP_AGENTIC, "Tool Misuse & Exploitation", "An agent uses legitimate tools unsafely: wrong arguments, wrong sink, chained exfiltration.", 4,
    { atlas: ["AML.T0053"], detectors: ["token_flow", "code_execution"], controls: ["tool_rbac", "tool_risk_tiers"] }),
  t("ASI03", OWASP_AGENTIC, "Identity & Privilege Abuse", "Agents inherit, escalate or are tricked into using privileges they should not.", 4,
    { detectors: ["authority_claim"], controls: ["authentication", "rbac", "tool_rbac"] }),
  t("ASI04", OWASP_AGENTIC, "Agentic Supply Chain Vulnerabilities", "Compromised tools, MCP servers, prompts or agents loaded at runtime.", 4,
    { atlas: ["AML.T0010"], detectors: ["tool_poisoning"], controls: ["tool_definition_pinning"], coverage: "partial" }),
  t("ASI05", OWASP_AGENTIC, "Unexpected Code Execution (RCE)", "Agent-generated or injected code/commands executed without sandboxing.", 5,
    { detectors: ["code_execution", "unsafe_output"] }),
  t("ASI06", OWASP_AGENTIC, "Memory & Context Poisoning", "Persistent memory or long context corrupted so future decisions are manipulated.", 4,
    { atlas: ["AML.T0080", "AML.T0070"], detectors: ["prompt_injection", "token_flow"], controls: ["memory_provenance"] }),
  t("ASI07", OWASP_AGENTIC, "Insecure Inter-Agent Communication", "Messages between agents spoofed, tampered or used to smuggle instructions.", 3,
    { detectors: ["prompt_injection", "authority_claim"], controls: ["trust_levels"], coverage: "partial",
      note: "Peer-agent messages are screened as tool-trust content; message signing is out of scope." }),
  t("ASI08", OWASP_AGENTIC, "Cascading Failures", "One faulty or compromised step propagates through a multi-agent workflow.", 3,
    { controls: ["kill_switch", "fail_modes"], coverage: "partial",
      note: "Per-run kill switch halts every later stage of a correlation once tripped." }),
  t("ASI09", OWASP_AGENTIC, "Human-Agent Trust Exploitation", "Agents manipulate humans into approving harmful actions, or humans over-trust agent output.", 3,
    { detectors: ["authority_claim", "groundedness"], controls: ["human_confirmation"], coverage: "partial" }),
  t("ASI10", OWASP_AGENTIC, "Rogue Agents", "Agents acting outside intended scope through drift, compromise or emergent behaviour.", 4,
    { detectors: ["trajectory", "token_flow"], controls: ["kill_switch", "anomaly_detection"], coverage: "partial" }),
  t("MCP01", OWASP_MCP, "Token Mismanagement & Secret Exposure", "Credentials held by or passed through MCP servers leak into context, logs or output.", 5,
    { atlas: ["AML.T0057"], detectors: ["secrets", "secret_leakage"], controls: ["redaction"] }),
  t("MCP02", OWASP_MCP, "Privilege Escalation via Scope Creep", "Tools or servers accumulate permissions beyond what the task requires.", 4,
    { controls: ["tool_rbac", "tool_risk_tiers"], detectors: ["token_flow"] }),
  t("MCP03", OWASP_MCP, "Tool Poisoning", "Malicious instructions hidden in tool names, descriptions or schemas; rug-pull redefinition.", 4,
    { atlas: ["AML.T0051.001"], detectors: ["tool_poisoning"], controls: ["tool_definition_pinning"] }),
  t("MCP04", OWASP_MCP, "Software Supply Chain Attacks & Dependency Tampering", "Compromised MCP server packages or dependencies.", 4,
    { atlas: ["AML.T0010"], controls: ["tool_definition_pinning"], coverage: "partial",
      note: "Definition pinning catches behavioural change; package provenance belongs in your build pipeline." }),
  t("MCP05", OWASP_MCP, "Command Injection & Execution", "Tool arguments reach a shell, interpreter or query engine unsanitised.", 5,
    { detectors: ["code_execution"] }),
  t("MCP06", OWASP_MCP, "Prompt Injection via Contextual Payloads", "Instructions smuggled in tool results, resources or fetched content.", 4,
    { atlas: ["AML.T0051.001"], detectors: ["prompt_injection"] }),
  t("MCP07", OWASP_MCP, "Insufficient Authentication & Authorization", "MCP clients or servers accept unauthenticated or over-authorised calls.", 4,
    { controls: ["authentication", "rbac", "tool_rbac"], coverage: "partial" }),
  t("MCP08", OWASP_MCP, "Lack of Audit and Telemetry", "Tool invocations and context changes are not logged or monitored.", 3,
    { controls: ["audit_events", "metrics", "tracing", "siem_export"] }),
  t("MCP09", OWASP_MCP, "Shadow MCP Servers", "Unapproved MCP servers used outside governance.", 3,
    { controls: ["tool_registry", "fleet_inventory"], coverage: "observed",
      note: "Unregistered tools are refused when a tool registry is configured, and surfaced in the fleet view." }),
  t("MCP10", OWASP_MCP, "Context Injection & Over-Sharing", "More context than necessary (other users' data, secrets) is shared with tools or models.", 3,
    { detectors: ["pii", "secrets"], controls: ["redaction"] }),
];

export const THREATS: Record<string, Threat> = Object.fromEntries(LIST.map((x) => [x.id, x]));
export const THREAT_ORDER: string[] = LIST.map((x) => x.id);

export const CATEGORY_THREATS: Record<string, string[]> = {
  prompt_injection: ["LLM01", "ASI01"],
  authority_manipulation: ["LLM01", "ASI03", "ASI09"],
  multi_turn_attack: ["LLM01", "ASI01"],
  credential_exposure: ["LLM02", "MCP01"],
  data_leakage: ["LLM02", "MCP01"],
  sensitive_data: ["LLM02", "MCP10"],
  content_policy: [],
  hallucination: ["LLM09"],
  unsafe_flow: ["LLM06", "ASI02", "ASI01"],
  excessive_agency: ["LLM06", "ASI02", "MCP02"],
  memory_provenance_laundering: ["ASI06"],
  access_control: ["ASI03", "MCP07"],
  rate_limit: ["LLM10"],
  system_prompt_leakage: ["LLM07"],
  improper_output: ["LLM05"],
  code_execution: ["ASI05", "MCP05"],
  tool_poisoning: ["MCP03", "ASI04", "LLM03"],
  unbounded_consumption: ["LLM10"],
};

const key = (category: string, stage: Stage) => `${category}|${stage}`;

export const STAGE_THREATS: Record<string, string[]> = {
  [key("prompt_injection", "retrieval")]: ["LLM08", "LLM04"],
  [key("prompt_injection", "tool_result")]: ["MCP06"],
  [key("prompt_injection", "memory_write")]: ["ASI06"],
  [key("prompt_injection", "memory_read")]: ["ASI06"],
  [key("prompt_injection", "output")]: ["LLM05"],
  [key("prompt_injection", "tool_definition")]: ["MCP03", "ASI04"],
  [key("sensitive_data", "retrieval")]: ["LLM08"],
  [key("credential_exposure", "tool_call")]: ["ASI02"],
  [key("authority_manipulation", "tool_result")]: ["ASI07"],
};

export const STAGE_OVERRIDES: Record<string, string[]> = {
  [key("unsafe_flow", "memory_write")]: ["ASI06"],
  [key("unsafe_flow", "memory_read")]: ["ASI06"],
};

const INTERNAL = new Set(["firewall_internal", "policy", "unspecified"]);

/** Threat ids for one fired finding at one stage, in stable order. */
export function threatsFor(finding: Finding, stage: Stage): string[] {
  if (!finding.detected || INTERNAL.has(finding.category)) return [];
  const k = key(finding.category, stage);
  const ids = STAGE_OVERRIDES[k]
    ? [...STAGE_OVERRIDES[k]]
    : [...(CATEGORY_THREATS[finding.category] ?? []), ...(STAGE_THREATS[k] ?? [])];
  const explicit = finding.evidence?.threats;
  if (Array.isArray(explicit)) ids.push(...explicit.map(String));
  return [...new Set(ids.filter((id) => id in THREATS))];
}

/** Stamp `threats` onto every finding. Returns the same array. */
export function annotate(findings: Finding[], stage: Stage): Finding[] {
  for (const f of findings) f.threats = threatsFor(f, stage);
  return findings;
}

export interface CoverageRow extends Threat {
  activeDetectors: string[];
  missingDetectors: string[];
  status: Coverage;
  hits: number;
}

/** Which threats this deployment actually covers, given what is switched on. */
export function coverageReport(
  enabledDetectors?: string[],
  frameworks: readonly string[] = FRAMEWORKS,
  hits: Record<string, number> = {},
): CoverageRow[] {
  const enabled = enabledDetectors ? new Set(enabledDetectors) : null;
  return LIST.filter((x) => frameworks.includes(x.framework)).map((threat) => {
    const active = enabled ? threat.detectors.filter((d) => enabled.has(d)) : threat.detectors;
    const missing = enabled ? threat.detectors.filter((d) => !enabled.has(d)) : [];
    let status: Coverage = threat.coverage;
    if (threat.detectors.length && !active.length) status = threat.controls.length ? "observed" : "disabled";
    else if (missing.length && status === "covered") status = "partial";
    return { ...threat, activeDetectors: active, missingDetectors: missing, status, hits: hits[threat.id] ?? 0 };
  });
}
