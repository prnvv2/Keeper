# OWASP coverage

Keeper names every decision in the terms security programmes report against:

- **OWASP Top 10 for LLM Applications 2025**: `LLM01`–`LLM10`
- **OWASP Top 10 for Agentic Applications 2026**: `ASI01`–`ASI10`
- **OWASP MCP Top 10 2025**: `MCP01`–`MCP10`
- **MITRE ATLAS** technique ids, as cross-references on each threat

Each finding gets a `threats` list, and each decision and audit event carries
the union. That's why these questions each have a one-line answer: "how many
LLM01 events did we block this week?", "are we seeing ASI06 anywhere?", "what's
our MCP03 exposure?"

```bash
keeper coverage                                   # this configuration, all three lists
keeper coverage --framework owasp-agentic-2026 -v # one list, with notes
keeper coverage --json                            # for CI / compliance evidence
```

```python
keeper.coverage()                      # same report, from the running instance
decision.threats                       # ('LLM01', 'ASI01')
```

In the dashboard, **Risk & OWASP** shows every threat with its coverage and
fleet-wide hit count. The audit log filters by `?threat=LLM01`.

The mapping lives in one module, [`sdk/python/keeper_firewall/taxonomy.py`](../sdk/python/keeper_firewall/taxonomy.py),
mirrored line for line in [`sdk/typescript/src/taxonomy.ts`](../sdk/typescript/src/taxonomy.ts).
The control plane imports the Python one, so the SDKs, the CLI and the dashboard
can't disagree about what an id means.

---

## How a finding becomes a threat id

Mapping has three layers, applied in order:

1. **By category.** Each detector has a category (`prompt_injection`,
   `credential_exposure`, `code_execution`, and so on), and each category maps
   to its default threats.
2. **By boundary.** Where the content crossed matters. A `prompt_injection`
   finding is:
   - `LLM01 + ASI01` in user input
   - `+ LLM08 + LLM04` in a retrieved RAG chunk
   - `+ MCP06` in a tool or MCP result
   - `+ ASI06` on a memory write
   - `+ MCP03 + ASI04` inside a tool definition

   A few stage rules *replace* the category mapping instead of extending it.
   For example, an `unsafe_flow` finding on a memory write is ASI06 only, not
   excessive agency.
3. **By the detector itself.** A detector can name extra threats with
   `evidence["threats"] = [...]`. Custom detectors use this to be precise
   without editing the taxonomy. Unknown ids are dropped.

## Coverage levels

| Status | Meaning |
|---|---|
| **covered** | Runtime detection and enforcement for the attack paths reachable from the request path. |
| **partial** | Some paths are enforced; others are out of reach of a runtime firewall. The note says which. |
| **observed** | No detector. Keeper records the relevant telemetry (fleet inventory, tool registry) so the gap is visible. |
| **disabled** | Keeper has a detector for it, and your configuration switched it off. |
| **out of scope** | Not addressable from the request path at all. |

Coverage is computed against the detectors actually enabled. Switching off
`groundedness` turns LLM09 from `partial` to `disabled` in the report, because
a coverage report that ignores configuration isn't evidence of anything.

## The mapping

These tables are generated from `taxonomy.py`; "Default status" is what
`keeper coverage` reports with the default configuration.

### OWASP Top 10 for LLM Applications 2025

| ID | Threat | Default status | Detectors | Other controls | Base impact | MITRE ATLAS |
|---|---|---|---|---|---|---|
| **LLM01** | Prompt Injection | partial | `prompt_injection`, `llm_classifier`, `trajectory`, `authority_claim` | — | 4 | AML.T0051 AML.T0054 |
| **LLM02** | Sensitive Information Disclosure | covered | `pii`, `secrets`, `secret_leakage` | redaction | 4 | AML.T0057 AML.T0024 |
| **LLM03** | Supply Chain | partial | `tool_poisoning` | model_allowlist | 4 | AML.T0010 |
| **LLM04** | Data and Model Poisoning | partial | `prompt_injection` | — | 4 | AML.T0020 AML.T0070 |
| **LLM05** | Improper Output Handling | covered | `unsafe_output` | — | 4 | AML.T0024 |
| **LLM06** | Excessive Agency | covered | `token_flow` | tool_rbac, tool_risk_tiers, human_confirmation | 4 | AML.T0053 |
| **LLM07** | System Prompt Leakage | covered | `system_prompt_leakage`, `prompt_injection` | — | 3 | AML.T0056 |
| **LLM08** | Vector and Embedding Weaknesses | partial | `prompt_injection`, `pii`, `secrets` | — | 3 | AML.T0070 |
| **LLM09** | Misinformation | disabled | `groundedness` | — | 2 | — |
| **LLM10** | Unbounded Consumption | covered | `resource_abuse` | rate_limits, token_budgets | 3 | AML.T0029 AML.T0034 |

- **LLM01** — Direct, indirect (RAG/tool/memory), encoded and multi-turn variants.
- **LLM03** — Keeper governs which models may be called and pins tool definitions; it cannot vet model weights.
- **LLM04** — Poisoned retrieval content is screened at the retrieval boundary; training-time poisoning is out of reach.
- **LLM08** — Retrieved chunks are screened before entering context; vector-store access control is the store's job.
- **LLM09** — Lexical groundedness screen; flags, never blocks.

### OWASP Top 10 for Agentic Applications 2026

| ID | Threat | Default status | Detectors | Other controls | Base impact | MITRE ATLAS |
|---|---|---|---|---|---|---|
| **ASI01** | Agent Goal Hijack | covered | `prompt_injection`, `trajectory`, `token_flow` | — | 4 | AML.T0051.001 |
| **ASI02** | Tool Misuse & Exploitation | covered | `token_flow`, `code_execution` | tool_rbac, tool_risk_tiers | 4 | AML.T0053 |
| **ASI03** | Identity & Privilege Abuse | covered | `authority_claim` | authentication, rbac, tool_rbac | 4 | — |
| **ASI04** | Agentic Supply Chain Vulnerabilities | partial | `tool_poisoning` | tool_definition_pinning | 4 | AML.T0010 |
| **ASI05** | Unexpected Code Execution (RCE) | covered | `code_execution`, `unsafe_output` | — | 5 | — |
| **ASI06** | Memory & Context Poisoning | covered | `prompt_injection`, `token_flow` | memory_provenance | 4 | AML.T0080 AML.T0070 |
| **ASI07** | Insecure Inter-Agent Communication | partial | `prompt_injection`, `authority_claim` | trust_levels | 3 | — |
| **ASI08** | Cascading Failures | partial | — | kill_switch, fail_modes | 3 | — |
| **ASI09** | Human-Agent Trust Exploitation | partial | `authority_claim`, `groundedness` | human_confirmation | 3 | — |
| **ASI10** | Rogue Agents | partial | `trajectory`, `token_flow` | kill_switch, anomaly_detection | 4 | — |

- **ASI07** — Peer-agent messages are screened as tool-trust content; message signing is out of scope.
- **ASI08** — Per-run kill switch halts every later stage of a correlation once tripped.

### OWASP MCP Top 10 2025

| ID | Threat | Default status | Detectors | Other controls | Base impact | MITRE ATLAS |
|---|---|---|---|---|---|---|
| **MCP01** | Token Mismanagement & Secret Exposure | covered | `secrets`, `secret_leakage` | redaction | 5 | AML.T0057 |
| **MCP02** | Privilege Escalation via Scope Creep | covered | `token_flow` | tool_rbac, tool_risk_tiers | 4 | — |
| **MCP03** | Tool Poisoning | covered | `tool_poisoning` | tool_definition_pinning | 4 | AML.T0051.001 |
| **MCP04** | Software Supply Chain Attacks & Dependency Tampering | partial | — | tool_definition_pinning | 4 | AML.T0010 |
| **MCP05** | Command Injection & Execution | covered | `code_execution` | — | 5 | — |
| **MCP06** | Prompt Injection via Contextual Payloads | covered | `prompt_injection` | — | 4 | AML.T0051.001 |
| **MCP07** | Insufficient Authentication & Authorization | partial | — | authentication, rbac, tool_rbac | 4 | — |
| **MCP08** | Lack of Audit and Telemetry | covered | — | audit_events, metrics, tracing, siem_export | 3 | — |
| **MCP09** | Shadow MCP Servers | observed | — | tool_registry, fleet_inventory | 3 | — |
| **MCP10** | Context Injection & Over-Sharing | covered | `pii`, `secrets` | redaction | 3 | — |

- **MCP04** — Definition pinning catches behavioural change; package provenance belongs in your build pipeline.
- **MCP09** — Unregistered tools are refused when a tool registry is configured, and surfaced in the fleet view.

---

## What each new control catches

| Detector | Threats | What it looks for | Default |
|---|---|---|---|
| `prompt_injection` (extended) | LLM01, ASI01, plus boundary threats | Now decodes base64 and hex segments and rescans the plaintext. An instruction hidden in `aWdub3Jl…` counts in full, plus an obfuscation signal for having been hidden. | block ≥ 0.6, flag ≥ 0.35 |
| `system_prompt_leakage` | LLM07 | **Canary tokens** (`keeper.canary()`), and verbatim reuse of system-prompt 6-grams in output. | block |
| `unsafe_output` | LLM05 (+ASI05) | Markdown or HTML image exfiltration to non-allowlisted hosts; `<script>`, iframes, event handlers, `javascript:` URIs; shell and SQL payloads. Shell and SQL only *flag* unless `executes_output: true`. | block exfil and active HTML |
| `code_execution` | ASI05, MCP05 | Execution payloads in tool arguments. Sink-aware: on a shell or interpreter tool only destructive or remote-exec idioms count; on any other tool, metacharacters and interpreter calls are the injection. | block ≥ 0.6 |
| `tool_poisoning` | MCP03, ASI04, LLM03 | Hidden directive tags, pre-use directives, sensitive paths (`~/.ssh`, `mcp.json`), "do not tell the user", side-channel parameters, tool shadowing, invisible Unicode, and **rug pulls**: a definition that changed after it was pinned. | block ≥ 0.6 |
| `resource_abuse` | LLM10 | Oversized prompts or history, token and character floods, "repeat forever" requests, over-budget `max_tokens`. | block oversize/flood, flag endless |

### Tool definitions (MCP03)

```python
safe = [tool for tool, decision in keeper.check_tool_definitions(mcp_tools, server="github-mcp")
        if not decision.blocked]
```

The method accepts MCP (`inputSchema`), OpenAI (`{"type": "function", "function": {...}}`)
and Anthropic (`input_schema`) shapes. Definitions are pinned per `server/tool`
on first sight. To make approval a review step rather than trust-on-first-use,
pre-load pins:

```yaml
detectors:
  tool_poisoning:
    options:
      pins: {"github-mcp/create_issue": "3f9a…sha256"}
```

Both SDKs compute the same SHA-256 fingerprint, so one pin file serves both.

---

## Honest gaps

- **LLM03 / LLM04 / MCP04 (supply chain, training-time poisoning):** a runtime
  firewall sees model *behaviour*, not weights or packages. Keeper pins tool
  definitions and restricts models by role; package provenance and model
  vetting belong in your build pipeline.
- **LLM09 (misinformation):** a lexical groundedness screen, off by default,
  that flags and never blocks.
- **ASI07 (inter-agent communication):** peer-agent messages are screened as
  tool-trust content. Message signing and agent identity are out of scope.
- **ASI08 / ASI10 (cascading failures, rogue agents):** the per-run kill switch
  halts a compromised run, and the control plane's anomaly detection surfaces
  drift. Neither is a complete answer; both are observable.
- **MCP07 / MCP09 (authn/z, shadow servers):** Keeper enforces who may call
  which tool (tool RBAC) and refuses unregistered tools when a registry is
  configured. It doesn't authenticate MCP servers to each other.
- **ATLAS ids** are cross-references. Technique names change between ATLAS
  releases, and the ids are the stable part. Check them against the matrix
  version your programme uses.
