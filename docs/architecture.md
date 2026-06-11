# Architecture Overview

## Pipeline Design

keeper uses a sequential pipeline architecture where each layer independently evaluates a request:

```
User Request
    |
[1] Network Layer       Rate limiting + IP block
    |
[2] Syntactic Layer     Max length, escape seq, SQL/XSS
    |
[3] PromptGuard         BERT classifier (<1ms jailbreak)
    |
[4] Semantic Layer      Ollama LLM scores intent (0-1)
    |
[5] AlignmentCheck      CoT auditor (agent reasoning)
    |
[6] CodeShield          Semgrep on generated code
    |
[7] Context Layer       Multi-turn drift detection
    |
[8] LLM / Tool Execution  (if not blocked)
```

### Key Principles

1. **Short-circuit on BLOCK** — once any layer returns `Action.BLOCK`, remaining layers are skipped
2. **Order matters** — lightweight checks (network, syntactic) run first; LLM-based checks run last
3. **Risk accumulation** — each layer updates `ctx.risk_score = max(ctx.risk_score, score)`
4. **Fail-open** — if Ollama is unreachable, semantic layers return score=0.0 (allow)

## Core Components

```
keeper/
├── core/           # PolicyEngine, Pipeline, RequestContext, Exceptions
├── layers/         # Security layers (network, syntactic, semantic, context)
├── guardrails/     # Pluggable guardrails (PromptGuard, AlignmentCheck, CodeShield)
├── agents/         # Agent sandbox & tool output injection monitor
├── models/         # Ollama client & benchmark datasets
├── integration/    # Framework adapters (FastAPI, LiteLLM, LangChain, MCP)
├── scanner/        # Rust token scanner (optional high-perf)
├── plugins/        # Plugin discovery via entry points
├── config/         # YAML configuration
└── main.py         # Entry point (CLI + server)
```

## Data Flow

1. `RequestContext` is created with the user prompt and metadata
2. Each layer reads the context, inspects the prompt, and optionally modifies `risk_score`, `action`, and `violations`
3. After all layers run (or a BLOCK short-circuits), the `PolicyEngine` maps the final risk score to an action
4. A structured JSON log is emitted for every decision

## Action Enforcement

| Risk Score | Action | Behavior |
|------------|--------|----------|
| < 0.5 | ALLOW | Forward request normally |
| 0.5 — 0.7 | ALERT | Log warning, allow through |
| 0.7 — 0.9 | REDACT | Strip sensitive parts, forward |
| >= 0.9 | BLOCK | Reject request entirely |
