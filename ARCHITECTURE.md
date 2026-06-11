# AI Agentic Native Firewall (AANF) — Architecture

## Overview

AANF is a modular, multi-layer security firewall for LLM-powered applications and AI agents. It intercepts every prompt, tool call, and agent output, enforcing policy through a chain of independent security layers.

## Pipeline

```
User/Agent Request
       |
  [1] Network Layer    — rate limit, IP allow/deny, token bucket
       |
  [2] Syntactic Layer  — escape seq, SQL/XSS patterns, format check
       |
  [3] PromptGuard      — fast BERT classifier (direct jailbreak)
       |
  [4] Semantic Layer   — Ollama LLM judges prompt intent
       |
  [5] AlignmentCheck   — CoT auditor for agent reasoning
       |
  [6] CodeShield       — Semgrep scan for LLM-generated code
       |
  [7] Context Layer    — multi-turn pattern detection
       |
  [8] LLM / Tool Execution
       |
  [9] Output Scan      — Rust scanner on response tokens
       |
  [10] Post-action Log — structured audit event
```

## Layers

| Layer | File | What it detects |
|-------|------|----------------|
| Network | `layers/network.py` | DoS, prompt flooding, IP abuse |
| Syntactic | `layers/syntactic.py` | SQL injection, XSS, escape sequences |
| Semantic | `layers/semantic.py` | Jailbreaks, DAN, role-playing bypass |
| Context | `layers/context.py` | Crescendo, Echo Chamber, multi-turn drift |

## Guardrails

| Guardrail | File | Method |
|-----------|------|--------|
| PromptGuard | `guardrails/prompt_guard.py` | BERT classifier (<1ms) |
| AlignmentCheck | `guardrails/alignment_check.py` | Ollama CoT auditor |
| CodeShield | `guardrails/code_shield.py` | Semgrep + regex rules |

## Integration Modes

| Mode | Adapter | Use Case |
|------|---------|----------|
| FastAPI Middleware | `integration/fastapi_middleware.py` | Drop-in ASGI middleware |
| LiteLLM Proxy | `integration/litellm_proxy.py` | Callback for 100+ LLM providers |
| LangChain Callback | `integration/langchain_hooks.py` | Agent lifecycle hooks |
| MCP Server | `integration/mcp_server.py` | Model Context Protocol tool |

## Tech Stack

- **Python** — orchestration, guardrails, policy engine (FastAPI)
- **Rust** — high-performance token scanning (PyO3)
- **HuggingFace Datasets** — threat benchmarks
- **Ollama** — local LLM for semantic analysis
- **Semgrep** — static code analysis

## Directory

```
aanf/
├── core/           # Policy engine & pipeline
├── layers/         # Security layers (network, syntactic, semantic, context)
├── guardrails/     # Pluggable guardrails (PromptGuard, AlignmentCheck, CodeShield)
├── scanner/        # Rust token scanner
├── models/         # HuggingFace datasets & Ollama client
├── agents/         # Agent sandbox & tool monitor
├── integration/    # Adapters (FastAPI, LiteLLM, LangChain, MCP)
├── config/         # YAML policies
├── main.py         # Entry point
├── requirements.txt
└── setup.py
```
