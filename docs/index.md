# AANF Documentation

**AI Agentic Native Firewall** — Multi-layer security for LLM applications and AI agents.

## Quick Links

- [Installation Guide](installation.md)
- [Quick Start](quickstart.md)
- [Architecture Overview](architecture.md)
- [API Reference](api_reference.md)
- [Configuration Guide](configuration.md)
- [Developer Guide](developer_guide.md)
- [Plugin Guide](plugin_guide.md)

## What is AANF?

AANF is a modular, multi-layer security firewall that intercepts every prompt, tool call, and agent output, enforcing security policy through a chain of independent layers:

| Layer | Type | Detection |
|-------|------|-----------|
| Network | Rate limiter | DoS, IP abuse, prompt flooding |
| Syntactic | Regex scanner | SQL injection, XSS, escape sequences |
| PromptGuard | BERT classifier | Direct jailbreak detection (<1ms) |
| Semantic | LLM scorer | Jailbreaks, DAN, encoded instructions |
| AlignmentCheck | CoT auditor | Goal hijacking, misalignment |
| CodeShield | Static analysis | Insecure generated code |
| Context | Drift detector | Crescendo, multi-turn manipulation |

## Installation

```bash
pip install aanf
```

Requires Python 3.10+ and [Ollama](https://ollama.com) for semantic analysis features.

## Quick Start

```python
from aanf import build_pipeline

pipeline = build_pipeline()
```
