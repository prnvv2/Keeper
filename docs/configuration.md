# Configuration Guide

## Configuration File

keeper is configured via a single YAML file at `config/policies.yaml`:

```yaml
layers:
  network:
    enabled: true
    rate_limit: 100/min
    block_ips: []
  syntactic:
    enabled: true
    max_prompt_length: 4096
    block_escape_seq: true
  semantic:
    enabled: true
    model: llama3.2
    threshold: 0.75
  context:
    enabled: true
    max_history: 20
    drift_threshold: 0.6

guardrails:
  prompt_guard:
    enabled: true
    model: "bert-base-uncased-jailbreak"
    threshold: 0.85
  alignment_check:
    enabled: true
    model: llama3.2
  code_shield:
    enabled: true
    languages: [python, javascript, sql]
    rules_dir: ./rules/

actions:
  block_threshold: 0.9
  redact_threshold: 0.7
  alert_threshold: 0.5

integration:
  mode: middleware
  siem_webhook: ""
  alert_channel: "slack"
```

## Layer Configuration

### Network Layer
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable this layer |
| `rate_limit` | string | "100/min" | Max requests per minute per IP |
| `block_ips` | list | [] | IPs to permanently block |

### Syntactic Layer
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `max_prompt_length` | int | 4096 | Max prompt character length |
| `block_escape_seq` | bool | true | Block hex/unicode escapes |

### Semantic Layer
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `model` | string | "llama3.2" | Ollama model for scoring |
| `threshold` | float | 0.75 | Score above this = BLOCK |

### Context Layer
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `max_history` | int | 20 | History turns per session |
| `drift_threshold` | float | 0.6 | Drift score above this = BLOCK |
| `model` | string | "llama3.2" | Ollama model for drift analysis |

## Guardrail Configuration

### PromptGuard
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `model` | string | "bert-base-uncased-jailbreak" | HuggingFace model |
| `threshold` | float | 0.85 | Confidence above this = BLOCK |

### AlignmentCheck
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `model` | string | "llama3.2" | Ollama model for auditing |

### CodeShield
| Key | Type | Default | Description |
|-----|------|---------|-------------|
| `enabled` | bool | true | Enable/disable |
| `languages` | list | [python, javascript, sql] | Languages to scan |

## Action Thresholds

| Key | Default | Description |
|-----|---------|-------------|
| `block_threshold` | 0.9 | risk >= this → BLOCK |
| `redact_threshold` | 0.7 | risk >= this → REDACT |
| `alert_threshold` | 0.5 | risk >= this → ALERT |

## Custom Configuration Path

```python
from keeper.core.engine import PolicyEngine

engine = PolicyEngine(config_path="/path/to/custom/policies.yaml")
```
