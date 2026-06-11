# Plugin Guide

keeper supports plugin-based extensibility via Python entry points. Plugins can add new layers, guardrails, or integrations.

## Plugin Discovery

Plugins are discovered using `importlib.metadata.entry_points()` with the following entry point groups:

| Group | Type | Example |
|-------|------|---------|
| `keeper.plugins.layers` | Security layer | `NetworkLayer` |
| `keeper.plugins.guardrails` | Guardrail | `PromptGuard` |
| `keeper.plugins.integrations` | Integration adapter | `keeperMiddleware` |

## Creating a Plugin Package

### 1. Define your plugin

```python
# my_plugin/layer.py
from keeper import BaseLayer, RequestContext
from keeper.core.engine import Action

class CustomLayer(BaseLayer):
    name = "custom_layer"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        if "block_this" in ctx.prompt:
            ctx.action = Action.BLOCK
            ctx.violations.append("custom_layer: blocked")
        return ctx
```

### 2. Register entry points in `pyproject.toml`

```toml
[project.entry-points."keeper.plugins.layers"]
custom_layer = "my_plugin.layer:CustomLayer"
```

### 3. Install the plugin

```bash
pip install my-plugin
```

### 4. Load and register

```python
from keeper.plugins import discover_layers

layers = discover_layers()
print(layers)  # {"custom_layer": <class CustomLayer>}
```

## Built-in Plugins

### Layers

| Name | Class | Description |
|------|-------|-------------|
| `network` | `NetworkLayer` | Rate limiting + IP block |
| `syntactic` | `SyntacticLayer` | Regex syntax checks |
| `semantic` | `SemanticLayer` | LLM-based scoring |
| `context` | `ContextLayer` | Multi-turn drift detection |

### Guardrails

| Name | Class | Description |
|------|-------|-------------|
| `prompt_guard` | `PromptGuard` | BERT jailbreak classifier |
| `alignment_check` | `AlignmentCheck` | CoT alignment auditor |
| `code_shield` | `CodeShield` | Static code analysis |

### Integrations

| Name | Description |
|------|-------------|
| `fastapi` | FastAPI ASGI middleware |
| `litellm` | LiteLLM pre-call hook |
| `langchain` | LangChain callback handler |
| `mcp` | Model Context Protocol tool |
