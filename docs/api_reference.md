# API Reference

## Top-Level API

### `keeper.build_pipeline()`
Returns a fully configured `Pipeline` instance with all default layers and guardrails registered in order.

**Returns:** `Pipeline`

### `keeper.__version__`
Current version string (e.g., `"0.2.0"`).

---

## Core Classes

### `RequestContext`

Data bag that travels through the pipeline.

```python
RequestContext(
    prompt: str,                    # User/agent input text
    user_id: str = "",              # Authenticated user identifier
    session_id: str = "",           # Conversation session ID
    ip: str = "",                   # Client IP address
    metadata: dict = {},            # Extra context (CoT, generated code, etc.)
    risk_score: float = 0.0,        # Accumulated risk across layers
    action: Action = Action.ALLOW,  # Enforcement decision
    latency_ms: float = 0.0,        # Total pipeline latency (set after run)
    violations: list = [],          # List of violation descriptions
)
```

### `Pipeline`

Orchestrates all security layers.

```python
Pipeline(policy_engine: PolicyEngine)

# Methods
pipeline.register(layer, config_override: dict = None)     # Register a layer
pipeline.unregister(name: str)                              # Remove a layer
pipeline.get_layer(name: str) -> BaseLayer                  # Get a registered layer
async pipeline.run(ctx: RequestContext) -> RequestContext   # Execute pipeline
pipeline.to_dict() -> dict                                  # Serialize pipeline state
```

### `PolicyEngine`

Loads YAML config and evaluates risk scores.

```python
PolicyEngine(config_path: str = "config/policies.yaml")

# Methods
engine.evaluate(risk_score: float) -> Action           # Map score to action
engine.get_layer_config(name: str) -> dict              # Get layer config
engine.get_guardrail_config(name: str) -> dict          # Get guardrail config
engine.reload()                                         # Reload from config file
```

### `Action` (enum)

```python
Action.ALLOW   # Let request through
Action.BLOCK   # Reject request
Action.REDACT  # Strip sensitive parts, forward
Action.ALERT   # Log warning, allow
```

---

## Base Classes (for Extension)

### `BaseLayer`

```python
from keeper import BaseLayer

class CustomLayer(BaseLayer):
    name = "custom"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # Inspect/modify ctx, return it
        return ctx
```

### `BaseGuardrail`

```python
from keeper import BaseGuardrail

class CustomGuardrail(BaseGuardrail):
    name = "custom_guardrail"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        return ctx
```

---

## Exceptions

| Exception | Description |
|-----------|-------------|
| `keeperError` | Base exception for all keeper errors |
| `PipelineError` | Pipeline execution error |
| `ConfigurationError` | Invalid configuration |
| `PolicyViolationError` | Request blocked by policy |
| `OllamaConnectionError` | Cannot reach Ollama |
| `PluginLoadError` | Failed to load a plugin |
| `RateLimitExceededError` | IP exceeded rate limit |
| `LayerNotRegisteredError` | Layer not found in pipeline |

---

## Integration APIs

### FastAPI Middleware

```python
from keeper.integration.fastapi_middleware import keeperMiddleware

app.add_middleware(keeperMiddleware, pipeline=pipeline)
```

### LangChain Callback

```python
from keeper.integration.langchain_hooks import keeperGuardrailHandler

handler = keeperGuardrailHandler(pipeline)
```

### LiteLLM Proxy Hook

```python
from keeper.integration.litellm_proxy import keeper_pre_call_hook

litellm.pre_call_hook = keeper_pre_call_hook
```

### MCP Tool

```python
from keeper.integration.mcp_server import keeperMCPTool

tool = keeperMCPTool(pipeline)
result = await tool.call("user prompt")
```
