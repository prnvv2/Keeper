# API Reference

## Top-Level API

### `aanf.build_pipeline()`
Returns a fully configured `Pipeline` instance with all default layers and guardrails registered in order.

**Returns:** `Pipeline`

### `aanf.__version__`
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
from aanf import BaseLayer

class CustomLayer(BaseLayer):
    name = "custom"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        # Inspect/modify ctx, return it
        return ctx
```

### `BaseGuardrail`

```python
from aanf import BaseGuardrail

class CustomGuardrail(BaseGuardrail):
    name = "custom_guardrail"

    async def analyze(self, ctx: RequestContext, config: dict) -> RequestContext:
        return ctx
```

---

## Exceptions

| Exception | Description |
|-----------|-------------|
| `AANFError` | Base exception for all AANF errors |
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
from aanf.integration.fastapi_middleware import AANFMiddleware

app.add_middleware(AANFMiddleware, pipeline=pipeline)
```

### LangChain Callback

```python
from aanf.integration.langchain_hooks import AANFGuardrailHandler

handler = AANFGuardrailHandler(pipeline)
```

### LiteLLM Proxy Hook

```python
from aanf.integration.litellm_proxy import aanf_pre_call_hook

litellm.pre_call_hook = aanf_pre_call_hook
```

### MCP Tool

```python
from aanf.integration.mcp_server import AANFMCPTool

tool = AANFMCPTool(pipeline)
result = await tool.call("user prompt")
```
