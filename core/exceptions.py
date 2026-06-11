class AANFError(Exception):
    pass

class PipelineError(AANFError):
    pass

class ConfigurationError(AANFError):
    pass

class LayerNotRegisteredError(PipelineError):
    def __init__(self, name: str):
        super().__init__(f"Layer '{name}' is not registered")
        self.layer_name = name

class PolicyViolationError(AANFError):
    def __init__(self, message: str, risk_score: float = 0.0, violations: list = None):
        super().__init__(message)
        self.risk_score = risk_score
        self.violations = violations or []

class OllamaConnectionError(AANFError):
    def __init__(self, message: str = "Cannot connect to Ollama. Ensure ollama serve is running."):
        super().__init__(message)

class PluginLoadError(AANFError):
    def __init__(self, plugin_name: str, reason: str):
        super().__init__(f"Failed to load plugin '{plugin_name}': {reason}")
        self.plugin_name = plugin_name
        self.reason = reason

class RateLimitExceededError(AANFError):
    def __init__(self, ip: str, limit: int):
        super().__init__(f"Rate limit exceeded for IP {ip}: {limit} req/min")
        self.ip = ip
        self.limit = limit
