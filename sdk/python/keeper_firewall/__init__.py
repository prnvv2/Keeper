"""Keeper — an open-source AI firewall for developers and security teams.

Quickstart::

    from keeper_firewall import Keeper

    keeper = Keeper(application="support-bot")
    reply = keeper.chat("Summarise ticket 4182")
    print(reply.text, reply.correlation_id)

Everything the firewall decides produces a structured audit event. With no
control plane configured those events stay local (in-memory plus an optional
JSONL file); point ``endpoint=`` at a Keeper control plane and the same events
feed the dashboard, alerting, and your SIEM.
"""

from .client import Keeper
from .config import (
    FAIL_CLOSED,
    FAIL_OPEN,
    AccessControlConfig,
    DetectorConfig,
    KeeperConfig,
    MetricsConfig,
    PolicyConfig,
    RedactionConfig,
    RuntimeConfig,
    TelemetryConfig,
)
from .detectors import Detector, DetectorInput, register as register_detector
from .errors import (
    AuthenticationError,
    AuthorizationError,
    BlockedError,
    ConfigurationError,
    DetectorError,
    KeeperError,
    PolicyError,
    RateLimitError,
    TransportError,
)
from .policy.models import Policy, Rule
from .providers import (
    AnthropicProvider,
    CallableProvider,
    EchoProvider,
    OpenAICompatibleProvider,
)
from .runtime.guardrails import ToolSpec
from .types import (
    Action,
    AuditEvent,
    Decision,
    Document,
    Finding,
    GuardedResponse,
    LLMResponse,
    MemoryRecord,
    Message,
    Principal,
    RequestContext,
    RiskTier,
    Severity,
    Span,
    Stage,
    ToolCall,
    TrustLevel,
)
from .version import SCHEMA_VERSION, __version__

__all__ = [
    "AccessControlConfig",
    "Action",
    "AnthropicProvider",
    "AuditEvent",
    "AuthenticationError",
    "AuthorizationError",
    "BlockedError",
    "CallableProvider",
    "ConfigurationError",
    "Decision",
    "Detector",
    "DetectorConfig",
    "DetectorError",
    "DetectorInput",
    "Document",
    "EchoProvider",
    "FAIL_CLOSED",
    "FAIL_OPEN",
    "Finding",
    "GuardedResponse",
    "Keeper",
    "KeeperConfig",
    "KeeperError",
    "LLMResponse",
    "MemoryRecord",
    "Message",
    "MetricsConfig",
    "OpenAICompatibleProvider",
    "Policy",
    "PolicyConfig",
    "PolicyError",
    "Principal",
    "RateLimitError",
    "RedactionConfig",
    "RequestContext",
    "RiskTier",
    "Rule",
    "RuntimeConfig",
    "SCHEMA_VERSION",
    "Severity",
    "Span",
    "Stage",
    "TelemetryConfig",
    "ToolCall",
    "ToolSpec",
    "TransportError",
    "TrustLevel",
    "__version__",
    "register_detector",
]
