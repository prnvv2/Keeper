"""Keeper — an open-source AI firewall for developers and security teams.

Quickstart::

    from keeper_firewall import Keeper

    keeper = Keeper(application="support-bot")
    reply = keeper.chat("Summarise ticket 4182")
    print(reply.text, reply.correlation_id)

Everything the firewall decides produces a structured audit event. With no
control plane configured those events stay local (in-memory plus an optional
JSONL file); set ``KEEPER_ENDPOINT`` (or ``telemetry={"endpoint": ...}``) to a
Keeper control plane and the same events feed the dashboard, alerting, and
your SIEM. Every decision is named in OWASP LLM / Agentic / MCP terms
(``decision.threats``) and scored on a likelihood x impact matrix
(``decision.risk``).
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
from .detectors import Detector, DetectorInput
from .detectors import register as register_detector
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
from .risk import RiskAssessment, RiskBand, RiskConfig, RiskEngine
from .runtime.guardrails import ToolSpec
from .taxonomy import THREATS, Threat, coverage_report
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
    "FAIL_CLOSED",
    "FAIL_OPEN",
    "SCHEMA_VERSION",
    "THREATS",
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
    "RiskAssessment",
    "RiskBand",
    "RiskConfig",
    "RiskEngine",
    "RiskTier",
    "Rule",
    "RuntimeConfig",
    "Severity",
    "Span",
    "Stage",
    "TelemetryConfig",
    "Threat",
    "ToolCall",
    "ToolSpec",
    "TransportError",
    "TrustLevel",
    "__version__",
    "coverage_report",
    "register_detector",
]
