"""Built-in detectors.

Importing this package registers every built-in detector with the registry in
:mod:`keeper_firewall.detectors.base`. Third-party detectors register
themselves the same way — there is no separate plugin tier.
"""

from .agentic import CodeExecutionDetector, ToolPoisoningDetector, tool_fingerprint, tool_text
from .base import (
    Detector,
    DetectorInput,
    build,
    detector,
    register,
    registered,
    timed,
)
from .cognitive import AuthorityClaimDetector, TrajectoryDetector
from .consumption import ResourceAbuseDetector
from .injection import PromptInjectionDetector, normalise
from .leakage import SystemPromptLeakageDetector, new_canary
from .llm import LLMClassifierDetector
from .output import BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector
from .output_handling import UnsafeOutputDetector
from .pii import PIIDetector, luhn_valid
from .secrets import SecretDetector, shannon_entropy
from .tokenflow import FlowRecord, TokenFlowDetector

#: Detectors that run on the input side by default, in execution order.
#: Cheap and deterministic first: if ``secrets`` blocks, nothing else needs to
#: run, and the expensive conversation-level gates are skipped entirely.
DEFAULT_INPUT_DETECTORS = (
    "resource_abuse",
    "secrets",
    "pii",
    "banned_topics",
    "prompt_injection",
    "authority_claim",
    "trajectory",
)

#: Output-side default order.
DEFAULT_OUTPUT_DETECTORS = (
    "secret_leakage",
    "system_prompt_leakage",
    "unsafe_output",
    "pii",
    "banned_topics",
    "groundedness",
)

#: Runtime-protection defaults, used for tool calls, tool results, retrieved
#: documents and memory writes.
DEFAULT_RUNTIME_DETECTORS = (
    # code_execution first: when an argument is an outright execution payload,
    # the more specific ASI05/MCP05 attribution should win the short-circuit.
    "code_execution",
    "token_flow",
    "secrets",
    "prompt_injection",
    "authority_claim",
)

__all__ = [
    "DEFAULT_INPUT_DETECTORS",
    "DEFAULT_OUTPUT_DETECTORS",
    "DEFAULT_RUNTIME_DETECTORS",
    "AuthorityClaimDetector",
    "BannedTopicsDetector",
    "CodeExecutionDetector",
    "Detector",
    "DetectorInput",
    "FlowRecord",
    "GroundednessDetector",
    "LLMClassifierDetector",
    "PIIDetector",
    "PromptInjectionDetector",
    "ResourceAbuseDetector",
    "SecretDetector",
    "SecretLeakageDetector",
    "SystemPromptLeakageDetector",
    "TokenFlowDetector",
    "ToolPoisoningDetector",
    "TrajectoryDetector",
    "UnsafeOutputDetector",
    "build",
    "detector",
    "luhn_valid",
    "new_canary",
    "normalise",
    "register",
    "registered",
    "shannon_entropy",
    "timed",
    "tool_fingerprint",
    "tool_text",
]
