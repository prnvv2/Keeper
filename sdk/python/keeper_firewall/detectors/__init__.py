"""Built-in detectors.

Importing this package registers every built-in detector with the registry in
:mod:`keeper_firewall.detectors.base`. Third-party detectors register
themselves the same way — there is no separate plugin tier.
"""

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
from .injection import PromptInjectionDetector, normalise
from .llm import LLMClassifierDetector
from .output import BannedTopicsDetector, GroundednessDetector, SecretLeakageDetector
from .pii import PIIDetector, luhn_valid
from .secrets import SecretDetector, shannon_entropy
from .tokenflow import FlowRecord, TokenFlowDetector

#: Detectors that run on the input side by default, in execution order.
#: Cheap and deterministic first: if ``secrets`` blocks, nothing else needs to
#: run, and the expensive conversation-level gates are skipped entirely.
DEFAULT_INPUT_DETECTORS = (
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
    "pii",
    "banned_topics",
    "groundedness",
)

#: Runtime-protection defaults, used for tool calls, tool results, retrieved
#: documents and memory writes.
DEFAULT_RUNTIME_DETECTORS = (
    "token_flow",
    "secrets",
    "prompt_injection",
    "authority_claim",
)

__all__ = [
    "AuthorityClaimDetector",
    "BannedTopicsDetector",
    "DEFAULT_INPUT_DETECTORS",
    "DEFAULT_OUTPUT_DETECTORS",
    "DEFAULT_RUNTIME_DETECTORS",
    "Detector",
    "DetectorInput",
    "FlowRecord",
    "GroundednessDetector",
    "LLMClassifierDetector",
    "PIIDetector",
    "PromptInjectionDetector",
    "SecretDetector",
    "SecretLeakageDetector",
    "TokenFlowDetector",
    "TrajectoryDetector",
    "build",
    "detector",
    "luhn_valid",
    "normalise",
    "register",
    "registered",
    "shannon_entropy",
    "timed",
]
