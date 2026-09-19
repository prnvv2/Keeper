"""SDK configuration.

Configuration is layered, lowest precedence first:

1. Defaults defined here.
2. A YAML/JSON config file (``KEEPER_CONFIG`` or the ``config_path`` argument).
3. ``KEEPER_*`` environment variables.
4. Keyword arguments passed to :class:`keeper_firewall.Keeper`.

Nothing in here reaches the network. Secrets (``api_key``) are read from the
environment by default and are never written to audit events or logs.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass, field, fields, is_dataclass
from typing import Any

from .errors import ConfigurationError
from .types import new_id

# ---------------------------------------------------------------------------
# Fail-safe behaviour
# ---------------------------------------------------------------------------

FAIL_OPEN = "open"      # on internal failure, allow the interaction through
FAIL_CLOSED = "closed"  # on internal failure, block the interaction


@dataclass(slots=True)
class DetectorConfig:
    """Per-detector switches.

    ``fail_mode`` decides what happens when *the detector itself* fails (throws,
    times out, a model backend is unreachable) — not what happens when it
    detects something. Defaults differ by detector and are set in
    :func:`default_detectors`; the reasoning is in ``docs/architecture.md``.
    """

    enabled: bool = True
    fail_mode: str = FAIL_OPEN
    timeout_ms: int = 150
    threshold: float = 0.5
    action: str | None = None  # override the detector's natural action
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class TelemetryConfig:
    """How audit events and metrics leave the SDK."""

    enabled: bool = True
    endpoint: str | None = None          # control plane base URL
    api_key: str | None = None
    batch_size: int = 50
    flush_interval_ms: int = 2000
    queue_capacity: int = 10_000
    # When the queue is full we drop the *oldest* non-critical events first;
    # BLOCK/CHALLENGE events are never dropped while capacity remains.
    drop_policy: str = "oldest_low_severity"
    timeout_ms: int = 3000
    max_retries: int = 3
    # Local sink; always on so the SDK is useful with no control plane at all.
    local_log_path: str | None = None
    local_log_stdout: bool = False
    # OpenTelemetry export of spans (no-op unless opentelemetry-sdk installed).
    otel_enabled: bool = False
    otel_endpoint: str | None = None


@dataclass(slots=True)
class RedactionConfig:
    """What of the payload is allowed into the audit trail.

    The default is deliberately conservative: Keeper ships *hashes and spans*,
    not prompt text, until an operator opts in. An AI firewall that silently
    exfiltrates every prompt to a central store is its own incident.
    """

    mode: str = "redacted"  # "none" | "redacted" | "full" | "hash_only"
    include_prompt: bool = True
    include_response: bool = True
    max_chars: int = 4000
    hash_payloads: bool = True
    hash_salt: str | None = None
    extra_patterns: list[str] = field(default_factory=list)


@dataclass(slots=True)
class MetricsConfig:
    """Prometheus exposition settings."""

    enabled: bool = True
    namespace: str = "keeper"
    # Serve /metrics on this port from inside the SDK process. None means the
    # host app is expected to expose the registry itself.
    port: int | None = None
    latency_buckets_ms: tuple[float, ...] = (1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500)


@dataclass(slots=True)
class PolicyConfig:
    """Where policy comes from and what happens when it can't be fetched."""

    source: str = "local"  # "local" | "control_plane"
    path: str | None = None
    bundle: str = "default"
    refresh_interval_s: int = 60
    # If the control plane is unreachable: keep the last policy we successfully
    # loaded, fall back to the bundled safe default, or disable enforcement.
    unreachable_behavior: str = "last_known_good"  # | "safe_default" | "fail_open"
    # Hard ceiling on how long a stale policy may keep being enforced.
    max_staleness_s: int = 3600
    engine: str = "embedded"  # "embedded" | "opa"
    opa_url: str | None = None
    dry_run: bool = False


@dataclass(slots=True)
class AccessControlConfig:
    """Authentication, RBAC and rate limiting."""

    enabled: bool = False
    auth_provider: str = "api_key"  # "api_key" | "oidc" | "mtls" | "callable"
    require_authentication: bool = True
    api_keys_path: str | None = None
    oidc_issuer: str | None = None
    oidc_audience: str | None = None
    oidc_jwks_url: str | None = None
    # Local rate limits are per SDK instance and therefore bypassable by
    # scaling out; see docs/architecture.md for the distributed story.
    rate_limit_enabled: bool = True
    default_rpm: int = 120
    default_burst: int = 20
    distributed: bool = False  # consult the control plane for fleet-wide quota


@dataclass(slots=True)
class RuntimeConfig:
    """Runtime protection: tool guardrails, streaming, memory provenance."""

    tool_guardrails_enabled: bool = True
    tool_allowlist: list[str] = field(default_factory=list)
    tool_denylist: list[str] = field(default_factory=list)
    screen_tool_results: bool = True
    screen_retrieved_documents: bool = True
    sandbox_untrusted_tools: bool = False
    stream_monitoring_enabled: bool = True
    # Evaluate the partial stream every N characters. Smaller = earlier
    # circuit-break, more CPU. See docs/observability.md for the tradeoff.
    stream_check_every_chars: int = 120
    stream_fast_threshold: float = 0.45   # escalate to the precise detector
    stream_break_threshold: float = 0.75  # break immediately
    memory_provenance_enabled: bool = True
    # Fail closed: a runtime guardrail that times out must not silently permit
    # a high-risk tool call.
    fail_mode: str = FAIL_CLOSED
    timeout_ms: int = 500


@dataclass(slots=True)
class KeeperConfig:
    """Top-level SDK configuration."""

    application: str = "unknown"
    environment: str = "production"
    instance_id: str = field(default_factory=lambda: new_id("inst_"))
    enabled: bool = True
    # Global kill switch for enforcement. Detectors still run and telemetry
    # still ships, but nothing is blocked. The way to roll Keeper out safely.
    monitor_only: bool = False
    detectors: dict[str, DetectorConfig] = field(default_factory=dict)
    telemetry: TelemetryConfig = field(default_factory=TelemetryConfig)
    redaction: RedactionConfig = field(default_factory=RedactionConfig)
    metrics: MetricsConfig = field(default_factory=MetricsConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    access_control: AccessControlConfig = field(default_factory=AccessControlConfig)
    runtime: RuntimeConfig = field(default_factory=RuntimeConfig)
    # Total budget for all input-side detectors. Exceeding it engages the
    # pipeline fail mode rather than letting latency grow unbounded.
    input_budget_ms: int = 250
    output_budget_ms: int = 250
    fail_mode: str = FAIL_OPEN

    def detector(self, name: str) -> DetectorConfig:
        return self.detectors.get(name, DetectorConfig())

    # -- construction -------------------------------------------------------

    @classmethod
    def load(
        cls,
        config_path: str | None = None,
        env: Mapping[str, str] | None = None,
        **overrides: Any,
    ) -> KeeperConfig:
        env = os.environ if env is None else env
        cfg = cls(detectors=default_detectors())

        path = config_path or env.get("KEEPER_CONFIG")
        if path:
            _apply_mapping(cfg, _read_config_file(path))

        _apply_mapping(cfg, _env_overrides(env))
        _apply_mapping(cfg, overrides)
        cfg.validate()
        return cfg

    def validate(self) -> None:
        if self.fail_mode not in (FAIL_OPEN, FAIL_CLOSED):
            raise ConfigurationError(f"fail_mode must be 'open' or 'closed', got {self.fail_mode!r}")
        if self.redaction.mode not in ("none", "redacted", "full", "hash_only"):
            raise ConfigurationError(f"unknown redaction mode {self.redaction.mode!r}")
        if self.policy.source == "control_plane" and not self.telemetry.endpoint:
            raise ConfigurationError(
                "policy.source='control_plane' requires telemetry.endpoint to be set"
            )
        if self.policy.unreachable_behavior not in (
            "last_known_good",
            "safe_default",
            "fail_open",
        ):
            raise ConfigurationError(
                f"unknown policy.unreachable_behavior {self.policy.unreachable_behavior!r}"
            )
        if self.policy.engine == "opa" and not self.policy.opa_url:
            raise ConfigurationError("policy.engine='opa' requires policy.opa_url")


def default_detectors() -> dict[str, DetectorConfig]:
    """Detector defaults.

    Two rules of thumb decide ``fail_mode`` here:

    * Deterministic, cheap, local detectors (regex-based PII and secrets) fail
      *closed* — if they cannot run, we do not know whether a secret is about
      to leave the perimeter, and the cost of a false block is low.
    * Probabilistic or network-dependent detectors fail *open* — blocking all
      traffic because a classifier endpoint is slow turns a security control
      into an availability incident.
    """
    return {
        "secrets": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=50),
        "pii": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=80),
        "prompt_injection": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=120, threshold=0.6),
        "authority_claim": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=50, threshold=0.5),
        "trajectory": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=80, threshold=0.65),
        "banned_topics": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=50),
        "secret_leakage": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=50),
        "groundedness": DetectorConfig(enabled=False, fail_mode=FAIL_OPEN, timeout_ms=200),
        "token_flow": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=100),
        "llm_classifier": DetectorConfig(enabled=False, fail_mode=FAIL_OPEN, timeout_ms=1500),
        # OWASP coverage additions: LLM07, LLM05, ASI05/MCP05, MCP03, LLM10.
        "system_prompt_leakage": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=50, threshold=0.6),
        "unsafe_output": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=50, threshold=0.6),
        "code_execution": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=50, threshold=0.6),
        "tool_poisoning": DetectorConfig(fail_mode=FAIL_CLOSED, timeout_ms=80, threshold=0.6),
        "resource_abuse": DetectorConfig(fail_mode=FAIL_OPEN, timeout_ms=30, threshold=0.6),
    }


# ---------------------------------------------------------------------------
# Internals
# ---------------------------------------------------------------------------

_ENV_MAP: dict[str, tuple[str, ...]] = {
    "KEEPER_APPLICATION": ("application",),
    "KEEPER_ENVIRONMENT": ("environment",),
    "KEEPER_ENABLED": ("enabled",),
    "KEEPER_MONITOR_ONLY": ("monitor_only",),
    "KEEPER_FAIL_MODE": ("fail_mode",),
    "KEEPER_ENDPOINT": ("telemetry", "endpoint"),
    "KEEPER_API_KEY": ("telemetry", "api_key"),
    "KEEPER_TELEMETRY_ENABLED": ("telemetry", "enabled"),
    "KEEPER_LOG_PATH": ("telemetry", "local_log_path"),
    "KEEPER_OTEL_ENABLED": ("telemetry", "otel_enabled"),
    "KEEPER_OTEL_ENDPOINT": ("telemetry", "otel_endpoint"),
    "KEEPER_REDACTION_MODE": ("redaction", "mode"),
    "KEEPER_REDACTION_SALT": ("redaction", "hash_salt"),
    "KEEPER_METRICS_PORT": ("metrics", "port"),
    "KEEPER_POLICY_SOURCE": ("policy", "source"),
    "KEEPER_POLICY_PATH": ("policy", "path"),
    "KEEPER_POLICY_BUNDLE": ("policy", "bundle"),
    "KEEPER_POLICY_DRY_RUN": ("policy", "dry_run"),
    "KEEPER_ACCESS_CONTROL_ENABLED": ("access_control", "enabled"),
}

_TRUE = {"1", "true", "yes", "on"}
_FALSE = {"0", "false", "no", "off"}


def _coerce(value: Any, current: Any) -> Any:
    if isinstance(current, bool):
        if isinstance(value, str):
            low = value.strip().lower()
            if low in _TRUE:
                return True
            if low in _FALSE:
                return False
            raise ConfigurationError(f"cannot read {value!r} as a boolean")
        return bool(value)
    if isinstance(current, int) and not isinstance(current, bool):
        return int(value)
    if isinstance(current, float):
        return float(value)
    return value


def _env_overrides(env: Mapping[str, str]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, path in _ENV_MAP.items():
        if key not in env:
            continue
        cursor = out
        for part in path[:-1]:
            cursor = cursor.setdefault(part, {})
        cursor[path[-1]] = env[key]
    return out


def _read_config_file(path: str) -> dict[str, Any]:
    if not os.path.exists(path):
        raise ConfigurationError(f"config file not found: {path}")
    with open(path, encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # optional dependency
        except ImportError as exc:  # pragma: no cover - env dependent
            raise ConfigurationError(
                "YAML config requires PyYAML; install keeper-firewall[yaml] or use JSON"
            ) from exc
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text or "{}")
    if not isinstance(data, dict):
        raise ConfigurationError(f"config file {path} must contain a mapping at the top level")
    return data


def _apply_mapping(target: Any, data: Mapping[str, Any]) -> None:
    """Recursively apply a mapping onto a dataclass instance."""
    known = {f.name: f for f in fields(target)}
    for key, value in data.items():
        if key not in known:
            raise ConfigurationError(
                f"unknown configuration key {key!r} for {type(target).__name__}"
            )
        current = getattr(target, key)
        if key == "detectors" and isinstance(value, Mapping):
            merged = dict(current)
            for name, det in value.items():
                base = merged.get(name, DetectorConfig())
                if isinstance(det, DetectorConfig):
                    merged[name] = det
                elif isinstance(det, Mapping):
                    _apply_mapping(base, det)
                    merged[name] = base
                else:
                    raise ConfigurationError(f"detector {name!r} must be a mapping")
            setattr(target, key, merged)
        elif is_dataclass(current) and isinstance(value, Mapping):
            _apply_mapping(current, value)
        elif is_dataclass(current) and is_dataclass(value):
            setattr(target, key, value)
        else:
            setattr(target, key, _coerce(value, current))
