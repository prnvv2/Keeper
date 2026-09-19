"""Detector contract and registry.

A detector is the smallest pluggable unit in Keeper. It receives a
:class:`DetectorInput` and returns a :class:`~keeper_firewall.types.Finding`.
It must not raise for ordinary "nothing found" cases, must be side-effect free,
and must respect its latency budget — the pipeline enforces the budget anyway,
but a detector that routinely blows it will be reported as unhealthy.

Third-party detectors register themselves with :func:`register` or are passed
directly to :class:`keeper_firewall.Keeper` via ``extra_detectors=``. Both
paths use the same contract, so there is no second-class plugin tier.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..config import DetectorConfig
from ..errors import ConfigurationError
from ..types import (
    Action,
    Document,
    Finding,
    Message,
    RequestContext,
    Severity,
    Span,
    Stage,
    ToolCall,
    TrustLevel,
)


@dataclass(slots=True)
class DetectorInput:
    """Everything a detector is allowed to see.

    Detectors get the payload plus enough context to reason about *where it
    came from*. ``trust`` matters: the same sentence is benign in a user's
    message and a red flag inside a retrieved document.
    """

    payload: str
    stage: Stage
    context: RequestContext
    trust: TrustLevel = TrustLevel.USER
    history: Sequence[Message] = ()
    documents: Sequence[Document] = ()
    tool_call: ToolCall | None = None
    grounding: Sequence[str] = ()
    metadata: Mapping[str, Any] = field(default_factory=dict)


class Detector:
    """Base class for all detectors."""

    #: Stable identifier, used as the config key and in audit events.
    name: str = "detector"
    #: Which pipeline stages this detector is eligible for.
    stages: tuple[Stage, ...] = (Stage.INPUT,)
    #: Human-readable threat category, used for dashboard grouping.
    category: str = "unspecified"
    #: Whether the detector can rewrite the payload (redaction).
    mutates: bool = False

    def __init__(self, config: DetectorConfig | None = None) -> None:
        self.config = config or DetectorConfig()

    def detect(self, data: DetectorInput) -> Finding:  # pragma: no cover - abstract
        raise NotImplementedError

    def redact(self, payload: str, finding: Finding) -> tuple[str, tuple[str, ...]]:
        """Return ``(new_payload, redacted_field_labels)``.

        Only called when :attr:`mutates` is true and the resolved action is
        ``REDACT``. The default implementation replaces every matched span with
        a typed placeholder, right to left so earlier offsets stay valid.
        """
        if not finding.spans:
            return payload, ()
        labels: list[str] = []
        out = payload
        for span in sorted(finding.spans, key=lambda s: s.start, reverse=True):
            placeholder = f"[REDACTED:{span.label}]"
            out = out[: span.start] + placeholder + out[span.end :]
            labels.append(span.label)
        return out, tuple(dict.fromkeys(reversed(labels)))

    # -- helpers for subclasses --------------------------------------------

    def clean(self, summary: str = "", **evidence: Any) -> Finding:
        return Finding(
            detector=self.name,
            detected=False,
            score=0.0,
            severity=Severity.INFO,
            action=Action.ALLOW,
            summary=summary,
            category=self.category,
            evidence=evidence,
        )

    def hit(
        self,
        score: float,
        summary: str,
        *,
        severity: Severity = Severity.MEDIUM,
        action: Action = Action.BLOCK,
        spans: Iterable[Span] = (),
        **evidence: Any,
    ) -> Finding:
        override = self.config.action
        if override:
            try:
                action = Action(override)
            except ValueError as exc:
                raise ConfigurationError(
                    f"detector {self.name!r}: unknown action override {override!r}"
                ) from exc
        return Finding(
            detector=self.name,
            detected=True,
            score=max(0.0, min(1.0, score)),
            severity=severity,
            action=action,
            summary=summary,
            category=self.category,
            spans=tuple(spans),
            evidence=evidence,
        )

    def supports(self, stage: Stage) -> bool:
        return stage in self.stages

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return f"<{type(self).__name__} name={self.name!r}>"


def timed(detector: Detector, data: DetectorInput) -> Finding:
    """Run a detector and stamp its wall-clock cost onto the finding."""
    start = time.perf_counter()
    finding = detector.detect(data)
    finding.elapsed_ms = (time.perf_counter() - start) * 1000
    return finding


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

DetectorFactory = Callable[[DetectorConfig], Detector]
_REGISTRY: dict[str, DetectorFactory] = {}


def register(name: str, factory: DetectorFactory) -> None:
    """Register a detector factory under ``name``.

    Re-registering an existing name is allowed and replaces the factory: that
    is how an organisation swaps our regex PII detector for their own
    ML-backed one without forking the SDK.
    """
    _REGISTRY[name] = factory


def registered() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY))


def build(name: str, config: DetectorConfig) -> Detector:
    if name not in _REGISTRY:
        raise ConfigurationError(
            f"unknown detector {name!r}; registered detectors: {', '.join(registered()) or 'none'}"
        )
    return _REGISTRY[name](config)


def detector(name: str) -> Callable[[type[Detector]], type[Detector]]:
    """Class decorator that registers a zero-argument-constructible detector."""

    def wrap(cls: type[Detector]) -> type[Detector]:
        cls.name = name
        def factory(cfg: DetectorConfig) -> Detector:
            return cls(cfg)

        register(name, factory)
        return cls

    return wrap
