"""The risk matrix: likelihood x impact, per OWASP threat, per decision.

Detectors answer "did I see an attack?". Security teams need a different
answer: "how bad is this, *here*?". A weak injection signal in a chat about the
weather and the same weak signal driving a ``payment.transfer`` tool call are
the same finding and very different risks. The risk engine turns findings into
a classic 5x5 risk matrix cell so that:

* enforcement can escalate on *context* (a medium-confidence signal on a
  critical sink is blocked, the same signal on a read-only path is flagged);
* every audit event carries one comparable number (1-25) and band, which is
  what the dashboard heat map, alerting and SIEM severity are built on;
* the answer is explainable — "L3 x I5 on ASI02 Tool Misuse" — not a model's
  opinion.

**Likelihood (1-5)** is how confident the evidence is that the threat is real,
taken from the strongest finding mapped to the threat. Boundary trust is
already inside detector scores (the injection detector multiplies by it), so it
is not counted twice here. Two or more *independent* detectors agreeing on a
threat adds one step: corroboration is real evidence.

**Impact (1-5)** is how bad it is if the threat succeeds: the threat's base
impact (policy-overridable), raised to the sink's risk tier when a tool call is
involved, and to the application's criticality floor when one is configured.
Persistence is already priced into the threats that describe it (ASI06), so a
memory write is not bumped a second time.

**Residual vs inherent.** A finding whose action is ``redact`` has already been
mitigated: the sensitive span will not reach the model. The *inherent* risk is
recorded for reporting, and the *residual* risk — likelihood reset to 1 for
fully mitigated threats — is what drives enforcement. Without that, redacting a
phone number would score as a critical LLM02 event and block the request the
redaction was meant to let through.

The engine only ever *escalates*. Its verdict joins the decision as one more
policy trace and is combined by escalation like everything else, so the risk
matrix can turn a flag into a block but can never turn a detector's block into
an allow.
"""

from __future__ import annotations

import enum
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .errors import PolicyError
from .taxonomy import THREATS
from .types import Action, Finding, PolicyTrace, RiskTier, Stage, ToolCall


class RiskBand(str, enum.Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    def rank(self) -> int:
        return _BAND_RANK[self]

    @classmethod
    def for_score(cls, score: int) -> RiskBand:
        if score <= 0:
            return cls.NONE
        if score <= 4:
            return cls.LOW
        if score <= 9:
            return cls.MEDIUM
        if score <= 16:
            return cls.HIGH
        return cls.CRITICAL


_BAND_RANK = {RiskBand.NONE: 0, RiskBand.LOW: 1, RiskBand.MEDIUM: 2, RiskBand.HIGH: 3, RiskBand.CRITICAL: 4}

DEFAULT_BAND_ACTIONS: Mapping[RiskBand, Action] = {
    RiskBand.NONE: Action.ALLOW,
    RiskBand.LOW: Action.ALLOW,
    RiskBand.MEDIUM: Action.FLAG,
    RiskBand.HIGH: Action.BLOCK,
    RiskBand.CRITICAL: Action.BLOCK,
}

DEFAULT_TOOL_IMPACT: Mapping[RiskTier, int] = {
    RiskTier.LOW: 2,
    RiskTier.MEDIUM: 3,
    RiskTier.HIGH: 4,
    RiskTier.CRITICAL: 5,
}

#: Finding score cut-points for likelihood 2, 3, 4 and 5.
DEFAULT_LIKELIHOOD_CUTS: tuple[float, float, float, float] = (0.35, 0.5, 0.65, 0.85)


@dataclass(slots=True)
class RiskConfig:
    """The ``risk:`` section of a policy document."""

    enforce: bool = True
    actions: Mapping[RiskBand, Action] = field(default_factory=lambda: dict(DEFAULT_BAND_ACTIONS))
    impact_overrides: Mapping[str, int] = field(default_factory=dict)
    tool_impact: Mapping[RiskTier, int] = field(default_factory=lambda: dict(DEFAULT_TOOL_IMPACT))
    likelihood_cuts: tuple[float, float, float, float] = DEFAULT_LIKELIHOOD_CUTS
    #: Per-application impact floor, e.g. ``{"payments-agent": 4}``: an asset's
    #: criticality raises the impact of every threat against it.
    application_impact: Mapping[str, int] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> RiskConfig:
        if not data:
            return cls()
        if not isinstance(data, Mapping):
            raise PolicyError("'risk' must be a mapping")
        unknown = set(data) - {"enforce", "actions", "impact", "tool_impact", "likelihood_cuts", "application_impact"}
        if unknown:
            raise PolicyError(f"unknown risk keys: {', '.join(sorted(unknown))}")
        try:
            actions = dict(DEFAULT_BAND_ACTIONS)
            for band, action in (data.get("actions") or {}).items():
                actions[RiskBand(str(band))] = Action(str(action))
            impact = {str(k): _impact(v, f"impact.{k}") for k, v in (data.get("impact") or {}).items()}
            for tid in impact:
                if tid not in THREATS:
                    raise PolicyError(f"risk.impact: unknown threat id {tid!r}")
            tool_impact = dict(DEFAULT_TOOL_IMPACT)
            for tier, v in (data.get("tool_impact") or {}).items():
                tool_impact[RiskTier(str(tier))] = _impact(v, f"tool_impact.{tier}")
            raw_cuts = [float(x) for x in (data.get("likelihood_cuts") or DEFAULT_LIKELIHOOD_CUTS)]
            if len(raw_cuts) != 4 or raw_cuts != sorted(raw_cuts) or not all(0.0 < c <= 1.0 for c in raw_cuts):
                raise PolicyError("risk.likelihood_cuts must be four ascending values in (0, 1]")
            cuts = (raw_cuts[0], raw_cuts[1], raw_cuts[2], raw_cuts[3])
            app_impact = {str(k): _impact(v, f"application_impact.{k}")
                          for k, v in (data.get("application_impact") or {}).items()}
        except ValueError as exc:
            raise PolicyError(f"invalid risk section: {exc}") from exc
        return cls(
            enforce=bool(data.get("enforce", True)),
            actions=actions,
            impact_overrides=impact,
            tool_impact=tool_impact,
            likelihood_cuts=cuts,
            application_impact=app_impact,
        )


def _impact(value: Any, where: str) -> int:
    n = int(value)
    if not 1 <= n <= 5:
        raise PolicyError(f"risk.{where} must be between 1 and 5, got {n}")
    return n


@dataclass(slots=True)
class ThreatRisk:
    """The matrix cell for one threat within one decision."""

    threat: str
    likelihood: int
    impact: int
    residual_likelihood: int
    detectors: tuple[str, ...]
    mitigated: bool = False

    @property
    def score(self) -> int:
        return self.likelihood * self.impact

    @property
    def residual_score(self) -> int:
        return self.residual_likelihood * self.impact

    @property
    def band(self) -> RiskBand:
        return RiskBand.for_score(self.score)

    @property
    def residual_band(self) -> RiskBand:
        return RiskBand.for_score(self.residual_score)

    def to_dict(self) -> dict[str, Any]:
        t = THREATS.get(self.threat)
        return {
            "threat": self.threat,
            "title": t.title if t else self.threat,
            "framework": t.framework if t else None,
            "likelihood": self.likelihood,
            "impact": self.impact,
            "score": self.score,
            "band": self.band.value,
            "residual_score": self.residual_score,
            "residual_band": self.residual_band.value,
            "mitigated": self.mitigated,
            "detectors": list(self.detectors),
        }


@dataclass(slots=True)
class RiskAssessment:
    """The decision-level risk: the worst residual threat cell.

    ``score``/``band`` are residual (what enforcement acted on);
    ``inherent_score``/``inherent_band`` are before mitigation.
    """

    likelihood: int = 0
    impact: int = 0
    score: int = 0
    band: RiskBand = RiskBand.NONE
    inherent_score: int = 0
    inherent_band: RiskBand = RiskBand.NONE
    primary: str | None = None
    threats: tuple[ThreatRisk, ...] = ()
    action: Action = Action.ALLOW

    @property
    def cell(self) -> tuple[int, int]:
        return (self.likelihood, self.impact)

    def to_dict(self) -> dict[str, Any]:
        return {
            "likelihood": self.likelihood,
            "impact": self.impact,
            "score": self.score,
            "band": self.band.value,
            "inherent_score": self.inherent_score,
            "inherent_band": self.inherent_band.value,
            "primary": self.primary,
            "action": self.action.value,
            "threats": [t.to_dict() for t in self.threats],
        }

    def explain(self) -> str:
        if not self.primary:
            return "no threats identified"
        t = THREATS.get(self.primary)
        title = f" {t.title}" if t else ""
        return (
            f"risk {self.score}/25 ({self.band.value}): likelihood {self.likelihood} x impact "
            f"{self.impact} on {self.primary}{title}"
        )


class RiskEngine:
    """Scores fired findings onto the matrix and proposes an action."""

    def __init__(self, config: RiskConfig | None = None) -> None:
        self.config = config or RiskConfig()

    def likelihood(self, score: float) -> int:
        level = 1
        for cut in self.config.likelihood_cuts:
            if score >= cut:
                level += 1
        return level

    def impact(
        self,
        threat_id: str,
        stage: Stage,
        *,
        tool_call: ToolCall | None = None,
        application: str | None = None,
    ) -> int:
        threat = THREATS.get(threat_id)
        base = self.config.impact_overrides.get(threat_id, threat.base_impact if threat else 3)
        if application and application in self.config.application_impact:
            base = max(base, self.config.application_impact[application])
        if tool_call is not None and tool_call.risk is not None:
            base = max(base, self.config.tool_impact.get(tool_call.risk, base))
        return max(1, min(5, base))

    def assess(
        self,
        findings: Iterable[Finding],
        stage: Stage,
        *,
        tool_call: ToolCall | None = None,
        application: str | None = None,
    ) -> RiskAssessment:
        by_threat: dict[str, list[Finding]] = {}
        for f in findings:
            if not f.detected:
                continue
            for tid in f.threats:
                by_threat.setdefault(tid, []).append(f)

        cells: list[ThreatRisk] = []
        for tid, fs in by_threat.items():
            likelihood = self.likelihood(max(f.score for f in fs))
            detectors = tuple(dict.fromkeys(f.detector for f in fs))
            if len(detectors) >= 2:
                likelihood = min(5, likelihood + 1)
            mitigated = all(f.action is Action.REDACT for f in fs)
            cells.append(
                ThreatRisk(
                    threat=tid,
                    likelihood=likelihood,
                    impact=self.impact(tid, stage, tool_call=tool_call, application=application),
                    residual_likelihood=1 if mitigated else likelihood,
                    detectors=detectors,
                    mitigated=mitigated,
                )
            )
        if not cells:
            return RiskAssessment()

        # Stable sort: on ties the first-mapped threat (the detector's primary
        # category, e.g. LLM01 before ASI01) stays the headline.
        cells.sort(key=lambda c: (-c.residual_score, -c.score))
        worst = cells[0]
        inherent = max(cells, key=lambda c: c.score)
        band = worst.residual_band
        return RiskAssessment(
            likelihood=worst.residual_likelihood,
            impact=worst.impact,
            score=worst.residual_score,
            band=band,
            inherent_score=inherent.score,
            inherent_band=inherent.band,
            primary=worst.threat,
            threats=tuple(cells),
            action=self.config.actions.get(band, Action.ALLOW),
        )

    def trace(self, assessment: RiskAssessment, *, policy_id: str, policy_version: str,
              dry_run: bool = False) -> PolicyTrace | None:
        """The assessment as a policy trace, or ``None`` if it changes nothing."""
        if not self.config.enforce or assessment.action is Action.ALLOW:
            return None
        return PolicyTrace(
            policy_id=policy_id,
            policy_version=policy_version,
            rule_id=f"risk-matrix/{assessment.band.value}",
            matched=True,
            action=Action.ALLOW if dry_run else assessment.action,
            note=(f"[dry-run: would {assessment.action.value}] " if dry_run else "") + assessment.explain(),
        )


def matrix(cells: Sequence[tuple[int, int]]) -> list[list[int]]:
    """Count (likelihood, impact) pairs into a 5x5 grid, ``grid[likelihood-1][impact-1]``."""
    grid = [[0] * 5 for _ in range(5)]
    for likelihood, impact in cells:
        if 1 <= likelihood <= 5 and 1 <= impact <= 5:
            grid[likelihood - 1][impact - 1] += 1
    return grid


__all__ = [
    "DEFAULT_BAND_ACTIONS",
    "RiskAssessment",
    "RiskBand",
    "RiskConfig",
    "RiskEngine",
    "ThreatRisk",
    "matrix",
]
