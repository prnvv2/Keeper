"""Cross-application anomaly detection.

The division of labour with the SDK matters: the SDK already runs fast local
heuristics on a single conversation. What it structurally cannot see is the
fleet. These detectors exist for exactly the patterns that are invisible from
inside one process:

``repeated_injection``
    One principal, many blocked injection attempts. Visible locally too, but
    only if they hit the same instance; behind a load balancer they do not.

``cross_application_probe``
    The *same* prompt hitting several different applications in a short window.
    This is the highest-signal detection in the system and no single SDK
    instance can produce it. It works on the salted prompt hash the SDK ships
    in ``tags.prompt_sha256``, so it functions even under strict redaction
    where no prompt text is stored at all.

``volume_spike``
    Request or block volume far above the rolling baseline, by z-score.

``new_attack_surface``
    An application that has never blocked anything suddenly starts to — often
    the first sign of a newly exposed endpoint or a changed system prompt.

``coverage_gap``
    An instance running with security detectors disabled, or in monitor-only
    mode, in production. Not an attack: a gap in the picture, and the thing an
    auditor asks about first.

All statistical, all explainable, all cheap. ML-based detection plugs in behind
the same :class:`AnomalyDetector` interface — each returns a list of
:class:`AnomalyFinding`, and the alert pipeline does not care how it got there.
"""

from __future__ import annotations

import math
import statistics
from collections import Counter, defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass(slots=True)
class AnomalyFinding:
    """One cross-application pattern worth telling somebody about."""

    kind: str
    title: str
    description: str
    severity: str = "medium"
    score: float = 0.0
    entities: Mapping[str, Any] = field(default_factory=dict)
    evidence: Mapping[str, Any] = field(default_factory=dict)
    #: Correlation ids an investigator should start from.
    examples: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "title": self.title,
            "description": self.description,
            "severity": self.severity,
            "score": round(self.score, 3),
            "entities": dict(self.entities),
            "evidence": dict(self.evidence),
            "examples": list(self.examples),
        }

    @property
    def dedupe_key(self) -> str:
        return f"{self.kind}:{'|'.join(f'{k}={v}' for k, v in sorted(self.entities.items()))}"


class AnomalyDetector(Protocol):
    name: str

    def analyse(self, events: Sequence[Mapping[str, Any]], config: Mapping[str, Any]) -> list[AnomalyFinding]: ...


class RepeatedInjectionDetector:
    """One principal grinding away at injection attempts."""

    name = "repeated_injection"

    def analyse(self, events, config):
        threshold = int(config.get("injection_threshold", 5))
        by_principal: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
        for event in events:
            if event.get("action") not in ("block", "challenge"):
                continue
            categories = set(event.get("categories") or [])
            if not categories & {"prompt_injection", "multi_turn_attack", "authority_manipulation"}:
                continue
            key = (event.get("principal_id") or "anonymous", event.get("application") or "unknown")
            by_principal[key].append(event)

        findings: list[AnomalyFinding] = []
        for (principal, application), matched in by_principal.items():
            if len(matched) < threshold:
                continue
            findings.append(
                AnomalyFinding(
                    kind=self.name,
                    title=f"{len(matched)} blocked injection attempts from {principal}",
                    description=(
                        f"Principal {principal!r} had {len(matched)} injection or manipulation "
                        f"attempts blocked in {application} within the analysis window."
                    ),
                    severity="high" if len(matched) >= threshold * 2 else "medium",
                    score=min(1.0, len(matched) / (threshold * 3)),
                    entities={"principal_id": principal, "application": application},
                    evidence={
                        "count": len(matched),
                        "categories": sorted({c for e in matched for c in (e.get("categories") or [])}),
                        "detectors": sorted({d for e in matched for d in (e.get("detectors_fired") or [])}),
                    },
                    examples=tuple(e["correlation_id"] for e in matched[:5]),
                )
            )
        return findings


class CrossApplicationProbeDetector:
    """The same payload probing several applications.

    Works from ``tags.prompt_sha256`` — the salted digest the SDK attaches to
    every event — so it keeps working when redaction mode is ``none`` and no
    prompt text exists anywhere in the control plane. That is the point of
    shipping the hash even when we do not ship the text.
    """

    name = "cross_application_probe"

    def analyse(self, events, config):
        threshold = int(config.get("cross_app_threshold", 2))
        by_hash: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
        for event in events:
            digest = (event.get("tags") or {}).get("prompt_sha256")
            if digest:
                by_hash[digest].append(event)

        findings: list[AnomalyFinding] = []
        for digest, matched in by_hash.items():
            apps = {e.get("application") for e in matched}
            if len(apps) < threshold:
                continue
            flagged = [e for e in matched if e.get("action") in ("block", "challenge", "flag")]
            if not flagged:
                continue  # the same benign prompt in two apps is not an event
            principals = {e.get("principal_id") for e in matched}
            findings.append(
                AnomalyFinding(
                    kind=self.name,
                    title=f"Identical payload probed {len(apps)} applications",
                    description=(
                        f"The same prompt (hash {digest[:12]}…) appeared in {len(apps)} applications "
                        f"and was flagged or blocked {len(flagged)} times. This pattern is invisible "
                        "to any single SDK instance."
                    ),
                    severity="high",
                    score=min(1.0, len(apps) / (threshold * 2)),
                    entities={"prompt_sha256": digest},
                    evidence={
                        "applications": sorted(a for a in apps if a),
                        "principals": sorted(p for p in principals if p),
                        "flagged": len(flagged),
                        "total": len(matched),
                    },
                    examples=tuple(e["correlation_id"] for e in flagged[:5]),
                )
            )
        return findings


class VolumeSpikeDetector:
    """Request or block volume far outside the rolling baseline."""

    name = "volume_spike"

    def analyse(self, events, config):
        sigma = float(config.get("volume_sigma", 3.0))
        buckets: dict[int, Counter] = defaultdict(Counter)
        for event in events:
            minute = int(event["timestamp_ms"]) // 60_000
            buckets[minute][event.get("application") or "unknown"] += 1

        if len(buckets) < 5:
            return []  # not enough history for a baseline to mean anything

        ordered = sorted(buckets)
        latest, history = ordered[-1], ordered[:-1]
        findings: list[AnomalyFinding] = []
        applications = {app for counter in buckets.values() for app in counter}

        for application in applications:
            series = [buckets[m].get(application, 0) for m in history]
            current = buckets[latest].get(application, 0)
            if len(series) < 4 or current == 0:
                continue
            mean = statistics.fmean(series)
            stdev = statistics.pstdev(series)
            if stdev < 1e-6:
                # A flat baseline with a sudden burst is still notable, but a
                # z-score is undefined; fall back to a multiple of the mean.
                if mean > 0 and current > max(10.0, mean * 5):
                    findings.append(self._finding(application, current, mean, float("inf")))
                continue
            z = (current - mean) / stdev
            if z >= sigma:
                findings.append(self._finding(application, current, mean, z))
        return findings

    @staticmethod
    def _finding(application: str, current: int, mean: float, z: float) -> AnomalyFinding:
        return AnomalyFinding(
            kind="volume_spike",
            title=f"Traffic spike in {application}",
            description=(
                f"{application} received {current} events in the last minute against a baseline "
                f"of {mean:.1f} (z={'inf' if math.isinf(z) else f'{z:.1f}'})."
            ),
            severity="medium",
            score=min(1.0, 0.5 if math.isinf(z) else z / 10),
            entities={"application": application},
            evidence={"current": current, "baseline_mean": round(mean, 2), "z_score": None if math.isinf(z) else round(z, 2)},
        )


class NewAttackSurfaceDetector:
    """An application that has never blocked anything suddenly does."""

    name = "new_attack_surface"

    def analyse(self, events, config):
        ordered = sorted(events, key=lambda e: e["timestamp_ms"])
        if len(ordered) < 20:
            return []
        midpoint = len(ordered) // 2
        early, late = ordered[:midpoint], ordered[midpoint:]

        def blockers(rows):
            return {r["application"] for r in rows if r.get("action") in ("block", "challenge")}

        newly = blockers(late) - blockers(early)
        seen_early = {r["application"] for r in early}
        findings: list[AnomalyFinding] = []
        for application in newly:
            if application not in seen_early:
                continue  # a brand-new application is a deploy, not an anomaly
            matched = [
                r for r in late
                if r["application"] == application and r.get("action") in ("block", "challenge")
            ]
            findings.append(
                AnomalyFinding(
                    kind=self.name,
                    title=f"{application} started blocking requests",
                    description=(
                        f"{application} produced no blocks in the first half of the window and "
                        f"{len(matched)} in the second. Worth checking whether an endpoint, "
                        "system prompt, or data source changed."
                    ),
                    severity="medium",
                    score=0.5,
                    entities={"application": application},
                    evidence={
                        "blocks": len(matched),
                        "categories": sorted({c for e in matched for c in (e.get("categories") or [])}),
                    },
                    examples=tuple(e["correlation_id"] for e in matched[:3]),
                )
            )
        return findings


class CoverageGapDetector:
    """Instances running without the protection you think they have."""

    name = "coverage_gap"

    #: Detectors whose absence in a production instance is worth reporting.
    EXPECTED = frozenset({"secrets", "pii", "prompt_injection"})

    def analyse(self, events, config):
        instances = config.get("instances") or []
        findings: list[AnomalyFinding] = []
        for instance in instances:
            if instance.get("environment") not in ("production", "prod"):
                continue
            if instance.get("status") == "stale":
                continue
            missing = sorted(self.EXPECTED - set(instance.get("detectors") or []))
            monitor_only = bool(instance.get("monitor_only"))
            if not missing and not monitor_only:
                continue
            reasons = []
            if missing:
                reasons.append(f"detectors disabled: {', '.join(missing)}")
            if monitor_only:
                reasons.append("running in monitor-only mode (nothing is blocked)")
            findings.append(
                AnomalyFinding(
                    kind=self.name,
                    title=f"Coverage gap in {instance.get('application')}",
                    description=(
                        f"Production instance {instance.get('instance_id')} of "
                        f"{instance.get('application')} is not fully protected: {'; '.join(reasons)}."
                    ),
                    severity="high" if missing else "medium",
                    score=0.6,
                    entities={
                        "application": instance.get("application"),
                        "instance_id": instance.get("instance_id"),
                    },
                    evidence={"missing_detectors": missing, "monitor_only": monitor_only,
                              "sdk_version": instance.get("sdk_version")},
                )
            )
        return findings


DEFAULT_DETECTORS: tuple[AnomalyDetector, ...] = (
    RepeatedInjectionDetector(),
    CrossApplicationProbeDetector(),
    VolumeSpikeDetector(),
    NewAttackSurfaceDetector(),
    CoverageGapDetector(),
)


def analyse(
    events: Sequence[Mapping[str, Any]],
    config: Mapping[str, Any],
    detectors: Sequence[AnomalyDetector] = DEFAULT_DETECTORS,
) -> list[AnomalyFinding]:
    """Run every detector. One failing must not silence the others."""
    findings: list[AnomalyFinding] = []
    for detector in detectors:
        try:
            findings.extend(detector.analyse(events, config))
        except Exception:
            continue
    return sorted(findings, key=lambda f: (-_SEVERITY[f.severity], -f.score))


_SEVERITY = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
