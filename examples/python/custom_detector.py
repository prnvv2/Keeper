"""Writing your own detector.

Third-party detectors use exactly the same contract as the built-ins — there is
no second-class plugin tier. Registering a name that already exists *replaces*
it, which is how an organisation swaps the regex PII detector for a
Presidio-backed one without forking the SDK.

    python examples/python/custom_detector.py
"""

from __future__ import annotations

import re

from keeper_firewall import (
    Action,
    Detector,
    DetectorConfig,
    DetectorInput,
    Keeper,
    Severity,
    Span,
    Stage,
)
from keeper_firewall.detectors import register


class InternalCodenameDetector(Detector):
    """Redacts internal project codenames before they reach a model provider.

    The kind of detector every organisation ends up wanting and nobody can ship
    for them, because the term list is the organisation.
    """

    name = "internal_codenames"
    stages = (Stage.INPUT, Stage.OUTPUT, Stage.TOOL_CALL)
    category = "content_policy"
    mutates = True          # allows the pipeline to call redact()

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        codenames = self.config.options.get("codenames", ["project falcon", "bluebird"])
        # One alternation, compiled once. A detector runs on every request; the
        # per-request cost should be a match, not a compile.
        self._pattern = re.compile("|".join(rf"\b{re.escape(c)}\b" for c in codenames), re.IGNORECASE)

    def detect(self, data: DetectorInput):
        spans = [
            Span(start=m.start(), end=m.end(), label="internal_codename")
            for m in self._pattern.finditer(data.payload)
        ]
        if not spans:
            return self.clean("no internal codenames")

        return self.hit(
            score=1.0,
            summary=f"{len(spans)} internal codename(s) referenced",
            severity=Severity.MEDIUM,
            action=Action.REDACT,
            spans=spans,
            # Evidence is what makes a decision reviewable rather than a black
            # box. Put the reasoning here, not just the verdict.
            matched=[data.payload[s.start : s.end] for s in spans],
        )


class BusinessHoursDetector(Detector):
    """A detector that reasons about context rather than content.

    Nothing says a detector has to look at the payload. This one flags
    high-risk activity outside business hours — a signal that is invisible to
    content analysis and genuinely useful in an insider-threat model.
    """

    name = "out_of_hours"
    stages = (Stage.TOOL_CALL,)
    category = "anomalous_access"

    def detect(self, data: DetectorInput):
        import datetime as dt

        hour = dt.datetime.now(dt.timezone.utc).hour
        if 6 <= hour < 20:
            return self.clean("within business hours", hour=hour)
        return self.hit(
            score=0.4,
            summary=f"privileged tool call at {hour:02d}:00 UTC, outside business hours",
            severity=Severity.LOW,
            action=Action.FLAG,          # a signal, not a verdict
            hour=hour,
            tool=data.tool_call.name if data.tool_call else None,
        )


def main() -> None:
    # Two registration paths, both first-class.
    register("internal_codenames", lambda cfg: InternalCodenameDetector(cfg))

    keeper = Keeper(
        application="custom-detector-demo",
        environment="development",
        # Configure it like any built-in.
        detectors={"internal_codenames": {"options": {"codenames": ["project falcon", "orion"]}}},
        # Or pass an instance directly.
        extra_detectors=[BusinessHoursDetector(DetectorConfig())],
    )

    # The pipeline's stage defaults do not know about your detector, so name it
    # explicitly — or add it to a policy bundle's detector list.
    decision = keeper.pipeline.evaluate(
        Stage.INPUT,
        "Can you summarise the Project Falcon roadmap and the Orion timeline?",
        keeper.context(user="u-1"),
        detectors=["internal_codenames", "pii", "secrets"],
    )
    print(f"action   : {decision.action.value}")
    print(f"redacted : {decision.payload}")
    print(f"evidence : {decision.reasons[0].evidence['matched']}\n")

    decision = keeper.pipeline.evaluate(
        Stage.TOOL_CALL,
        "db.query(sql='SELECT * FROM payroll')",
        keeper.context(user="u-1"),
        detectors=["out_of_hours", "token_flow"],
    )
    for finding in decision.findings:
        print(f"{finding.detector:20} {finding.action.value:8} {finding.summary}")

    keeper.close()


if __name__ == "__main__":
    main()
