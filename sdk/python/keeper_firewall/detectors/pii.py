"""PII detection and redaction.

Regex plus validators — not an NER model. That is a deliberate v1 choice:

* It is deterministic, so a redaction decision is reproducible and explainable
  in an audit review ("rule ``credit_card`` matched offsets 41-57, Luhn-valid").
* It costs microseconds, which keeps us inside the latency budget in
  ``docs/architecture.md`` without loading a model into the host process.
* It has no model weights, so the SDK stays a small pure-Python wheel — see
  the supply-chain argument in ``docs/threat-model.md``.

The cost is recall on unstructured PII (names, addresses, free-text health
information). :class:`keeper_firewall.detectors.llm.LLMClassifierDetector` is
the documented upgrade path, and the ``Detector`` contract means an org can
register a Presidio- or spaCy-backed replacement under the same ``pii`` name.

Default action is REDACT, not BLOCK: a user pasting their own phone number
into a support assistant should get an answer, with the number stripped before
it reaches the provider.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterable

from ..config import DetectorConfig
from ..types import Action, Finding, Severity, Span, Stage
from .base import Detector, DetectorInput, detector


def luhn_valid(digits: str) -> bool:
    """Standard Luhn checksum, used to cut credit-card false positives."""
    nums = [int(c) for c in digits if c.isdigit()]
    if len(nums) < 13:
        return False
    checksum = 0
    parity = len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        checksum += n
    return checksum % 10 == 0


def _valid_ssn(value: str) -> bool:
    digits = re.sub(r"\D", "", value)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    return area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000"


def _valid_iban(value: str) -> bool:
    cleaned = re.sub(r"\s", "", value).upper()
    if not (15 <= len(cleaned) <= 34):
        return False
    rearranged = cleaned[4:] + cleaned[:4]
    numeric = "".join(str(ord(c) - 55) if c.isalpha() else c for c in rearranged)
    try:
        return int(numeric) % 97 == 1
    except ValueError:
        return False


# label -> (pattern, severity, validator)
PII_PATTERNS: dict[str, tuple[re.Pattern[str], Severity, Callable[[str], bool] | None]] = {
    "email": (
        re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b"),
        Severity.MEDIUM,
        None,
    ),
    "credit_card": (
        re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
        Severity.HIGH,
        luhn_valid,
    ),
    "us_ssn": (
        re.compile(r"\b\d{3}[\- ]\d{2}[\- ]\d{4}\b"),
        Severity.HIGH,
        _valid_ssn,
    ),
    "iban": (
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b"),
        Severity.HIGH,
        _valid_iban,
    ),
    "phone": (
        re.compile(r"(?<![\w.])(?:\+?\d{1,3}[ .\-]?)?(?:\(\d{2,4}\)[ .\-]?)?\d{3,4}[ .\-]\d{3,4}(?:[ .\-]\d{2,4})?(?![\w.])"),
        Severity.MEDIUM,
        lambda v: 7 <= len(re.sub(r"\D", "", v)) <= 15,
    ),
    "ip_address": (
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b"),
        Severity.LOW,
        None,
    ),
    "date_of_birth": (
        re.compile(r"(?i)\b(?:dob|date of birth)\b\s*[:=]?\s*\d{1,4}[\-/.]\d{1,2}[\-/.]\d{1,4}"),
        Severity.HIGH,
        None,
    ),
    "passport": (
        re.compile(r"(?i)\bpassport(?:\s+(?:no|number|#))?\s*[:=]?\s*([A-Z0-9]{6,9})\b"),
        Severity.HIGH,
        None,
    ),
    "medical_record": (
        re.compile(r"(?i)\b(?:mrn|medical record(?:\s+number)?)\s*[:=#]?\s*([A-Z0-9\-]{5,20})\b"),
        Severity.HIGH,
        None,
    ),
}


@detector("pii")
class PIIDetector(Detector):
    """Finds personal data and, by default, redacts it in place."""

    stages = (Stage.INPUT, Stage.OUTPUT, Stage.TOOL_CALL, Stage.TOOL_RESULT, Stage.MEMORY_WRITE)
    category = "sensitive_data"
    mutates = True

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        enabled = opts.get("entities")
        self.entities: tuple[str, ...] = tuple(enabled) if enabled else tuple(PII_PATTERNS)
        unknown = set(self.entities) - set(PII_PATTERNS) - set(opts.get("custom", {}))
        if unknown:
            raise ValueError(f"unknown PII entities: {', '.join(sorted(unknown))}")
        self.action_on_hit = Action(opts.get("action", "redact"))
        # Entities that should escalate to a hard block rather than redaction.
        self.block_entities: frozenset[str] = frozenset(opts.get("block_entities", ()))
        self.custom: dict[str, tuple[re.Pattern[str], Severity, None]] = {
            label: (re.compile(spec["pattern"]), Severity(spec.get("severity", "medium")), None)
            for label, spec in (opts.get("custom") or {}).items()
        }

    def detect(self, data: DetectorInput) -> Finding:
        spans = list(self._spans(data.payload))
        if not spans:
            return self.clean("no PII detected")

        labels = sorted({s.label for s in spans})
        severities = [self._severity(s.label) for s in spans]
        worst = max(severities, key=lambda s: s.rank())
        action = self.action_on_hit
        if self.block_entities & set(labels):
            action = Action.BLOCK

        return self.hit(
            score=1.0,
            summary=f"{len(spans)} PII item(s) detected: {', '.join(labels)}",
            severity=worst,
            action=action,
            spans=spans,
            labels=labels,
            counts={label: sum(1 for s in spans if s.label == label) for label in labels},
        )

    def _severity(self, label: str) -> Severity:
        if label in PII_PATTERNS:
            return PII_PATTERNS[label][1]
        return self.custom[label][1]

    def _spans(self, payload: str) -> Iterable[Span]:
        taken: list[tuple[int, int]] = []
        table = {**PII_PATTERNS, **self.custom}
        # Longest/highest-signal entities first so a card number is not eaten
        # by the phone pattern.
        order = sorted(
            (e for e in self.entities if e in table),
            key=lambda e: 0 if e in ("credit_card", "iban", "us_ssn") else 1,
        )
        for label in order:
            pattern, _severity, validator = table[label]
            for match in pattern.finditer(payload):
                start, end = (match.span(1) if match.groups() else match.span())
                value = payload[start:end]
                if validator and not validator(value):
                    continue
                if any(start < t_end and t_start < end for t_start, t_end in taken):
                    continue
                taken.append((start, end))
                yield Span(start, end, label)
