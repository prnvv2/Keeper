"""Credential and secret detection.

Deterministic by design. Two complementary signals:

* **Vendor patterns** — provider-specific key shapes (``sk-``, ``ghp_``,
  ``AKIA``…). High precision, near-zero false positives, so they justify a
  BLOCK-or-REDACT action on their own.
* **Structural entropy** — an assignment like ``api_key = "<40 chars of
  base64>"`` where the value has high Shannon entropy. Catches credentials from
  vendors we have never heard of, at the cost of some false positives, so it is
  scored lower and defaults to REDACT rather than BLOCK.

This detector fails *closed* (see :func:`keeper_firewall.config.default_detectors`):
if it cannot run we do not know whether a live credential is about to be sent
to a third-party model provider.
"""

from __future__ import annotations

import math
import re
from typing import Iterable

from ..config import DetectorConfig
from ..types import Action, Finding, Severity, Span, Stage
from .base import Detector, DetectorInput, detector

# (label, compiled pattern, severity) — ordered most specific first.
VENDOR_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity], ...] = (
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("aws_secret_access_key", re.compile(r"(?i)aws_secret_access_key\s*[=:]\s*['\"]?([A-Za-z0-9/+=]{40})"), Severity.CRITICAL),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"), Severity.CRITICAL),
    ("gitlab_token", re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("anthropic_key", re.compile(r"\bsk-ant-[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.CRITICAL),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9\-]{10,}\b"), Severity.CRITICAL),
    ("stripe_key", re.compile(r"\b[rs]k_(?:live|test)_[A-Za-z0-9]{16,}\b"), Severity.CRITICAL),
    ("twilio_sid", re.compile(r"\bAC[0-9a-fA-F]{32}\b"), Severity.HIGH),
    ("sendgrid_key", re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.CRITICAL),
    ("npm_token", re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |PGP |DSA )?PRIVATE KEY-----"), Severity.CRITICAL),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b"), Severity.HIGH),
    ("basic_auth_url", re.compile(r"\b[a-z][a-z0-9+.\-]{0,31}://[^\s/:@]{1,256}:[^\s/@]{3,256}@[^\s/]{1,256}"), Severity.HIGH),
    ("bearer_header", re.compile(r"(?i)\bauthorization\s*:\s*bearer\s+[A-Za-z0-9._\-]{16,}"), Severity.HIGH),
)

# key = "value" style assignments whose value we then entropy-test.
ASSIGNMENT = re.compile(
    r"(?i)\b(?P<key>[a-z0-9_.\-]{0,64}(?:secret|token|password|passwd|pwd|api[_\-]?key|access[_\-]?key|"
    r"client[_\-]?secret|credential)s?)\b\s*[=:]\s*['\"]?(?P<value>[^\s'\"]{12,})['\"]?"
)

_PLACEHOLDERS = {
    "xxx", "changeme", "your_api_key", "yourapikey", "todo", "redacted",
    "placeholder", "example", "none", "null", "abc123", "secret", "password",
}


def shannon_entropy(value: str) -> float:
    """Bits of entropy per character. Random base64 lands around 5.5–6.0."""
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for ch in value:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(value)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    low = value.strip().strip("<>{}[]").lower()
    if low in _PLACEHOLDERS:
        return True
    # "your-api-key-here", "REPLACE_ME", "***"
    return bool(re.fullmatch(r"[*x•]+|(?:your|my|the|replace|insert)[\w\-]*", low))


@detector("secrets")
class SecretDetector(Detector):
    """Finds live-looking credentials in a payload."""

    stages = (Stage.INPUT, Stage.OUTPUT, Stage.TOOL_CALL, Stage.TOOL_RESULT, Stage.MEMORY_WRITE)
    category = "credential_exposure"
    mutates = True

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.entropy_threshold: float = float(opts.get("entropy_threshold", 3.6))
        self.min_entropy_length: int = int(opts.get("min_entropy_length", 16))
        self.entropy_enabled: bool = bool(opts.get("entropy_enabled", True))
        self.action_on_hit = Action(opts.get("action", "block"))
        extra = opts.get("extra_patterns") or []
        self.extra: tuple[tuple[str, re.Pattern[str], Severity], ...] = tuple(
            (p.get("label", "custom_secret"), re.compile(p["pattern"]), Severity(p.get("severity", "high")))
            for p in extra
        )

    def detect(self, data: DetectorInput) -> Finding:
        spans = list(self._vendor_spans(data.payload))
        worst = Severity.CRITICAL if spans else Severity.INFO
        entropy_hits: list[str] = []

        if self.entropy_enabled:
            for match in ASSIGNMENT.finditer(data.payload):
                value = match.group("value")
                if looks_like_placeholder(value) or len(value) < self.min_entropy_length:
                    continue
                if shannon_entropy(value) < self.entropy_threshold:
                    continue
                start, end = match.span("value")
                if any(s.start <= start < s.end for s in spans):
                    continue  # already covered by a vendor pattern
                label = f"generic_secret:{match.group('key').lower()}"
                spans.append(Span(start, end, label))
                entropy_hits.append(match.group("key"))
                worst = max(worst, Severity.HIGH, key=lambda s: s.rank())

        if not spans:
            return self.clean("no credentials detected")

        labels = sorted({s.label for s in spans})
        vendor_labels = [label for label in labels if not label.startswith("generic_secret")]
        return self.hit(
            score=1.0 if vendor_labels else 0.7,
            summary=f"credential material detected: {', '.join(labels)}",
            severity=worst,
            action=self.action_on_hit,
            spans=spans,
            labels=labels,
            vendor_matches=len(vendor_labels),
            entropy_matches=entropy_hits,
        )

    def _vendor_spans(self, payload: str) -> Iterable[Span]:
        for label, pattern, _severity in VENDOR_PATTERNS + self.extra:
            for match in pattern.finditer(payload):
                # Prefer the capture group when the pattern has one (so we do
                # not redact the surrounding "aws_secret_access_key =" text).
                if match.groups():
                    start, end = match.span(1)
                else:
                    start, end = match.span()
                yield Span(start, end, label, snippet="")
