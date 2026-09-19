"""Redaction of payloads before they enter the audit trail.

An AI firewall that ships every prompt verbatim to a central store has created
a new, highly concentrated data-protection problem in the name of solving a
security one. So redaction is a first-class part of the observability path, not
a config afterthought, and the default is the conservative option.

Four modes:

``none``
    Nothing of the payload is recorded. Findings, spans and policy traces still
    are, so the dashboard remains useful; the investigator sees *that* a card
    number was present at offsets 41-57, not what it was.

``hash_only``
    As ``none``, plus a salted digest so identical prompts can be correlated
    across applications without the content ever being stored. This is what
    makes fleet-wide "the same probe hit four apps" detection possible under
    strict data handling.

``redacted`` (default)
    The payload with every detected span replaced by a typed placeholder, and a
    safety-net pass for patterns no detector claimed.

``full``
    The raw payload. Legitimate for a staging environment or a regulated
    workload where the audit store is already the system of record, but it must
    be a deliberate choice, so it is never the default.

The salt matters: without one, a digest of a short or low-entropy payload is
trivially reversible by brute force. If the operator does not set
``redaction.hash_salt`` we generate a random per-process salt, which keeps
digests correlatable within a process but not across restarts — safe, but the
degraded mode, and we say so in the docs.
"""

from __future__ import annotations

import hashlib
import re
import secrets as _secrets
from typing import Iterable, Sequence

from ..config import RedactionConfig
from ..types import Finding, Span

#: Patterns applied as a safety net in ``redacted`` mode, independent of which
#: detectors ran. A disabled PII detector must not become a silent data leak
#: into the audit store.
SAFETY_NET: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("email", re.compile(r"\b[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}\b")),
    ("card_like", re.compile(r"\b(?:\d[ \-]?){13,19}\b")),
    ("token_like", re.compile(r"\b(?:sk|pk|gh[pousr]|xox[abprs]|glpat)[-_][A-Za-z0-9_\-]{16,}\b")),
    ("bearer", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}")),
    ("private_key", re.compile(r"-----BEGIN[^-]{0,40}PRIVATE KEY-----[\s\S]{0,16384}?-----END[^-]{0,40}PRIVATE KEY-----")),
)


class Redactor:
    """Applies a :class:`RedactionConfig` to payloads bound for the audit trail."""

    def __init__(self, config: RedactionConfig | None = None) -> None:
        self.config = config or RedactionConfig()
        salt = self.config.hash_salt
        self._ephemeral_salt = salt is None
        self._salt = (salt or _secrets.token_hex(16)).encode()

    @property
    def uses_ephemeral_salt(self) -> bool:
        """True when digests will not correlate across process restarts."""
        return self._ephemeral_salt

    def digest(self, payload: str) -> str:
        return hashlib.sha256(self._salt + payload.encode("utf-8", "replace")).hexdigest()[:32]

    def apply(
        self,
        payload: str | None,
        findings: Iterable[Finding] = (),
        *,
        kind: str = "prompt",
    ) -> tuple[str | None, tuple[str, ...]]:
        """Return ``(payload_for_audit, redacted_labels)``."""
        if payload is None:
            return None, ()
        mode = self.config.mode
        if kind == "prompt" and not self.config.include_prompt:
            return None, ()
        if kind == "response" and not self.config.include_response:
            return None, ()

        if mode == "none":
            return None, ()
        if mode == "hash_only":
            return f"sha256:{self.digest(payload)}", ("*",)
        if mode == "full":
            return self._truncate(payload), ()

        redacted, labels = self.redact(payload, findings)
        return self._truncate(redacted), labels

    def redact(self, payload: str, findings: Iterable[Finding] = ()) -> tuple[str, tuple[str, ...]]:
        """Replace detector spans, then apply the safety net to what is left."""
        spans: list[Span] = []
        for finding in findings:
            if finding.detected:
                spans.extend(finding.spans)

        out, labels = replace_spans(payload, spans)

        extra: list[str] = []
        for label, pattern in SAFETY_NET:
            out, n = pattern.subn(f"[REDACTED:{label}]", out)
            if n:
                extra.append(label)
        for raw in self.config.extra_patterns:
            out, n = re.subn(raw, "[REDACTED:custom]", out)
            if n:
                extra.append("custom")

        return out, tuple(dict.fromkeys(list(labels) + extra))

    def _truncate(self, payload: str) -> str:
        limit = self.config.max_chars
        if limit <= 0 or len(payload) <= limit:
            return payload
        return payload[:limit] + f"…[truncated {len(payload) - limit} chars]"


def replace_spans(payload: str, spans: Sequence[Span]) -> tuple[str, tuple[str, ...]]:
    """Replace ``spans`` with typed placeholders, right to left.

    Overlapping spans are merged: two detectors both flagging the same card
    number must produce one placeholder, not a placeholder nested inside a
    mangled second one.
    """
    if not spans:
        return payload, ()
    merged: list[Span] = []
    for span in sorted(spans, key=lambda s: (s.start, -s.end)):
        if merged and span.start < merged[-1].end:
            last = merged[-1]
            if span.end > last.end:
                merged[-1] = Span(last.start, span.end, f"{last.label}+{span.label}")
            continue
        merged.append(span)

    out = payload
    for span in reversed(merged):
        if not (0 <= span.start <= span.end <= len(out)):
            continue
        out = out[: span.start] + f"[REDACTED:{span.label}]" + out[span.end :]
    return out, tuple(dict.fromkeys(s.label for s in merged))
