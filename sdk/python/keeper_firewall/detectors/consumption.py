"""Unbounded consumption (OWASP LLM10).

Rate limits (in :mod:`keeper_firewall.accesscontrol.ratelimit`) bound *how
often* a principal can call the model. This detector bounds *how much a single
request can cost*: oversized prompts, flooding with repeated tokens (a known
way to push models into divergent, data-regurgitating output), and requests
engineered to make the model generate without end.

All checks are O(n) over the payload and run before the model is called, which
is the only point at which the cost has not been paid yet.
"""

from __future__ import annotations

import re
from collections import Counter

from ..config import DetectorConfig
from ..types import Action, Finding, Severity, Stage
from .base import Detector, DetectorInput, detector

_TOKEN = re.compile(r"\S+")
_RUN = re.compile(r"(.)\1{499,}", re.DOTALL)
_ENDLESS = re.compile(
    r"\b(?:repeat|say|write|output|print)\b[^.\n]{0,40}\b(?:forever|indefinitely|infinitely|endlessly|"
    r"non[- ]?stop|until\s+(?:you\s+)?(?:run\s+out|crash|stop)|\d{4,}\s+times)\b",
    re.IGNORECASE,
)


@detector("resource_abuse")
class ResourceAbuseDetector(Detector):
    """Oversized, flooded or runaway-generation requests."""

    stages = (Stage.INPUT,)
    category = "unbounded_consumption"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.threshold = float(self.config.threshold or 0.6)
        self.max_chars = int(opts.get("max_chars", 100_000))
        self.max_messages = int(opts.get("max_messages", 500))
        self.max_output_tokens = int(opts.get("max_output_tokens", 0))  # 0 = not enforced
        self.flood_min_tokens = int(opts.get("flood_min_tokens", 200))
        self.flood_share = float(opts.get("flood_share", 0.5))

    def detect(self, data: DetectorInput) -> Finding:
        text = data.payload
        signals: list[dict[str, object]] = []
        score = 0.0

        def add(sid: str, weight: float, **kw: object) -> None:
            nonlocal score
            signals.append({"id": sid, "weight": weight, **kw})
            score = max(score, weight)

        total_chars = len(text) + sum(len(m.content) for m in data.history)
        if total_chars > self.max_chars:
            add("oversized_prompt", 0.9, chars=total_chars, limit=self.max_chars)
        if len(data.history) > self.max_messages:
            add("oversized_history", 0.8, messages=len(data.history), limit=self.max_messages)

        tokens = _TOKEN.findall(text)
        if len(tokens) >= self.flood_min_tokens:
            word, count = Counter(t.lower() for t in tokens).most_common(1)[0]
            share = count / len(tokens)
            if share >= self.flood_share:
                add("token_flood", 0.7, token=word[:40], share=round(share, 3), tokens=len(tokens))
        if _RUN.search(text):
            add("character_flood", 0.7)
        m = _ENDLESS.search(text)
        if m:
            add("endless_generation", 0.55, snippet=m.group()[:80])

        requested = data.metadata.get("max_tokens")
        if self.max_output_tokens and isinstance(requested, int) and requested > self.max_output_tokens:
            add("output_budget_exceeded", 0.8, requested=requested, limit=self.max_output_tokens)

        if not signals:
            return self.clean("request within resource bounds", chars=total_chars, tokens=len(tokens))
        ids = ", ".join(sorted(str(s["id"]) for s in signals))
        if score >= self.threshold:
            return self.hit(score, f"request exceeds resource bounds ({ids})", severity=Severity.MEDIUM,
                            action=Action.BLOCK, signals=signals)
        return self.hit(score, f"request shows resource-abuse traits ({ids})", severity=Severity.LOW,
                        action=Action.FLAG, signals=signals)
