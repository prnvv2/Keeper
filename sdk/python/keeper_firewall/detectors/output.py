"""Output-side detectors.

Output filtering answers a different question from input filtering. On the way
in we ask "is this input trying to subvert the model?"; on the way out we ask
"does this response disclose something it should not, or assert something the
context does not support?".

Three detectors live here:

* :class:`SecretLeakageDetector` — the model echoing context back out. The
  interesting case is not a generic credential (the ``secrets`` detector
  already covers that on both sides) but a *known* secret: a value the host
  application registered as confidential appearing verbatim in the response.
  That is cross-tenant or system-prompt leakage, and it is unambiguous.

* :class:`BannedTopicsDetector` — deterministic content policy. Term lists with
  per-category severity, plus optional regex rules. Not a safety classifier and
  not pretending to be one: it enforces *the organisation's* list, which is the
  part a compliance team can actually review and sign off.

* :class:`GroundednessDetector` — does the answer stay inside the retrieved
  context? Cheap lexical overlap, off by default, and honest about being a
  screen rather than a hallucination oracle.
"""

from __future__ import annotations

import hashlib
import re
from typing import Iterable, Sequence

from ..config import DetectorConfig
from ..types import Action, Finding, Severity, Span, Stage
from .base import Detector, DetectorInput, detector
from .secrets import VENDOR_PATTERNS


@detector("secret_leakage")
class SecretLeakageDetector(Detector):
    """Detects known-confidential values echoed in a model response.

    The host application registers the values it considers confidential — the
    system prompt, a tenant's records, API keys held in config — via
    ``Keeper.register_secret()``. We store only salted hashes of those values,
    so the detector never keeps a second copy of anyone's secret in memory in
    plaintext, and match by scanning candidate substrings of the output.

    Matching is exact-substring on normalised text. Fuzzy or semantic leakage
    (the model *describing* a secret rather than quoting it) is out of scope
    and documented as such in ``docs/threat-model.md``.
    """

    stages = (Stage.OUTPUT, Stage.STREAM, Stage.TOOL_CALL)
    category = "data_leakage"
    mutates = True

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.min_length: int = int(opts.get("min_length", 8))
        self.action_on_hit = Action(opts.get("action", "block"))
        self._salt = (opts.get("salt") or "keeper").encode()
        self._hashes: dict[str, tuple[str, int]] = {}  # digest -> (label, length)
        self._lengths: set[int] = set()
        for label, value in (opts.get("secrets") or {}).items():
            self.register(value, label=label)

    def register(self, value: str, *, label: str = "registered_secret") -> None:
        """Register a confidential value. Only its salted hash is retained."""
        value = value.strip()
        if len(value) < self.min_length:
            return
        self._hashes[self._digest(value)] = (label, len(value))
        self._lengths.add(len(value))

    def _digest(self, value: str) -> str:
        return hashlib.sha256(self._salt + value.encode("utf-8", "replace")).hexdigest()

    def detect(self, data: DetectorInput) -> Finding:
        spans: list[Span] = []
        payload = data.payload
        if self._hashes and payload:
            # Only lengths we actually registered are candidates, so this is
            # O(len(payload) * distinct_lengths), not O(n^2).
            for length in sorted(self._lengths):
                for i in range(0, max(0, len(payload) - length + 1)):
                    window = payload[i : i + length]
                    hit = self._hashes.get(self._digest(window))
                    if hit:
                        spans.append(Span(i, i + length, f"leaked:{hit[0]}"))

        # A generic live-looking credential in *model output* is always wrong:
        # the model has no legitimate reason to emit one.
        for label, pattern, _sev in VENDOR_PATTERNS:
            for match in pattern.finditer(payload):
                start, end = match.span(1) if match.groups() else match.span()
                spans.append(Span(start, end, f"credential:{label}"))

        if not spans:
            return self.clean("no known secrets in response")

        spans = _dedupe(spans)
        labels = sorted({s.label for s in spans})
        return self.hit(
            score=1.0,
            summary=f"response contains confidential material: {', '.join(labels)}",
            severity=Severity.CRITICAL,
            action=self.action_on_hit,
            spans=spans,
            labels=labels,
        )


#: Default categories. Intentionally short and generic — this is a starting
#: point an organisation replaces with its own list, not a safety taxonomy.
DEFAULT_TERMS: dict[str, tuple[Severity, tuple[str, ...]]] = {
    "weapons": (Severity.HIGH, ("pipe bomb", "improvised explosive", "detonator wiring", "nerve agent synthesis")),
    "malware": (Severity.HIGH, ("ransomware payload", "keylogger source", "credential stealer", "reverse shell payload")),
    "self_harm": (Severity.CRITICAL, ("lethal dose of", "how to end my life")),
    "fraud": (Severity.MEDIUM, ("stolen credit card", "money laundering steps", "how to launder")),
}


@detector("banned_topics")
class BannedTopicsDetector(Detector):
    """Deterministic organisational content policy.

    Runs on both input and output. Term matching is word-boundary aware and
    case-insensitive; regex rules are available for anything a term list cannot
    express (a banned claim template, a competitor comparison, a regulated
    phrase like "guaranteed return").
    """

    stages = (Stage.INPUT, Stage.OUTPUT, Stage.STREAM)
    category = "content_policy"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.action_on_hit = Action(opts.get("action", "block"))
        categories = opts.get("categories")
        self.terms: dict[str, tuple[Severity, tuple[str, ...]]] = (
            {
                name: (Severity(spec.get("severity", "medium")), tuple(spec["terms"]))
                for name, spec in categories.items()
            }
            if categories
            else dict(DEFAULT_TERMS)
        )
        self._compiled: dict[str, tuple[Severity, re.Pattern[str]]] = {
            name: (sev, re.compile("|".join(rf"\b{re.escape(t)}\b" for t in terms), re.IGNORECASE))
            for name, (sev, terms) in self.terms.items()
            if terms
        }
        self.rules: dict[str, tuple[Severity, re.Pattern[str]]] = {
            name: (Severity(spec.get("severity", "medium")), re.compile(spec["pattern"], re.IGNORECASE))
            for name, spec in (opts.get("rules") or {}).items()
        }

    def detect(self, data: DetectorInput) -> Finding:
        spans: list[Span] = []
        severities: list[Severity] = []
        categories: list[str] = []
        for name, (sev, pattern) in {**self._compiled, **self.rules}.items():
            for match in pattern.finditer(data.payload):
                spans.append(Span(match.start(), match.end(), f"banned:{name}"))
                severities.append(sev)
                categories.append(name)

        if not spans:
            return self.clean("no banned content")

        return self.hit(
            score=1.0,
            summary=f"banned content in category/categories: {', '.join(sorted(set(categories)))}",
            severity=max(severities, key=lambda s: s.rank()),
            action=self.action_on_hit,
            spans=_dedupe(spans),
            categories=sorted(set(categories)),
            matches=len(spans),
        )


_SENTENCE = re.compile(r"(?<=[.!?])\s+")
_WORD = re.compile(r"[a-z0-9]+")
_STOPWORDS = frozenset(
    "a an the and or but if then of to in on at by for with from as is are was were be been being "
    "this that these those it its it's you your we our they their he she his her i me my do does did "
    "not no can could would should will shall may might must have has had there here what which who "
    "when where why how all any some each other more most than so such only own same too very".split()
)


@detector("groundedness")
class GroundednessDetector(Detector):
    """Screens a RAG answer for claims the retrieved context does not support.

    Sentence-level lexical overlap against the grounding passages. This is a
    *screen*, not a hallucination detector: it reliably catches an answer that
    wandered away from its sources entirely, and it will not catch a fluent
    fabrication that reuses the source's vocabulary. It defaults to FLAG for
    exactly that reason — blocking on a lexical heuristic would be
    indefensible. Off by default; enable it where you have real grounding
    passages to compare against.
    """

    stages = (Stage.OUTPUT,)
    category = "hallucination"

    def __init__(self, config: DetectorConfig | None = None) -> None:
        super().__init__(config)
        opts = self.config.options
        self.min_overlap: float = float(opts.get("min_overlap", 0.3))
        self.min_sentence_words: int = int(opts.get("min_sentence_words", 6))
        self.max_unsupported_ratio: float = float(opts.get("max_unsupported_ratio", 0.5))
        self.action_on_hit = Action(opts.get("action", "flag"))

    def detect(self, data: DetectorInput) -> Finding:
        grounding = list(data.grounding) or [d.content for d in data.documents]
        if not grounding:
            return self.clean("no grounding context supplied; groundedness not evaluated")

        vocab = _content_words(" ".join(grounding))
        if not vocab:
            return self.clean("grounding context has no content words")

        sentences = [s for s in _SENTENCE.split(data.payload) if s.strip()]
        scored: list[tuple[str, float]] = []
        for sentence in sentences:
            words = _content_words(sentence)
            if len(words) < self.min_sentence_words:
                continue
            overlap = len(words & vocab) / len(words)
            scored.append((sentence.strip(), overlap))

        if not scored:
            return self.clean("no substantive sentences to check")

        unsupported = [(s, o) for s, o in scored if o < self.min_overlap]
        ratio = len(unsupported) / len(scored)
        evidence = {
            "sentences_checked": len(scored),
            "unsupported_sentences": len(unsupported),
            "unsupported_ratio": round(ratio, 3),
            "examples": [s[:160] for s, _ in unsupported[:3]],
            "mean_overlap": round(sum(o for _, o in scored) / len(scored), 3),
        }
        if ratio > self.max_unsupported_ratio:
            return self.hit(
                score=min(1.0, ratio),
                summary=(
                    f"{len(unsupported)} of {len(scored)} sentences are not supported "
                    "by the retrieved context"
                ),
                severity=Severity.MEDIUM,
                action=self.action_on_hit,
                **evidence,
            )
        return self.clean("response is grounded in the retrieved context", **evidence)


def _content_words(text: str) -> set[str]:
    return {w for w in _WORD.findall(text.lower()) if w not in _STOPWORDS and len(w) > 2}


def _dedupe(spans: Iterable[Span]) -> tuple[Span, ...]:
    """Drop spans fully contained in another span, keeping the outermost."""
    ordered: Sequence[Span] = sorted(spans, key=lambda s: (s.start, -(s.end - s.start)))
    out: list[Span] = []
    for span in ordered:
        if out and span.start >= out[-1].start and span.end <= out[-1].end:
            continue
        out.append(span)
    return tuple(out)
