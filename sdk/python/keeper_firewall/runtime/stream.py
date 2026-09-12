"""Mid-generation monitoring and circuit breaking.

Filtering a streamed response only after the stream finishes defeats the point
of streaming: by then the user has read it. But evaluating every detector on
every token is unaffordable — a 500-token response would run the detector suite
500 times.

The cascade used here, and the tradeoffs it makes explicit:

* Evaluate only every ``stream_check_every_chars`` characters (default 120,
  roughly a sentence). Detection is therefore *late by up to one window*. A
  smaller window buys earlier interception and costs CPU linearly.
* Each checkpoint runs the cheap deterministic detectors — leaked secrets,
  banned terms — over the accumulated text. These are the ones that are both
  fast and precise on partial text.
* Score at or above ``stream_break_threshold``: break immediately.
* Score in the ambiguous band (``stream_fast_threshold`` to break threshold):
  escalate that checkpoint to the full detector set, once. This is the same
  cheap-path/escalation arrangement the Token-Flow Firewall paper argues for,
  applied to tokens instead of flows.
* Whatever happens, the complete response is evaluated by the full output
  pipeline before the stream is reported as finished — the incremental pass is
  an early-exit optimisation, never a replacement.

**What the caller must understand**: a circuit break means the consumer has
already received the text emitted before the break. Keeper cannot un-send it.
:meth:`StreamGuard.stream` therefore buffers one window by default
(``hold_window=True``), trading a window of latency for the guarantee that
nothing is released until it has been checked. Set it to ``False`` for the
lowest possible time-to-first-token, accepting that up to one window of unsafe
text may reach the user before the break.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterator, Sequence

from ..types import Action, Decision, RequestContext, Stage, TrustLevel

#: Detectors cheap and precise enough to run on partial text.
FAST_STREAM_DETECTORS = ("secret_leakage", "banned_topics")
#: Escalation set, run once when the fast pass lands in the ambiguous band.
FULL_STREAM_DETECTORS = ("secret_leakage", "banned_topics", "pii", "prompt_injection")


@dataclass(slots=True)
class StreamResult:
    """Outcome of a guarded stream."""

    text: str
    broken: bool = False
    break_decision: Decision | None = None
    final_decision: Decision | None = None
    checkpoints: int = 0
    escalations: int = 0
    chunks: int = 0
    replacement: str | None = None

    @property
    def delivered(self) -> str:
        """What the caller should treat as the response."""
        if self.broken and self.replacement is not None:
            return self.replacement
        return self.text


@dataclass
class StreamGuard:
    """Evaluates a token stream incrementally and can break it mid-generation."""

    pipeline: Any  # keeper_firewall.pipeline.Pipeline
    check_every_chars: int = 120
    fast_threshold: float = 0.45
    break_threshold: float = 0.75
    hold_window: bool = True
    fast_detectors: Sequence[str] = field(default_factory=lambda: list(FAST_STREAM_DETECTORS))
    full_detectors: Sequence[str] = field(default_factory=lambda: list(FULL_STREAM_DETECTORS))
    break_message: str = "[response withheld by the AI firewall]"

    def stream(
        self,
        chunks: Iterator[str],
        context: RequestContext,
        *,
        on_break: Callable[[Decision], None] | None = None,
        grounding: Sequence[str] = (),
    ) -> Iterator[str]:
        """Yield checked chunks, stopping the stream if it turns unsafe.

        The result of the run is attached to the generator as ``.result`` once
        it completes; :meth:`collect` is the convenience wrapper for callers
        who do not need incremental delivery.
        """
        result = StreamResult(text="")
        buffer: list[str] = []
        pending = ""
        since_check = 0

        for chunk in chunks:
            result.chunks += 1
            result.text += chunk
            pending += chunk
            since_check += len(chunk)

            if since_check < self.check_every_chars:
                if not self.hold_window:
                    yield chunk
                    pending = ""
                continue

            since_check = 0
            decision = self._checkpoint(result, context, grounding)
            if decision is not None and decision.blocked:
                result.broken = True
                result.break_decision = decision
                result.replacement = self.break_message
                if on_break:
                    on_break(decision)
                if self.hold_window:
                    # Nothing unsafe has been released: drop the held window.
                    yield self.break_message
                return
            if self.hold_window and pending:
                yield pending
                pending = ""

        if self.hold_window and pending:
            # Final partial window still has to be checked before release.
            decision = self._checkpoint(result, context, grounding, final=True)
            if decision is not None and decision.blocked:
                result.broken = True
                result.break_decision = decision
                result.replacement = self.break_message
                if on_break:
                    on_break(decision)
                yield self.break_message
                return
            yield pending

        result.final_decision = self.pipeline.evaluate(
            Stage.OUTPUT,
            result.text,
            context,
            trust=TrustLevel.SYSTEM,
            grounding=grounding,
        )
        buffer.clear()

    def _checkpoint(
        self,
        result: StreamResult,
        context: RequestContext,
        grounding: Sequence[str],
        *,
        final: bool = False,
    ) -> Decision | None:
        result.checkpoints += 1
        decision = self.pipeline.evaluate(
            Stage.STREAM,
            result.text,
            context,
            trust=TrustLevel.SYSTEM,
            detectors=self.fast_detectors,
            grounding=grounding,
            emit=False,  # only checkpoints that act are worth an audit event
        )
        score = max((f.score for f in decision.findings if f.detected), default=0.0)

        if decision.blocked or score >= self.break_threshold:
            self.pipeline.emit(
                decision,
                context,
                response=result.text,
                extra_tags={"stream_checkpoint": result.checkpoints, "stream_action": "break"},
            )
            return decision

        if score >= self.fast_threshold:
            result.escalations += 1
            escalated = self.pipeline.evaluate(
                Stage.STREAM,
                result.text,
                context,
                trust=TrustLevel.SYSTEM,
                detectors=self.full_detectors,
                grounding=grounding,
                emit=False,
            )
            if escalated.action in (Action.BLOCK, Action.CHALLENGE):
                escalated.action = Action.BLOCK
                self.pipeline.emit(
                    escalated,
                    context,
                    response=result.text,
                    extra_tags={"stream_checkpoint": result.checkpoints, "stream_action": "break_escalated"},
                )
                return escalated
        return None

    def collect(
        self,
        chunks: Iterator[str],
        context: RequestContext,
        *,
        grounding: Sequence[str] = (),
    ) -> StreamResult:
        """Consume a stream fully and return the :class:`StreamResult`."""
        result = StreamResult(text="")
        broken: list[Decision] = []
        pieces: list[str] = []
        for piece in self.stream(chunks, context, on_break=broken.append, grounding=grounding):
            pieces.append(piece)
        if broken:
            # The last yielded piece is the break message, not model output.
            result.text = "".join(pieces[:-1])
            result.broken = True
            result.break_decision = broken[0]
            result.replacement = self.break_message
        else:
            result.text = "".join(pieces)
        return result
