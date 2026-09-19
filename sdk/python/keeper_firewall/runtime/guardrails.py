"""Agent and tool execution guardrails.

Input filtering sees the user's prompt. It structurally cannot see what arrives
*mid-execution*: a tool result, a retrieved document, an agent's own plan. That
is the gap this module covers, and it is where the majority of real agent
compromises land (OWASP LLM01 indirect injection, LLM08 excessive agency).

Four controls, all pre-execution:

1. **Capability scope** — is this agent, acting for this principal, allowed to
   call this tool at all? Allowlist, denylist, and RBAC, checked before the
   arguments are even looked at.
2. **Argument mediation** — the token-flow check from
   :mod:`keeper_firewall.detectors.tokenflow`: does the *authority of the
   content* that produced these arguments match the risk of the sink?
3. **Result screening** — tool output and retrieved documents are data. If they
   contain instructions addressed to the model, they are treated as an attack
   before they reach the context window, not after.
4. **Kill switch** — a run that crosses a policy boundary can be halted whole,
   rather than having one call blocked while the agent keeps going and tries
   another route.

Sandboxing is deliberately *not* implemented as "we run your tool safely".
Real isolation is an OS-level concern (container, seccomp, namespace), and a
Python-level fake would be worse than none because it would be trusted. What
:class:`ToolGuard` provides is the decision point and the hook
(``sandbox_runner``) where a real sandbox plugs in; ``docs/deployment.md``
covers the container-level hardening that backs it.
"""

from __future__ import annotations

import fnmatch
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from ..errors import AuthorizationError, BlockedError
from ..types import (
    Action,
    Decision,
    Document,
    RequestContext,
    RiskTier,
    Stage,
    ToolCall,
    TrustLevel,
)


@dataclass(slots=True)
class ToolSpec:
    """What the firewall knows about a tool it may be asked to permit."""

    name: str
    risk: RiskTier = RiskTier.MEDIUM
    description: str = ""
    #: Roles permitted to invoke it. Empty means "governed by policy/RBAC only".
    roles: tuple[str, ...] = ()
    #: Whether results from this tool are trusted. A web fetch is not.
    result_trust: TrustLevel = TrustLevel.TOOL
    requires_confirmation: bool = False
    sandbox: bool = False


class KillSwitch:
    """Halts an in-progress agent run.

    Scoped per correlation id, so tripping it stops the offending run without
    touching concurrent ones. Once tripped, every subsequent guarded operation
    for that run raises, which is the point: an agent that just tried to
    exfiltrate a credential should not get to try nineteen more things.
    """

    def __init__(self) -> None:
        self._tripped: dict[str, str] = {}
        self._lock = threading.Lock()

    def trip(self, correlation_id: str, reason: str) -> None:
        with self._lock:
            self._tripped.setdefault(correlation_id, reason)

    def reason(self, correlation_id: str) -> str | None:
        with self._lock:
            return self._tripped.get(correlation_id)

    def is_tripped(self, correlation_id: str) -> bool:
        return self.reason(correlation_id) is not None

    def reset(self, correlation_id: str) -> None:
        with self._lock:
            self._tripped.pop(correlation_id, None)

    def active(self) -> dict[str, str]:
        with self._lock:
            return dict(self._tripped)


@dataclass
class ToolGuard:
    """Mediates tool calls, tool results, and retrieved documents."""

    pipeline: Any                       # keeper_firewall.pipeline.Pipeline
    tools: dict[str, ToolSpec] = field(default_factory=dict)
    allowlist: tuple[str, ...] = ()
    denylist: tuple[str, ...] = ()
    authorizer: Any = None              # accesscontrol.rbac.Authorizer
    kill_switch: KillSwitch = field(default_factory=KillSwitch)
    sandbox_runner: Callable[[ToolCall, Callable[..., Any]], Any] | None = None
    confirm: Callable[[ToolCall, Decision], bool] | None = None
    #: Tripping the kill switch on a block is the safe default for agent runs.
    trip_on_block: bool = True

    def register(self, spec: ToolSpec) -> None:
        self.tools[spec.name] = spec

    def register_many(self, specs: Sequence[ToolSpec]) -> None:
        for spec in specs:
            self.register(spec)

    # -- scope checks ------------------------------------------------------

    def in_scope(self, tool: str, context: RequestContext) -> tuple[bool, str]:
        """Allowlist/denylist and RBAC, before any content is inspected."""
        if self.kill_switch.is_tripped(context.correlation_id):
            return False, f"agent run halted: {self.kill_switch.reason(context.correlation_id)}"
        for pattern in self.denylist:
            if fnmatch.fnmatchcase(tool, pattern):
                return False, f"tool matches denylist entry {pattern!r}"
        if self.allowlist and not any(fnmatch.fnmatchcase(tool, p) for p in self.allowlist):
            return False, "tool is not on the allowlist"
        spec = self.tools.get(tool)
        if spec and spec.roles and not (set(spec.roles) & set(context.principal.roles)):
            return False, f"tool requires one of roles {list(spec.roles)}"
        if self.authorizer is not None:
            allowed, reason = self.authorizer.check(context.principal, "tool", tool)
            if not allowed:
                return False, reason
        return True, "in scope"

    # -- the three boundaries ---------------------------------------------

    def check_call(
        self,
        call: ToolCall,
        context: RequestContext,
        *,
        trust: TrustLevel = TrustLevel.USER,
        tainted_by: Sequence[str] = (),
    ) -> Decision:
        """Mediate a tool call before execution.

        ``trust`` is the authority of the content that *caused* this call. If
        the agent decided to call ``email.send`` because a retrieved document
        said so, pass ``TrustLevel.RETRIEVED`` — that is the whole signal.
        """
        spec = self.tools.get(call.name)
        if call.risk is None and spec is not None:
            call.risk = spec.risk
        if call.risk is None:
            # Unregistered tool: borrow token_flow's sink table so the risk
            # matrix still sees `payment.transfer` as a critical sink.
            flow = self.pipeline.detector("token_flow")
            if flow is not None and hasattr(flow, "resolve_risk"):
                call.risk = flow.resolve_risk(call.name)

        in_scope, reason = self.in_scope(call.name, context)
        if not in_scope:
            decision = _refused(
                context, Stage.TOOL_CALL, f"tool {call.name!r} refused: {reason}", call
            )
            self.pipeline.emit(
                decision,
                context,
                prompt=call.argument_text(),
                extra_tags={"tool": call.name, "trust": trust.value, "scope_reason": reason},
            )
            if self.trip_on_block:
                self.kill_switch.trip(context.correlation_id, reason)
            return decision

        decision = self.pipeline.evaluate(
            Stage.TOOL_CALL,
            call.argument_text(),
            context,
            trust=trust,
            tool_call=call,
            metadata={"tainted_by": tuple(tainted_by)},
        )

        if decision.action is Action.CHALLENGE:
            decision = self._resolve_challenge(call, decision, context)

        if decision.blocked and self.trip_on_block:
            reasons = decision.reasons
            self.kill_switch.trip(
                context.correlation_id,
                reasons[0].summary if reasons else f"blocked tool call {call.name!r}",
            )
        return decision

    def _resolve_challenge(self, call: ToolCall, decision: Decision, context: RequestContext) -> Decision:
        """A CHALLENGE needs a human. Without one wired up, it is a block.

        This is the deliberate conservative default: "ask the user" that
        silently becomes "go ahead" when nobody is listening is not a control.
        """
        if self.confirm is None:
            decision.action = Action.BLOCK
            return decision
        try:
            approved = self.confirm(call, decision)
        except Exception:
            approved = False
        decision.action = Action.ALLOW if approved else Action.BLOCK
        self.pipeline.emit(
            decision,
            context,
            prompt=call.argument_text(),
            extra_tags={"tool": call.name, "challenge_resolved": "approved" if approved else "denied"},
        )
        return decision

    def check_result(
        self, call: ToolCall, result: str, context: RequestContext
    ) -> Decision:
        """Screen a tool result before it enters the model's context."""
        spec = self.tools.get(call.name)
        trust = spec.result_trust if spec else TrustLevel.TOOL
        return self.pipeline.evaluate(
            Stage.TOOL_RESULT, result, context, trust=trust, tool_call=call
        )

    def check_documents(
        self, documents: Sequence[Document], context: RequestContext
    ) -> list[tuple[Document, Decision]]:
        """Screen retrieved documents at the retrieval boundary.

        Per-document rather than per-batch, because the useful outcome is
        usually "drop the poisoned passage and answer from the other four",
        not "fail the whole query".
        """
        out: list[tuple[Document, Decision]] = []
        for doc in documents:
            decision = self.pipeline.evaluate(
                Stage.RETRIEVAL,
                doc.content,
                context,
                trust=doc.trust,
                documents=[doc],
                metadata={"source": doc.source, "doc_id": doc.doc_id},
            )
            out.append((doc, decision))
        return out

    def filter_documents(
        self, documents: Sequence[Document], context: RequestContext
    ) -> tuple[list[Document], list[tuple[Document, Decision]]]:
        """Return ``(safe_documents, rejected)`` after screening."""
        safe: list[Document] = []
        rejected: list[tuple[Document, Decision]] = []
        for doc, decision in self.check_documents(documents, context):
            if decision.blocked:
                rejected.append((doc, decision))
            elif decision.action is Action.REDACT and decision.payload is not None:
                safe.append(
                    Document(
                        content=decision.payload,
                        source=doc.source,
                        doc_id=doc.doc_id,
                        trust=doc.trust,
                        metadata={**dict(doc.metadata), "redacted": True},
                    )
                )
            else:
                safe.append(doc)
        return safe, rejected

    # -- execution ---------------------------------------------------------

    def guarded_call(
        self,
        call: ToolCall,
        execute: Callable[..., Any],
        context: RequestContext,
        *,
        trust: TrustLevel = TrustLevel.USER,
        screen_result: bool = True,
    ) -> Any:
        """Check, execute, and screen the result. Raises on a block."""
        decision = self.check_call(call, context, trust=trust)
        if decision.blocked:
            raise BlockedError(decision)

        spec = self.tools.get(call.name)
        if spec and spec.sandbox and self.sandbox_runner is not None:
            result = self.sandbox_runner(call, execute)
        else:
            result = execute(**call.arguments)

        if screen_result and isinstance(result, str):
            result_decision = self.check_result(call, result, context)
            if result_decision.blocked:
                raise BlockedError(result_decision)
            if result_decision.action is Action.REDACT and result_decision.payload is not None:
                return result_decision.payload
        return result

    def wrap(
        self,
        name: str,
        fn: Callable[..., Any],
        *,
        risk: RiskTier = RiskTier.MEDIUM,
        context_getter: Callable[[], RequestContext] | None = None,
    ) -> Callable[..., Any]:
        """Decorate a tool function so every call goes through the guard."""
        self.register(ToolSpec(name=name, risk=risk, description=fn.__doc__ or ""))

        def wrapper(*args: Any, **kwargs: Any) -> Any:
            context = (context_getter or _require_context)()
            call = ToolCall(name=name, arguments=kwargs, risk=risk)
            return self.guarded_call(call, lambda **kw: fn(*args, **kw), context)

        wrapper.__name__ = getattr(fn, "__name__", name)
        wrapper.__doc__ = fn.__doc__
        return wrapper


def _require_context() -> RequestContext:
    raise AuthorizationError(
        "ToolGuard.wrap needs a context_getter: the guard must know which run a "
        "tool call belongs to in order to scope the kill switch and audit trail"
    )


def _refused(context: RequestContext, stage: Stage, summary: str, call: ToolCall | None) -> Decision:
    from ..types import Finding, Severity

    return Decision(
        action=Action.BLOCK,
        stage=stage,
        correlation_id=context.correlation_id,
        findings=(
            Finding(
                detector="tool_guard",
                detected=True,
                score=1.0,
                severity=Severity.HIGH,
                action=Action.BLOCK,
                summary=summary,
                category="excessive_agency",
                evidence={"tool": call.name if call else None},
            ),
        ),
    )


def default_tool_specs() -> list[ToolSpec]:
    """A starting risk classification for tool names people actually use.

    Not a substitute for classifying your own tools — a tool called ``update``
    could be anything — but it means an agent wired up in five minutes is not
    running with every tool at MEDIUM.
    """
    return [
        ToolSpec("shell.exec", RiskTier.CRITICAL, "Run a shell command", sandbox=True),
        ToolSpec("file.read", RiskTier.LOW, "Read a file"),
        ToolSpec("file.write", RiskTier.HIGH, "Write a file"),
        ToolSpec("file.delete", RiskTier.CRITICAL, "Delete a file", requires_confirmation=True),
        ToolSpec("http.get", RiskTier.LOW, "Fetch a URL", result_trust=TrustLevel.EXTERNAL),
        ToolSpec("http.post", RiskTier.HIGH, "Post to a URL", result_trust=TrustLevel.EXTERNAL),
        ToolSpec("web.search", RiskTier.LOW, "Search the web", result_trust=TrustLevel.EXTERNAL),
        ToolSpec("db.query", RiskTier.MEDIUM, "Read from a database"),
        ToolSpec("db.execute", RiskTier.CRITICAL, "Write to a database", requires_confirmation=True),
        ToolSpec("email.send", RiskTier.HIGH, "Send an email", requires_confirmation=True),
        ToolSpec("payment.charge", RiskTier.CRITICAL, "Charge a payment method", requires_confirmation=True),
        ToolSpec("memory.write", RiskTier.MEDIUM, "Persist an agent memory"),
    ]
