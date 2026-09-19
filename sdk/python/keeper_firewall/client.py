"""The developer-facing API.

Everything in the SDK is reachable through one object::

    from keeper_firewall import Keeper

    keeper = Keeper(application="support-bot")
    reply = keeper.chat("Summarise this ticket", provider=my_provider)

Design constraint for this file: the ten-minute quickstart in
``docs/sdk-integration.md`` has to be true. That means Keeper works with zero
configuration (no control plane, no policy file, no API key), enforces
something sensible out of the box, and wraps an existing model call without the
application changing its architecture.

The three integration shapes, in increasing order of involvement:

``keeper.wrap(fn)``
    Decorate an existing function that takes messages and returns text. The
    least invasive option and the one the quickstart uses.

``keeper.chat(...)``
    Let Keeper make the model call through a provider adapter. Convenient when
    starting fresh.

``keeper.check_input`` / ``check_output``
    Call the filters directly and keep full control of the model call. What you
    use when the application's call path is complicated.
"""

from __future__ import annotations

import contextlib
import functools
import threading
from typing import Any, Callable, Iterator, Mapping, Sequence

from .accesscontrol.auth import AuthProvider, build_provider
from .accesscontrol.ratelimit import Quota, RateLimiter
from .accesscontrol.rbac import Authorizer, from_policy
from .config import KeeperConfig
from .detectors import Detector
from .errors import AuthorizationError, BlockedError, RateLimitError
from .observability.events import EventBuilder, FanoutSink, JSONLinesSink, MemorySink, StreamSink
from .observability.metrics import Metrics
from .observability.redaction import Redactor
from .observability.tracing import Tracer
from .pipeline import Pipeline
from .policy.loader import PolicyProvider
from .policy.models import Policy
from .providers.base import CallableProvider, EchoProvider, Provider
from .runtime.guardrails import ToolGuard, default_tool_specs
from .runtime.memory import MemoryFirewall
from .runtime.stream import StreamGuard
from .transport.client import ControlPlaneClient
from .transport.shipper import TelemetryShipper
from .types import (
    Action,
    Decision,
    Document,
    GuardedResponse,
    GuardedResponse as _GuardedResponse,  # re-export convenience
    LLMResponse,
    Message,
    Principal,
    RequestContext,
    Stage,
    ToolCall,
    TrustLevel,
    now_ms,
)
from .version import __version__


class Keeper:
    """The AI firewall. One instance per application process."""

    def __init__(
        self,
        application: str | None = None,
        *,
        config: KeeperConfig | None = None,
        config_path: str | None = None,
        provider: Provider | Callable[..., Any] | None = None,
        extra_detectors: Sequence[Detector] = (),
        principal_resolver: Callable[..., Principal] | None = None,
        on_event: Callable[[Any], None] | None = None,
        **overrides: Any,
    ) -> None:
        # Note the two different things named "detectors": ``extra_detectors``
        # takes Detector *instances* to add to the registry, while a
        # ``detectors={...}`` keyword override configures the built-in ones.
        if application:
            overrides.setdefault("application", application)
        self.config = config or KeeperConfig.load(config_path, **overrides)

        # --- observability first: everything below it is observed ----------
        self.metrics = Metrics(self.config.metrics, application=self.config.application)
        self.metrics.gauge(
            "info", 1,
            application=self.config.application,
            sdk_version=__version__,
            environment=self.config.environment,
        )
        self.tracer = Tracer(service_name=f"keeper:{self.config.application}")
        self.redactor = Redactor(self.config.redaction)

        self.sink = FanoutSink()
        self.memory_sink = MemorySink()
        self.sink.add(self.memory_sink)
        if self.config.telemetry.local_log_path:
            self.sink.add(JSONLinesSink(self.config.telemetry.local_log_path))
        if self.config.telemetry.local_log_stdout:
            self.sink.add(StreamSink())

        self.client: ControlPlaneClient | None = (
            ControlPlaneClient(
                self.config.telemetry.endpoint,
                api_key=self.config.telemetry.api_key,
                timeout_ms=self.config.telemetry.timeout_ms,
            )
            if self.config.telemetry.endpoint
            else None
        )
        self.shipper = TelemetryShipper(
            self.config.telemetry,
            instance_id=self.config.instance_id,
            metrics=self.metrics,
            client=self.client,
        )

        # --- policy --------------------------------------------------------
        self.policy_provider = PolicyProvider(
            self.config.policy, client=self.client, on_change=self._on_policy_change
        )

        # --- access control ------------------------------------------------
        self.auth: AuthProvider | None = None
        if self.config.access_control.enabled:
            self.auth = build_provider(self.config.access_control, principal_resolver)
        self.authorizer = from_policy(
            self.policy_provider.policy.model_access, self.policy_provider.policy.tool_access
        )
        self.limiter = RateLimiter(
            default=Quota(
                rpm=self.config.access_control.default_rpm,
                burst=self.config.access_control.default_burst,
            ),
            distributed=self.config.access_control.distributed,
            lease_client=self._lease if self.config.access_control.distributed else None,
        )
        self.limiter.apply_policy(self.policy_provider.policy.rate_limits)

        # --- enforcement ---------------------------------------------------
        self.events = EventBuilder(
            self.redactor,
            instance_id=self.config.instance_id,
            policy_version=self.policy_provider.policy.ref,
        )
        self.pipeline = Pipeline(
            self.config,
            policy=self.policy_provider,
            metrics=self.metrics,
            events=self.events,
            sink=self.sink,
            shipper=self.shipper,
            extra_detectors=extra_detectors,
            on_event=on_event,
        )

        # --- runtime protection --------------------------------------------
        self.tools = ToolGuard(
            pipeline=self.pipeline,
            allowlist=tuple(self.config.runtime.tool_allowlist),
            denylist=tuple(self.config.runtime.tool_denylist),
            authorizer=self.authorizer,
        )
        self.tools.register_many(default_tool_specs())
        self.stream_guard = StreamGuard(
            pipeline=self.pipeline,
            check_every_chars=self.config.runtime.stream_check_every_chars,
            fast_threshold=self.config.runtime.stream_fast_threshold,
            break_threshold=self.config.runtime.stream_break_threshold,
        )
        self.memory = MemoryFirewall(pipeline=self.pipeline)

        # --- model backend --------------------------------------------------
        self.provider: Provider = self._coerce_provider(provider)

        self._registered_secrets: list[tuple[str, str]] = []
        self._lock = threading.Lock()
        self._started_ms = now_ms()

        if self.config.metrics.port:
            self.metrics.start_http_server()
        if self.client is not None:
            self._register_instance()

    # -- construction helpers ---------------------------------------------

    @staticmethod
    def _coerce_provider(provider: Provider | Callable[..., Any] | None) -> Provider:
        if provider is None:
            return EchoProvider()
        if callable(provider) and not hasattr(provider, "complete"):
            return CallableProvider(provider)
        return provider  # type: ignore[return-value]

    def _on_policy_change(self, policy: Policy) -> None:
        """Re-derive everything a policy bundle can influence."""
        self.events.policy_version = policy.ref
        self.limiter.apply_policy(policy.rate_limits)
        self.authorizer = from_policy(policy.model_access, policy.tool_access)
        self.tools.authorizer = self.authorizer
        self.metrics.gauge("policy_age_seconds", 0, policy_id=policy.id)

    def _register_instance(self) -> None:
        """Announce this instance to the fleet inventory. Best effort."""
        assert self.client is not None
        try:
            self.client.register_instance(
                {
                    "instance_id": self.config.instance_id,
                    "application": self.config.application,
                    "environment": self.config.environment,
                    "sdk_version": __version__,
                    "language": "python",
                    "policy_id": self.policy_provider.policy.id,
                    "policy_version": self.policy_provider.policy.version,
                    "detectors": list(self.pipeline.detector_names),
                    "monitor_only": self.config.monitor_only,
                }
            )
        except Exception:  # noqa: BLE001 - inventory is not on the critical path
            pass

    def _lease(self, scope: str, consumed: int) -> Mapping[str, Any]:
        assert self.client is not None
        response = self.client.check_quota(
            {"instance_id": self.config.instance_id, "scope": scope, "consumed": consumed}
        )
        return response.json() or {}

    # -- context -----------------------------------------------------------

    def context(
        self,
        *,
        principal: Principal | None = None,
        credential: str | None = None,
        user: str | None = None,
        roles: Sequence[str] = (),
        tenant: str | None = None,
        session: str | None = None,
        model: str | None = None,
        traceparent: str | None = None,
        tags: Mapping[str, Any] | None = None,
        **auth_context: Any,
    ) -> RequestContext:
        """Build the :class:`RequestContext` for one interaction.

        Identity resolution order: an explicit ``principal`` wins; otherwise a
        configured auth provider authenticates ``credential``; otherwise the
        ``user``/``roles`` shorthand is used unauthenticated.
        """
        if principal is None:
            if self.auth is not None and (credential or auth_context):
                principal = self.auth.authenticate(credential, **auth_context)
            elif user:
                principal = Principal(id=user, roles=tuple(roles), tenant=tenant, authenticated=False)
            else:
                principal = Principal.anonymous()

        trace_id, span_id = (None, None)
        if traceparent:
            from .observability.tracing import parse_traceparent

            trace_id, span_id = parse_traceparent(traceparent)
        if trace_id is None:
            trace_id, span_id = self.tracer.current_ids()

        return RequestContext(
            session_id=session,
            principal=principal,
            application=self.config.application,
            environment=self.config.environment,
            model=model,
            provider=getattr(self.provider, "name", None),
            trace_id=trace_id,
            span_id=span_id,
            tags=dict(tags or {}),
        )

    # -- access control ----------------------------------------------------

    def authorize(self, context: RequestContext, *, model: str | None = None, cost: float = 1.0) -> None:
        """Authentication, RBAC and rate limiting. Raises on refusal."""
        cfg = self.config.access_control
        if not cfg.enabled:
            return

        if cfg.require_authentication and not context.principal.authenticated:
            self.metrics.inc("access_denied_total", reason="unauthenticated")
            self._emit_access_denied(context, "unauthenticated principal")
            raise AuthorizationError("authentication required", principal=context.principal.id)

        target = model or context.model
        if target:
            allowed, reason = self.authorizer.check(context.principal, "model", target)
            if not allowed:
                self.metrics.inc("access_denied_total", reason="model_forbidden")
                self._emit_access_denied(context, f"model {target!r}: {reason}")
                raise AuthorizationError(
                    f"principal {context.principal.id!r} may not use model {target!r}: {reason}",
                    principal=context.principal.id,
                    resource=f"model:{target}",
                )

        if cfg.rate_limit_enabled:
            try:
                self.limiter.check(context.principal, model=target, cost=cost)
            except RateLimitError as exc:
                self.metrics.inc("access_denied_total", reason="rate_limited")
                self._emit_access_denied(context, str(exc))
                raise

    def _emit_access_denied(self, context: RequestContext, summary: str) -> None:
        from .types import Finding, Severity

        decision = Decision(
            action=Action.BLOCK,
            stage=Stage.ACCESS,
            correlation_id=context.correlation_id,
            findings=(
                Finding(
                    detector="access_control",
                    detected=True,
                    score=1.0,
                    severity=Severity.MEDIUM,
                    action=Action.BLOCK,
                    summary=summary,
                    category="access_control",
                ),
            ),
        )
        self.pipeline.emit(decision, context)

    # -- filtering ---------------------------------------------------------

    def check_input(
        self,
        text: str,
        context: RequestContext | None = None,
        *,
        trust: TrustLevel = TrustLevel.USER,
        history: Sequence[Message] = (),
        **kwargs: Any,
    ) -> Decision:
        """Run the input filters over a prompt."""
        context = context or self.context()
        return self.pipeline.evaluate(
            Stage.INPUT, text, context, trust=trust, history=history, **kwargs
        )

    def check_output(
        self,
        text: str,
        context: RequestContext | None = None,
        *,
        grounding: Sequence[str] = (),
        **kwargs: Any,
    ) -> Decision:
        """Run the output filters over a model response."""
        context = context or self.context()
        return self.pipeline.evaluate(
            Stage.OUTPUT, text, context, trust=TrustLevel.SYSTEM, grounding=grounding, **kwargs
        )

    def check_documents(
        self, documents: Sequence[Document], context: RequestContext | None = None
    ) -> tuple[list[Document], list[tuple[Document, Decision]]]:
        """Screen retrieved documents; returns ``(safe, rejected)``."""
        context = context or self.context()
        return self.tools.filter_documents(documents, context)

    def check_tool_call(
        self,
        name: str,
        arguments: Mapping[str, Any] | None = None,
        context: RequestContext | None = None,
        *,
        trust: TrustLevel = TrustLevel.USER,
        **kwargs: Any,
    ) -> Decision:
        """Mediate a tool call before it executes."""
        context = context or self.context()
        return self.tools.check_call(
            ToolCall(name=name, arguments=dict(arguments or {})), context, trust=trust, **kwargs
        )

    def check_tool_definitions(
        self,
        tools: Sequence[Mapping[str, Any]],
        context: RequestContext | None = None,
        *,
        server: str = "default",
        pin: bool | None = None,
    ) -> list[tuple[Mapping[str, Any], Decision]]:
        """Screen MCP / function-calling tool definitions before the model sees them.

        Accepts MCP ``{"name", "description", "inputSchema"}`` dicts, OpenAI
        ``{"type": "function", "function": {...}}`` dicts, or Anthropic
        ``{"name", "description", "input_schema"}`` dicts. Each definition is
        scanned for embedded directives (OWASP MCP03) and pinned: a later
        change to a pinned definition is reported as a rug pull. Pass
        ``pin=False`` to screen without pinning (for example when ``server``
        does not identify one stable tool provider).
        Returns ``(definition, decision)`` pairs; drop the blocked ones.
        """
        from .detectors.agentic import tool_text

        context = context or self.context()
        results: list[tuple[Mapping[str, Any], Decision]] = []
        for raw in tools:
            definition = raw.get("function", raw) if isinstance(raw, Mapping) else {}
            decision = self.pipeline.evaluate(
                Stage.TOOL_DEFINITION,
                tool_text(definition),
                context,
                trust=TrustLevel.EXTERNAL,
                metadata={"tool_definition": definition, "server": server, "tool": definition.get("name"), "pin": pin},
            )
            results.append((raw, decision))
        return results

    def canary(self) -> str:
        """A fresh canary token to embed in your system prompt.

        If the token ever appears in model output, the ``system_prompt_leakage``
        detector blocks the response (OWASP LLM07). Put it somewhere the model
        has no reason to repeat, e.g. ``"Internal reference: KPR-3f9a..."``.
        """
        from .detectors.leakage import new_canary

        token = new_canary()
        detector = self.pipeline.detector("system_prompt_leakage")
        if detector is not None and hasattr(detector, "add_canary"):
            detector.add_canary(token)
        return token

    def coverage(self) -> list[dict[str, Any]]:
        """OWASP LLM / Agentic / MCP coverage given the detectors enabled here."""
        from .taxonomy import coverage_report

        return [row.to_dict() for row in coverage_report(self.pipeline.detector_names)]

    # -- the main entry point ---------------------------------------------

    def chat(
        self,
        messages: str | Sequence[Message] | Sequence[Mapping[str, Any]],
        *,
        context: RequestContext | None = None,
        provider: Provider | None = None,
        model: str | None = None,
        grounding: Sequence[str] = (),
        raise_on_block: bool = False,
        **provider_kwargs: Any,
    ) -> GuardedResponse:
        """Filter, call the model, filter the response, audit all of it."""
        provider = provider or self.provider
        turns = _normalise_messages(messages)
        context = context or self.context(model=model)
        context.model = model or context.model
        context.provider = getattr(provider, "name", None)
        context.messages = list(turns)
        start = now_ms()

        with self.tracer.span("keeper.chat", application=self.config.application) as span:
            context.trace_id = context.trace_id or span.trace_id
            context.span_id = span.span_id

            self.authorize(context, model=model)

            prompt = turns[-1].content if turns else ""
            history = turns[:-1]
            input_decision = self.pipeline.evaluate(
                Stage.INPUT, prompt, context, trust=turns[-1].trust if turns else TrustLevel.USER,
                history=history,
                metadata={"max_tokens": provider_kwargs.get("max_tokens")},
            )
            span.set("keeper.input_action", input_decision.action.value)

            if input_decision.blocked:
                span.event("keeper.blocked", stage="input")
                response = GuardedResponse(
                    text=self._block_message(input_decision),
                    correlation_id=context.correlation_id,
                    model=model,
                    input_decision=input_decision,
                    blocked=True,
                    latency_ms=now_ms() - start,
                )
                if raise_on_block:
                    raise BlockedError(input_decision)
                return response

            if input_decision.action is Action.REDACT and input_decision.payload is not None:
                turns = list(turns[:-1]) + [
                    Message(role=turns[-1].role, content=input_decision.payload, trust=turns[-1].trust)
                ]

            model_start = now_ms()
            llm: LLMResponse = provider.complete(turns, model=model, **provider_kwargs)
            model_ms = now_ms() - model_start
            self.metrics.observe("model_latency_ms", model_ms, provider=getattr(provider, "name", "unknown"))
            span.set("keeper.model_latency_ms", model_ms)

            output_decision = self.pipeline.evaluate(
                Stage.OUTPUT,
                llm.text,
                context,
                trust=TrustLevel.SYSTEM,
                grounding=grounding,
                latency_ms=model_ms,
                tokens_in=llm.tokens_in,
                tokens_out=llm.tokens_out,
            )
            span.set("keeper.output_action", output_decision.action.value)

            text = llm.text
            if output_decision.blocked:
                text = self._block_message(output_decision)
                if raise_on_block:
                    raise BlockedError(output_decision)
            elif output_decision.action is Action.REDACT and output_decision.payload is not None:
                text = output_decision.payload

            return GuardedResponse(
                text=text,
                correlation_id=context.correlation_id,
                model=llm.model,
                input_decision=input_decision,
                output_decision=output_decision,
                blocked=output_decision.blocked,
                raw=llm.raw,
                tokens_in=llm.tokens_in,
                tokens_out=llm.tokens_out,
                latency_ms=now_ms() - start,
            )

    def stream(
        self,
        messages: str | Sequence[Message] | Sequence[Mapping[str, Any]],
        *,
        context: RequestContext | None = None,
        provider: Provider | None = None,
        model: str | None = None,
        grounding: Sequence[str] = (),
        **provider_kwargs: Any,
    ) -> Iterator[str]:
        """Stream a response with mid-generation enforcement."""
        provider = provider or self.provider
        turns = _normalise_messages(messages)
        context = context or self.context(model=model)
        context.model = model or context.model
        context.messages = list(turns)

        self.authorize(context, model=model)
        prompt = turns[-1].content if turns else ""
        input_decision = self.pipeline.evaluate(
            Stage.INPUT, prompt, context, history=turns[:-1]
        )
        if input_decision.blocked:
            yield self._block_message(input_decision)
            return

        chunks = provider.stream(turns, model=model, **provider_kwargs)
        yield from self.stream_guard.stream(chunks, context, grounding=grounding)

    # -- wrapping existing code -------------------------------------------

    def wrap(
        self,
        fn: Callable[..., Any] | None = None,
        *,
        model: str | None = None,
        context_getter: Callable[[], RequestContext] | None = None,
    ) -> Callable[..., Any]:
        """Decorate an existing LLM call so it runs behind the firewall.

        The wrapped function must take messages as its first positional
        argument and return a string or an
        :class:`~keeper_firewall.types.LLMResponse`::

            @keeper.wrap
            def ask(messages, **kwargs):
                return openai_client.chat.completions.create(...)
        """

        def decorate(inner: Callable[..., Any]) -> Callable[..., Any]:
            provider = CallableProvider(lambda msgs, **kw: inner(msgs, **kw), model=model)

            @functools.wraps(inner)
            def wrapper(messages: Any, *args: Any, **kwargs: Any) -> GuardedResponse:
                context = (context_getter or self.context)()
                return self.chat(
                    messages, context=context, provider=provider, model=model, **kwargs
                )

            wrapper.keeper = self  # type: ignore[attr-defined]
            return wrapper

        return decorate(fn) if fn is not None else decorate

    @contextlib.contextmanager
    def request(self, **kwargs: Any) -> Iterator[RequestContext]:
        """Scope a whole interaction — model call, tools, memory — to one id."""
        context = self.context(**kwargs)
        try:
            yield context
        finally:
            self.tools.kill_switch.reset(context.correlation_id)

    # -- registration ------------------------------------------------------

    def register_secret(self, value: str, *, label: str = "registered_secret") -> None:
        """Tell the firewall a value is confidential so it can catch leaks.

        Register the system prompt, tenant identifiers, and any config secret
        the model could plausibly echo. Only salted hashes are retained.
        """
        detector = self.pipeline.detector("secret_leakage")
        if detector is not None and hasattr(detector, "register"):
            detector.register(value, label=label)
        with self._lock:
            self._registered_secrets.append((label, self.redactor.digest(value)))

    def register_tool(self, *args: Any, **kwargs: Any) -> None:
        """Declare a tool and its risk tier. See :class:`ToolSpec`."""
        from .runtime.guardrails import ToolSpec

        self.tools.register(args[0] if args and isinstance(args[0], ToolSpec) else ToolSpec(*args, **kwargs))

    def set_policy(self, policy: Policy | Mapping[str, Any]) -> None:
        """Replace the active policy locally (tests, or a local hot reload)."""
        if not isinstance(policy, Policy):
            policy = Policy.from_dict(policy, source="set_policy")
        self.policy_provider.set_policy(policy)
        self._on_policy_change(policy)

    # -- observability surface --------------------------------------------

    def metrics_text(self) -> str:
        """Prometheus exposition text, for the host app's ``/metrics``."""
        return self.metrics.render()

    def health(self) -> dict[str, Any]:
        """Everything an ops team needs to monitor the firewall itself."""
        return {
            "status": "degraded" if self.policy_provider.degraded else "ok",
            "sdk_version": __version__,
            "application": self.config.application,
            "environment": self.config.environment,
            "instance_id": self.config.instance_id,
            "uptime_ms": now_ms() - self._started_ms,
            "monitor_only": self.config.monitor_only,
            "detectors": list(self.pipeline.detector_names),
            "policy": self.policy_provider.health(),
            "telemetry": self.shipper.health(),
            "rate_limiter": self.limiter.state(),
            "memory": self.memory.stats(),
            "kill_switches_active": len(self.tools.kill_switch.active()),
            "redaction": {
                "mode": self.config.redaction.mode,
                "ephemeral_salt": self.redactor.uses_ephemeral_salt,
            },
        }

    def recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        """The last N audit events from the in-memory sink."""
        return [e.to_dict() for e in self.memory_sink.events[-limit:]]

    def flush(self, timeout_s: float = 5.0) -> bool:
        """Block until queued telemetry is delivered. Call before exit."""
        self.sink.flush()
        return self.shipper.flush(timeout_s)

    def close(self) -> None:
        self.flush()
        self.shipper.close()
        self.policy_provider.close()
        self.pipeline.close()
        self.sink.close()

    def __enter__(self) -> "Keeper":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- internals ---------------------------------------------------------

    def _block_message(self, decision: Decision) -> str:
        """The user-visible text when something is blocked.

        Prefers the policy rule's own message, so a compliance team controls
        the wording. Falls back to a generic line plus the correlation id —
        deliberately not the detector's evidence, which would tell an attacker
        exactly which signal fired.
        """
        for trace in decision.policy_traces:
            if trace.matched and trace.action is Action.BLOCK and trace.note:
                return trace.note
        return (
            "This request was blocked by the AI firewall. "
            f"Reference: {decision.correlation_id}"
        )


def _normalise_messages(
    messages: str | Sequence[Message] | Sequence[Mapping[str, Any]],
) -> list[Message]:
    if isinstance(messages, str):
        return [Message(role="user", content=messages)]
    out: list[Message] = []
    for item in messages:
        if isinstance(item, Message):
            out.append(item)
        elif isinstance(item, Mapping):
            trust = item.get("trust", TrustLevel.USER)
            out.append(
                Message(
                    role=str(item.get("role", "user")),
                    content=str(item.get("content", "")),
                    name=item.get("name"),
                    trust=TrustLevel(trust) if not isinstance(trust, TrustLevel) else trust,
                )
            )
        else:
            raise TypeError(f"cannot read {type(item).__name__} as a message")
    return out
