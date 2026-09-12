"""Policy documents and the condition language.

**Why not Rego by default.** OPA/Rego is the obvious candidate and we support
it (:class:`keeper_firewall.policy.engine.OPAEngine`), but it is not the
default, for three reasons specific to this deployment shape:

1. The policy runs *inside the customer's application process*. Embedding OPA
   means either a cgo/WASM runtime in the host process or a network hop per
   evaluation — a hard cost to justify against a sub-millisecond budget.
2. The people who author these policies are security and compliance engineers.
   A declarative YAML matcher with named predicates is reviewable in a pull
   request by someone who does not write Rego, and that review is most of the
   value of having policy-as-code at all.
3. The decision surface is genuinely small: match on stage, detector results,
   principal, and content classification; emit one action. Rego's power is
   aimed at a much larger problem than this.

Organisations already running OPA can set ``policy.engine: opa`` and keep their
existing authoring, review, and distribution toolchain. The engine interface is
the same either way; nothing else in the SDK knows which is in use.

The condition language is deliberately total: no loops, no user-supplied code,
no regex backtracking over attacker-controlled input beyond what the detectors
already do. A policy cannot hang the request path.
"""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Sequence

from ..errors import PolicyError
from ..types import Action, Severity, Stage

# ---------------------------------------------------------------------------
# Condition language
# ---------------------------------------------------------------------------

Predicate = Callable[[Mapping[str, Any]], bool]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set, frozenset)):
        return list(value)
    return [value]


def _get(ctx: Mapping[str, Any], path: str) -> Any:
    cursor: Any = ctx
    for part in path.split("."):
        if isinstance(cursor, Mapping):
            cursor = cursor.get(part)
        else:
            return None
    return cursor


def _match_any(actual: Any, expected: Sequence[Any]) -> bool:
    """Glob-aware membership test, used by every string-valued predicate."""
    values = _as_list(actual)
    for want in expected:
        want_s = str(want)
        for have in values:
            have_s = str(have)
            if want_s == have_s or fnmatch.fnmatchcase(have_s, want_s):
                return True
    return False


#: Leaf predicates available in a ``when`` clause. Keeping this an explicit,
#: closed table is what makes a policy document safe to accept from the control
#: plane: an unknown key is a load-time error, never a silently-true condition.
LEAF_BUILDERS: dict[str, Callable[[Any], Predicate]] = {
    "stage": lambda v: lambda c: _match_any(c.get("stage"), _as_list(v)),
    "environment": lambda v: lambda c: _match_any(c.get("environment"), _as_list(v)),
    "application": lambda v: lambda c: _match_any(c.get("application"), _as_list(v)),
    "model": lambda v: lambda c: _match_any(c.get("model"), _as_list(v)),
    "provider": lambda v: lambda c: _match_any(c.get("provider"), _as_list(v)),
    "tenant": lambda v: lambda c: _match_any(c.get("tenant"), _as_list(v)),
    "principal": lambda v: lambda c: _match_any(c.get("principal_id"), _as_list(v)),
    "role": lambda v: lambda c: _match_any(c.get("roles"), _as_list(v)),
    "not_role": lambda v: lambda c: not _match_any(c.get("roles"), _as_list(v)),
    "authenticated": lambda v: lambda c: bool(c.get("authenticated")) is bool(v),
    "trust": lambda v: lambda c: _match_any(c.get("trust"), _as_list(v)),
    "tool": lambda v: lambda c: _match_any(c.get("tool"), _as_list(v)),
    "detector_fired": lambda v: lambda c: _match_any(c.get("detectors_fired"), _as_list(v)),
    "detector_not_fired": lambda v: lambda c: not _match_any(c.get("detectors_fired"), _as_list(v)),
    "category": lambda v: lambda c: _match_any(c.get("categories"), _as_list(v)),
    "label": lambda v: lambda c: _match_any(c.get("labels"), _as_list(v)),
    "severity_at_least": lambda v: lambda c: _severity_rank(c.get("severity")) >= _severity_rank(v),
    "score_at_least": lambda v: lambda c: float(c.get("max_score") or 0.0) >= float(v),
    "tag": lambda v: _tag_predicate(v),
    "content_matches": lambda v: _regex_predicate(v),
    "always": lambda v: (lambda c: bool(v)),
}


def _severity_rank(value: Any) -> int:
    if value is None:
        return -1
    try:
        return Severity(str(value)).rank()
    except ValueError as exc:
        raise PolicyError(f"unknown severity {value!r}") from exc


def _tag_predicate(spec: Any) -> Predicate:
    if not isinstance(spec, Mapping):
        raise PolicyError("'tag' expects a mapping of tag name to expected value(s)")
    wanted = {str(k): _as_list(v) for k, v in spec.items()}

    def check(ctx: Mapping[str, Any]) -> bool:
        tags = ctx.get("tags") or {}
        return all(_match_any(tags.get(name), values) for name, values in wanted.items())

    return check


def _regex_predicate(spec: Any) -> Predicate:
    patterns = [re.compile(p, re.IGNORECASE) for p in _as_list(spec)]

    def check(ctx: Mapping[str, Any]) -> bool:
        payload = ctx.get("payload") or ""
        return any(p.search(payload) for p in patterns)

    return check


def compile_condition(spec: Any) -> Predicate:
    """Compile a ``when`` clause into a callable predicate.

    Accepted shapes::

        when: {all: [ {...}, {...} ]}
        when: {any: [ {...}, {...} ]}
        when: {not: {...}}
        when: {stage: input, detector_fired: [secrets, pii]}   # implicit all

    A mapping with several leaf keys is an implicit ``all``.
    """
    if spec is None:
        return lambda ctx: True
    if isinstance(spec, bool):
        return lambda ctx, v=spec: v
    if isinstance(spec, Sequence) and not isinstance(spec, (str, bytes)):
        parts = [compile_condition(s) for s in spec]
        return lambda ctx: all(p(ctx) for p in parts)
    if not isinstance(spec, Mapping):
        raise PolicyError(f"condition must be a mapping or list, got {type(spec).__name__}")

    predicates: list[Predicate] = []
    for key, value in spec.items():
        if key == "all":
            parts = [compile_condition(s) for s in _as_list(value)]
            predicates.append(lambda ctx, ps=parts: all(p(ctx) for p in ps))
        elif key == "any":
            parts = [compile_condition(s) for s in _as_list(value)]
            predicates.append(lambda ctx, ps=parts: any(p(ctx) for p in ps))
        elif key in ("not", "none"):
            part = compile_condition(value)
            predicates.append(lambda ctx, p=part: not p(ctx))
        elif key in LEAF_BUILDERS:
            predicates.append(LEAF_BUILDERS[key](value))
        else:
            raise PolicyError(
                f"unknown condition {key!r}; supported: "
                f"{', '.join(sorted(list(LEAF_BUILDERS) + ['all', 'any', 'not']))}"
            )
    if len(predicates) == 1:
        return predicates[0]
    return lambda ctx: all(p(ctx) for p in predicates)


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class Rule:
    """One policy rule: a condition, an action, and an explanation."""

    id: str
    action: Action
    when: Any = None
    description: str = ""
    severity: Severity | None = None
    stop: bool = True          # stop evaluating further rules once matched
    message: str = ""          # shown to the end user when this rule blocks
    tags: Mapping[str, Any] = field(default_factory=dict)
    _predicate: Predicate | None = field(default=None, repr=False, compare=False)

    def compile(self) -> "Rule":
        self._predicate = compile_condition(self.when)
        return self

    def matches(self, ctx: Mapping[str, Any]) -> bool:
        if self._predicate is None:
            self.compile()
        assert self._predicate is not None
        return self._predicate(ctx)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Rule":
        try:
            rule_id = str(data["id"])
            action = Action(str(data["action"]))
        except KeyError as exc:
            raise PolicyError(f"rule is missing required key {exc.args[0]!r}") from exc
        except ValueError as exc:
            raise PolicyError(f"rule {data.get('id')!r}: {exc}") from exc
        severity = data.get("severity")
        return cls(
            id=rule_id,
            action=action,
            when=data.get("when"),
            description=str(data.get("description", "")),
            severity=Severity(str(severity)) if severity else None,
            stop=bool(data.get("stop", True)),
            message=str(data.get("message", "")),
            tags=dict(data.get("tags") or {}),
        ).compile()


@dataclass(slots=True)
class Policy:
    """A versioned bundle of rules plus detector overrides."""

    id: str = "default"
    version: str = "0"
    description: str = ""
    rules: tuple[Rule, ...] = ()
    detector_overrides: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    default_action: Action = Action.ALLOW
    #: Rate limits expressed in policy rather than local config, so the control
    #: plane can tighten a tenant's quota fleet-wide without a redeploy.
    rate_limits: Mapping[str, Mapping[str, Any]] = field(default_factory=dict)
    #: Model/tool access lists keyed by role.
    model_access: Mapping[str, Sequence[str]] = field(default_factory=dict)
    tool_access: Mapping[str, Sequence[str]] = field(default_factory=dict)
    metadata: Mapping[str, Any] = field(default_factory=dict)
    etag: str | None = None
    loaded_at_ms: int = 0
    source: str = "builtin"

    @property
    def ref(self) -> str:
        return f"{self.id}@{self.version}"

    @classmethod
    def from_dict(cls, data: Mapping[str, Any], *, source: str = "unknown") -> "Policy":
        if not isinstance(data, Mapping):
            raise PolicyError("policy document must be a mapping")
        unknown = set(data) - {
            "id", "version", "description", "rules", "detectors", "defaults",
            "rate_limits", "model_access", "tool_access", "metadata",
        }
        if unknown:
            raise PolicyError(f"unknown policy keys: {', '.join(sorted(unknown))}")

        defaults = data.get("defaults") or {}
        rules = tuple(Rule.from_dict(r) for r in (data.get("rules") or []))
        seen: set[str] = set()
        for rule in rules:
            if rule.id in seen:
                raise PolicyError(f"duplicate rule id {rule.id!r}")
            seen.add(rule.id)

        return cls(
            id=str(data.get("id", "default")),
            version=str(data.get("version", "0")),
            description=str(data.get("description", "")),
            rules=rules,
            detector_overrides=dict(data.get("detectors") or {}),
            default_action=Action(str(defaults.get("action", "allow"))),
            rate_limits=dict(data.get("rate_limits") or {}),
            model_access=dict(data.get("model_access") or {}),
            tool_access=dict(data.get("tool_access") or {}),
            metadata=dict(data.get("metadata") or {}),
            source=source,
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "version": self.version,
            "description": self.description,
            "defaults": {"action": self.default_action.value},
            "detectors": dict(self.detector_overrides),
            "rate_limits": dict(self.rate_limits),
            "model_access": {k: list(v) for k, v in self.model_access.items()},
            "tool_access": {k: list(v) for k, v in self.tool_access.items()},
            "metadata": dict(self.metadata),
            "rules": [
                {
                    "id": r.id,
                    "action": r.action.value,
                    "when": r.when,
                    "description": r.description,
                    "severity": r.severity.value if r.severity else None,
                    "stop": r.stop,
                    "message": r.message,
                    "tags": dict(r.tags),
                }
                for r in self.rules
            ],
        }

    def stages(self) -> set[Stage]:
        """Stages any rule in this policy can apply to (for diagnostics)."""
        out: set[Stage] = set()
        for rule in self.rules:
            spec = rule.when if isinstance(rule.when, Mapping) else {}
            for value in _as_list(spec.get("stage")):
                try:
                    out.add(Stage(str(value)))
                except ValueError:
                    continue
        return out or set(Stage)


#: The policy enforced when the control plane has never been reachable and no
#: local policy is configured. It is intentionally minimal: block credential
#: egress and confirmed injection, redact PII, allow everything else. A
#: firewall that fails into "block everything" on a cold start is a firewall
#: nobody deploys.
SAFE_DEFAULT_POLICY: dict[str, Any] = {
    "id": "keeper.safe-default",
    "version": "1.0.0",
    "description": "Built-in fallback policy used when no other policy is available.",
    "defaults": {"action": "allow"},
    "rules": [
        {
            "id": "block-credential-egress",
            "description": "Never let live credentials reach a model provider.",
            "when": {"detector_fired": ["secrets", "secret_leakage"]},
            "action": "block",
            "severity": "critical",
            "message": "This request contains credential material and was blocked.",
        },
        {
            "id": "block-injection",
            "description": "Block confirmed prompt injection at any boundary.",
            "when": {"detector_fired": "prompt_injection", "severity_at_least": "high"},
            "action": "block",
            "severity": "high",
            "message": "This request was identified as a prompt injection attempt.",
        },
        {
            "id": "block-unsafe-flow",
            "description": "Block low-authority content driving privileged tools.",
            "when": {"detector_fired": "token_flow", "severity_at_least": "high"},
            "action": "block",
            "severity": "critical",
            "message": "This action was not authorised by a sufficiently trusted source.",
        },
        {
            "id": "redact-pii",
            "description": "Strip personal data rather than failing the request.",
            "when": {"detector_fired": "pii"},
            "action": "redact",
            "severity": "medium",
            "stop": False,
        },
        {
            "id": "flag-authority-claims",
            "description": "Unverified authority claims are recorded for review.",
            "when": {"detector_fired": "authority_claim"},
            "action": "flag",
            "severity": "low",
            "stop": False,
        },
    ],
}
