# Low-level design

Component-by-component detail: the interfaces between modules, the plugin
contracts, the data models, and the API surface. `architecture.md` covers *why*;
this covers *what exactly*.

---

## 1. Core type system

Everything in the SDK is expressed in terms of a small set of types. They are
dependency-free dataclasses in Python and plain interfaces in TypeScript,
because the SDK is installed into third-party applications and every transitive
dependency we add becomes theirs too.

### The four ladders

Three of these are ordered enumerations, and the ordering *is* the security
logic.

```
Action        allow(0) < flag(1) < redact(2) < challenge(3) < block(4)
Severity      info(0) < low(1) < medium(2) < high(3) < critical(4)
TrustLevel    external(0) < retrieved(1) < tool(2) < user(3) < user_confirmed(4) < system(5)
RiskTier      low → requires retrieved(1)   medium → requires user(3)
              high → requires user_confirmed(4)   critical → requires user_confirmed(4)
```

`Action` ordering drives escalation combination. `TrustLevel` and `RiskTier`
together define the authority gap that `token_flow` and `MemoryFirewall`
enforce. The invariant that ties it together: **no transformation may raise a
value's position on the trust ladder.**

### Finding

What one detector concluded about one payload.

```python
@dataclass(slots=True)
class Finding:
    detector: str
    detected: bool
    score: float                    # detector-local confidence, [0, 1]
    severity: Severity
    action: Action
    summary: str                    # human-readable, appears in the dashboard
    category: str                   # dashboard grouping, alert matching
    spans: tuple[Span, ...]         # offsets, drive redaction
    evidence: Mapping[str, Any]     # why — the reviewable part
    elapsed_ms: float
    error: str | None
```

`score` is deliberately **not** averaged across detectors. See `Decision.combine`.

### Decision

```python
@dataclass(slots=True)
class Decision:
    action: Action
    stage: Stage
    correlation_id: str
    findings: tuple[Finding, ...]
    policy_traces: tuple[PolicyTrace, ...]
    payload: str | None             # possibly redacted
    original_payload: str | None    # never shipped raw
    elapsed_ms: float
    fail_mode_engaged: str | None   # set when a fail path ran
```

```python
@classmethod
def combine(cls, stage, correlation_id, findings, policy_traces=(), payload=None):
    action = Action.ALLOW
    for f in findings:
        if f.detected and f.action.escalates_over(action):
            action = f.action
    for t in policy_traces:
        if t.matched and t.action.escalates_over(action):
            action = t.action
    ...
```

Five lines, and the most consequential five in the codebase. The Cognitive
Firewall paper's finding is that averaging independent safety verdicts lets a
quorum of "fine" out-vote one confident "this is an attack". Escalation costs a
higher false-positive rate, which is the correct direction to err and is why
`monitor_only` exists.

### RequestContext

One per interaction, spanning input filtering, the model call, every tool call,
and output filtering. Its `correlation_id` is the join key for the entire audit
trail.

### AuditEvent

The cross-language, cross-version contract. Field names are stable; additions
are backwards compatible, removals are not. Versioned by `schema_version`
(`keeper.audit.v1`). Full schema in [`observability.md`](observability.md#2-audit-events).

---

## 2. Detector contract

The smallest pluggable unit, and the extension point most people will use.

```python
class Detector:
    name: str                       # config key and audit-event identifier
    stages: tuple[Stage, ...]       # which boundaries it is eligible for
    category: str                   # dashboard grouping
    mutates: bool                   # may it rewrite the payload?

    def __init__(self, config: DetectorConfig) -> None: ...
    def detect(self, data: DetectorInput) -> Finding: ...
    def redact(self, payload: str, finding: Finding) -> tuple[str, tuple[str, ...]]: ...
```

### Rules a detector must obey

1. **Do not raise for "nothing found."** Return a clean `Finding`. Exceptions
   are reserved for genuine failure and trigger the configured fail mode.
2. **Be side-effect free.** Detectors may run twice (escalation) and in
   arbitrary order.
3. **Respect the latency budget.** The pipeline enforces it anyway, but a
   detector that routinely blows it will show up as unhealthy in Analytics.
4. **Put the reasoning in `evidence`.** A finding with no evidence is a black
   box, and a block nobody can review gets the control switched off.

### DetectorInput

Detectors get the payload plus enough context to reason about *where it came
from* — the same sentence is benign in a user message and a red flag inside a
retrieved document.

```python
@dataclass(slots=True)
class DetectorInput:
    payload: str
    stage: Stage
    context: RequestContext
    trust: TrustLevel
    history: Sequence[Message]
    documents: Sequence[Document]
    tool_call: ToolCall | None
    grounding: Sequence[str]
    metadata: Mapping[str, Any]
```

### Registration

```python
from keeper_firewall import Detector, register_detector

class CompanyPolicyDetector(Detector):
    name = "company_policy"
    stages = (Stage.INPUT, Stage.OUTPUT)
    category = "content_policy"

    def detect(self, data):
        if "project falcon" in data.payload.lower():
            return self.hit(score=1.0, summary="internal codename mentioned",
                            severity=Severity.MEDIUM, action=Action.REDACT)
        return self.clean()

register_detector("company_policy", lambda cfg: CompanyPolicyDetector(cfg))
keeper = Keeper(application="app", extra_detectors=[CompanyPolicyDetector(DetectorConfig())])
```

Re-registering an existing name **replaces** it. That is how an organisation
swaps the regex PII detector for a Presidio-backed one without forking — there
is no second-class plugin tier.

### The built-ins

| Name | Stages | Mutates | Default fail mode | Mechanism |
|---|---|---|---|---|
| `secrets` | input, output, tool_call, tool_result, memory_write | yes | **closed** | 17 vendor patterns + Shannon entropy on assignment-shaped text |
| `pii` | same | yes | **closed** | 9 entities, Luhn / SSN / IBAN mod-97 validators |
| `prompt_injection` | input, retrieval, tool_result, memory_write, stream | no | open | 20 weighted signals, 5 families, saturating combination, trust multiplier |
| `authority_claim` | input, retrieval, tool_result, memory_write | no | open | 10 claim patterns checked against the verified `Principal` |
| `trajectory` | input | no | open | refusal pressure + topic drift + decomposition |
| `banned_topics` | input, output, stream | no | open | term lists + regex rules, per-category severity |
| `secret_leakage` | output, stream, tool_call | yes | **closed** | salted-digest matching of registered values + vendor patterns |
| `groundedness` | output | no | open (off by default) | sentence-level lexical overlap against grounding |
| `token_flow` | tool_call, tool_result, memory_write, retrieval | no | **closed** | source→sink authority gap + dangerous-argument patterns |
| `llm_classifier` | most (off by default) | no | open | escalation target; `guard` or `judge` mode |

---

## 3. Pipeline

```python
def evaluate(
    self, stage, payload, context, *,
    trust=TrustLevel.USER, history=(), documents=(), tool_call=None,
    grounding=(), detectors=None, metadata=None, emit=True,
    latency_ms=0.0, tokens_in=None, tokens_out=None,
) -> Decision
```

Sequence:

1. Resolve the detector list — explicit, else the stage default.
2. Run detectors sequentially, accumulating elapsed time against the budget.
   - Over budget → skip the rest, record a finding, engage the pipeline fail
     mode.
   - Exception → convert to a finding whose action depends on the detector's
     `fail_mode`.
   - `BLOCK` at score ≥ 0.99 → short-circuit. Remaining detectors cannot change
     the outcome and their cost is pure latency on an already-refused request.
3. Build facts, evaluate policy.
4. Combine by escalation.
5. Fail-closed with no findings → synthesise a `BLOCK` explaining that
   evaluation could not complete. Reporting a clean allow when we could not
   evaluate would be a lie.
6. `REDACT` → apply span replacement from every mutating detector.
7. `monitor_only` → downgrade `BLOCK`/`CHALLENGE` to `FLAG`, tag the findings.
8. Record metrics, emit exactly one audit event.

### Why sequential

The built-in detectors are regex and arithmetic over a few kilobytes — tens of
microseconds each. A thread pool would cost more in scheduling than it saves and
would make the latency profile harder to reason about. Python detectors whose
configured `timeout_ms` exceeds `THREADED_TIMEOUT_MS` (400ms — in practice only
`llm_classifier`) run on a bounded pool with a real timeout.

**Honest limitation:** Python cannot safely interrupt a running function. An
over-budget threaded detector is *abandoned* — we stop waiting, apply its fail
mode, and let the thread finish into the void. The pool is bounded, so a
persistently hanging detector degrades to "this detector no longer contributes"
rather than exhausting the process. Pretending otherwise would be worse.

---

## 4. Policy

### Document format

YAML or JSON, identical in both SDKs.

```yaml
id: acme.default
version: 1.4.0                    # immutable once published
description: What this policy is for, and who owns it.

defaults:
  action: allow

detectors:                        # tune the built-ins fleet-wide
  prompt_injection:
    threshold: 0.7
  pii:
    action: redact

rate_limits:
  "*":               {rpm: 600, burst: 60}
  "tenant:acme":     {rpm: 120, burst: 20}
  "role:service":    {rpm: 6000, burst: 300}

model_access:
  analyst: ["gpt-4o-mini", "claude-*"]
  admin:   ["*"]
tool_access:
  analyst: ["crm.lookup", "!shell.*"]

rules:
  - id: block-credential-egress
    description: Never let live credentials reach a model provider.
    when:
      detector_fired: [secrets, secret_leakage]
    action: block
    severity: critical
    message: This request contains credential material and was blocked.

  - id: redact-pii-except-support
    when:
      all:
        - detector_fired: pii
        - not: {application: support-bot}
    action: redact
    stop: false
```

### Condition language

Deliberately total: no loops, no user code, no unbounded backtracking. A policy
cannot hang the request path.

| Predicate | Matches against |
|---|---|
| `stage`, `environment`, `application`, `model`, `provider`, `tenant`, `principal`, `trust`, `tool` | glob-aware string match |
| `role`, `not_role` | any of the principal's roles |
| `detector_fired`, `detector_not_fired` | detectors that fired |
| `category`, `label` | finding categories / span labels |
| `severity_at_least`, `score_at_least` | ordered comparison |
| `authenticated` | boolean |
| `tag` | mapping of tag name → expected value(s) |
| `content_matches` | regex over the payload |
| `all`, `any`, `not` | nest arbitrarily; several leaf keys in one mapping are an implicit `all` |

**Unknown keys are a load-time error, never a silently-true condition.** That is
what makes it safe to accept a document from the control plane at all.

### Why not Rego by default

OPA is the obvious candidate and is supported (`policy.engine: opa`). It is not
the default for three reasons specific to this deployment shape:

1. The policy runs **inside the customer's application process**. Embedding OPA
   means a cgo/WASM runtime in the host process or a network hop per evaluation
   — hard to justify against a sub-millisecond budget.
2. The authors are security and compliance engineers. A declarative YAML matcher
   with named predicates is reviewable in a pull request by someone who does not
   write Rego, and that review is most of the value of policy-as-code.
3. The decision surface is genuinely small: match on stage, detector results and
   principal; emit one action. Rego's power targets a much larger problem.

Organisations already running OPA keep their authoring and review toolchain. The
engine interface is identical; nothing else in the SDK knows which is in use.

### Dry run

```python
report = dry_run_report(candidate_policy, historical_events)
# {"policy": "acme.default@2.0.0", "events_replayed": 5000, "changed": 14,
#  "transitions": {"allow->block": 12, "redact->block": 2}, "examples": [...]}
```

The reason `dry_run` is more than a flag: the control plane replays real
recorded traffic through a candidate bundle and shows exactly which requests
would change outcome, before anything is enforced.

---

## 5. Runtime protection

### ToolGuard

Four pre-execution controls:

```python
def check_call(self, call, context, *, trust=TrustLevel.USER, tainted_by=()) -> Decision
def check_result(self, call, result, context) -> Decision
def filter_documents(self, documents, context) -> tuple[list[Document], list[tuple[Document, Decision]]]
def guarded_call(self, call, execute, context, *, trust=...) -> Any
```

1. **Capability scope** — allowlist, denylist, per-tool roles, RBAC. Checked
   before the arguments are even looked at.
2. **Argument mediation** — the `token_flow` source→sink check.
3. **Result screening** — tool output is data; if it contains instructions
   addressed to the model, that is an attack, caught before it enters context.
4. **Kill switch** — a block halts the whole run, scoped by correlation id. An
   agent that just tried to exfiltrate a credential does not get nineteen more
   attempts.

`CHALLENGE` without a `confirm` callback is a **block**. "Ask the user" that
silently becomes "go ahead" when nobody is listening is not a control.

Sandboxing is deliberately a hook (`sandbox_runner`), not an implementation.
Real isolation is an OS-level concern; a Python-level fake would be worse than
none because it would be trusted.

### StreamGuard

See [`architecture.md` §6](architecture.md#6-streaming-enforcement) for the
cascade and the `hold_window` tradeoff.

### MemoryFirewall

```python
def write(self, content, *, trust, source, context=None, derived_from=(), user_confirmed=False)
def consolidate(self, content, parents, *, context=None)
def authorize_call(self, call, *, candidates=None, user_confirmed=False) -> MemoryGateResult
def lineage(self, memory_id) -> list[MemoryRecord]
```

Three invariants, each one line of code and each load-bearing:

```python
# 1. Trust comes from the boundary, never from the text.
record.trust = self._floor(caller_supplied_trust, derived_from)

# 2. Consolidation takes the minimum over parents. Non-amplification.
trust = min((r.trust for r in parents), key=lambda t: t.authority())

# 3. Confirmation is honoured only when the platform observed it.
user_confirmed = bool(user_confirmed) and trust.authority() >= TrustLevel.USER.authority()
```

And the binding step the PPMF paper insists on: `authorize_call` scores
relevance against the **call's arguments**, not the conversation, so an
unrelated high-authority memory in the same context cannot vouch for the action.

---

## 6. Access control

| Provider | Use |
|---|---|
| `CallableProvider` | **Recommended.** The app hands Keeper the principal it already has. Keeper never sees a credential. |
| `APIKeyProvider` | PBKDF2-hashed keys from a file, hot-reloaded on mtime change, compared with `compare_digest` against every record (a short-circuit would leak which prefix was right). |
| `OIDCProvider` | Takes a `verifier` callable so the crypto dependency is yours. **Refuses to run without one** — it does not fall back to decoding claims unverified, because an unverified JWT is an attacker-controlled dictionary. |
| `MTLSProvider` | Derives a principal from an already-verified certificate. Trusts that its input came from a real handshake, which is documented as an assumption. |

`Authorizer` evaluates `resource_type:pattern` permissions with glob matching,
role inheritance (cycle-safe), and deny-always-wins. Default effect is deny —
except that `authorizer_from_policy` **abstains** (`default_effect="allow"`)
when a policy defines no access lists at all, because an org that only wanted
content filtering should not find every call refused by an RBAC layer they never
configured.

ABAC is not implemented, deliberately. `Permission.condition` accepts the same
condition language as policy rules and is evaluated against principal
attributes, which covers the common attribute cases without inventing a second
policy engine.

`RateLimiter` is a multi-scope token bucket. Scopes are charged narrowest-first
and **refunded** if a later scope refuses, so a rejected request never consumes
quota it did not use. Bucket count is bounded with LRU eviction — an unbounded
dict keyed by principal id is a DoS vector against the limiter itself.

---

## 7. Control-plane API

### SDK-facing — `/v1/*`, ingest credential

| Endpoint | Purpose | Notes |
|---|---|---|
| `POST /v1/telemetry/events` | Ship a batch | Idempotent on `event_id`; alert evaluation happens in a background task so a slow webhook never becomes latency in a customer's chatbot |
| `GET /v1/policies/{bundle}` | Pull policy | `If-None-Match` → 304 with no body in the steady state |
| `POST /v1/fleet/register` | Announce an instance | Best effort, never blocks startup |
| `POST /v1/fleet/heartbeat` | Liveness + SDK health snapshot | |
| `POST /v1/quota/check` | Request a quota lease | See `architecture.md` §7 |

### Human-facing — `/api/*`, admin credential

| Endpoint | Answers |
|---|---|
| `GET /api/overview` | "What is happening right now?" — one round trip for the whole landing page |
| `GET /api/timeline` | Traffic by decision over time, from the counter table |
| `GET /api/events` | Structured + free-text search over the audit trail |
| `GET /api/events/{id}` | One decision in full |
| `GET /api/events/correlation/{id}` | **The investigation endpoint** — a whole interaction, stage by stage |
| `GET /api/analytics/detectors` | Is each detector earning its latency? |
| `GET /api/analytics/policy` | Which rules actually fire? |
| `GET /api/analytics/anomalies` | Cross-application patterns |
| `GET /api/fleet` | Who is running what, and is anything stale? |
| `GET/POST /api/policies`, `POST /api/policies/dry-run` | Author, version, replay, publish |
| `GET /api/alerts`, `POST /api/alerts/{id}/acknowledge` | Alert workflow |
| `GET/PUT/DELETE /api/alert-rules`, `POST /api/alerts/test` | Rule management and channel testing |

Full OpenAPI at `/openapi.json`; interactive at `/docs`.

### Ingest validation

Permissive about **unknown** fields, strict about known ones. A fleet is never
on one SDK version: a newer instance sends fields this control plane has not
heard of, and rejecting its batch would lose the audit trail of the most
up-to-date deployments.

---

## 8. Storage schema

| Table | Purpose | Design note |
|---|---|---|
| `audit_events` | One row per decision | Findings and traces as JSON — always read with their parent, never queried across events except via the two fields lifted out at ingest (`detectors_fired`, `categories`). Normalising them would triple the write cost of the hottest path for a query nobody runs. `search_text` is a pre-lowercased haystack so free-text search is one `LIKE`, not a scan across eight columns. |
| `event_counters` | Per-minute rollups by application and action | Keeps the timeline O(minutes) instead of O(events) |
| `instances` | Fleet inventory | Answers "is anything still running the version with the bad detector?" |
| `policies` | Versioned bundles, append-only | Publishing never mutates a row; republishing a version with different content is **refused**, so a decision under 1.4.0 is always explicable |
| `alert_rules`, `alerts` | Definitions and firings | Delivery result stored per channel |

Indexes exist for exactly the three queries the dashboard makes:
timeline-by-time, filter-by-application/action/severity, and lookup by
correlation id.

---

## 9. Configuration model

Layered, lowest precedence first: defaults → config file → `KEEPER_*`
environment → constructor arguments. Unknown keys are a startup error, not a
silent no-op.

```python
@dataclass
class KeeperConfig:
    application: str; environment: str; instance_id: str
    enabled: bool; monitor_only: bool
    detectors: dict[str, DetectorConfig]
    telemetry: TelemetryConfig; redaction: RedactionConfig; metrics: MetricsConfig
    policy: PolicyConfig; access_control: AccessControlConfig; runtime: RuntimeConfig
    input_budget_ms: int; output_budget_ms: int; fail_mode: str
```

Note the two different things named "detectors": `extra_detectors=` takes
`Detector` instances to add; `detectors={...}` configures the built-ins.

---

## 10. Cross-language parity

The two SDKs are ports of one design. What guarantees that stays true:

1. **The audit event schema is identical**, including field names and
   snake_case wire format. The control plane cannot tell which language
   produced an event.
2. **The ladders and the combination rule are identical.**
3. **The policy document format is identical** — the same published bundle
   loads in both.
4. **The test suites assert the same behaviours.** `sdk/python/tests/` and
   `sdk/typescript/test/` share their case list; a detector whose verdict
   diverges between languages fails a build.

Python is the reference implementation and carries two extras: the
`llm_classifier` detector and the `keeper` CLI. Everything in Section 2 of the
brief — input filtering, output filtering, access control, observability,
runtime protection, policy — is present in both.
