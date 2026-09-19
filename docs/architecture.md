# Architecture

Keeper is two cooperating systems.

The **data plane** is an SDK that runs inside the developer's own application
process. It sees every AI interaction, decides what to do with it, and emits a
structured record of that decision.

The **control plane** is a self-hosted service every SDK instance reports to.
It aggregates those records into an operational picture, distributes policy
back out, and forwards the audit trail to the organisation's existing SIEM.

The relationship between them is the single most important design decision in
the project, and it is stated first because everything else follows from it:
**the data plane's failure domain is strictly smaller than the control
plane's.** Applications keep working, and keep enforcing, when the control
plane is unreachable. Nothing on the request hot path waits for a network call
to the control plane, ever.

---

## 1. System overview

```
┌────────────────────────── Developer's application process ──────────────────────────┐
│                                                                                     │
│   app code ──► Keeper SDK ─────────────────────────────────────────► model provider │
│                  │                                                                  │
│                  │  ① access control    ② input filtering    ③ model call           │
│                  │  ④ output filtering  ⑤ runtime guards (tools, retrieval, memory) │
│                  │                                                                  │
│                  ├──► local audit sink (in-memory + optional JSONL)                 │
│                  ├──► Prometheus registry  ──► the app's own /metrics               │
│                  └──► bounded queue ──┐                                             │
└───────────────────────────────────────┼─────────────────────────────────────────────┘
                                        │ async batches (never blocking)
                                        │ ETag policy poll (60s, background thread)
                                        ▼
┌──────────────────────────────── Control plane ──────────────────────────────────────┐
│  /v1/*  ingest, policy, fleet, quota      ← ingest credential (many holders)         │
│  /api/* search, analytics, policy, alerts ← admin credential (people)                │
│                                                                                      │
│  ingest ──► audit store ──┬──► dashboard (React)                                     │
│                           ├──► alert engine ──► webhook / Slack / log                │
│                           ├──► anomaly analysis (cross-application)                  │
│                           └──► SIEM forwarder ──► Splunk / Elastic / Sentinel / OTLP │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. The trust-boundary tradeoff

This deserves to be confronted directly rather than buried, because it is the
weakness a security reviewer will find first.

**SDK-based enforcement runs inside the process it is protecting.** A malicious
or compromised application can, in principle, not call Keeper, monkey-patch it,
downgrade its config, or drop its telemetry. There is no way around this: code
in the same process as the control cannot be prevented from tampering with it.

**An inline proxy** — a separate service the application's traffic must
traverse — does not have that weakness. The application cannot opt out of a
network hop it does not control. It costs a round trip on every LLM call, a new
tier to deploy and scale, and a hard dependency the application did not have
before.

### The v1 decision, and why

Ship the SDK as the primary integration path.

1. **The threat model that matters most is not a hostile first-party
   application.** It is prompt injection, indirect injection through retrieved
   content, credential leakage, and over-permissioned agents — attacks against
   an application whose developers *want* the firewall to work. Against that
   threat model, in-process enforcement is equally effective and considerably
   faster.
2. **Adoption is a security property.** A control that is easy to add gets
   added. A proxy that requires a platform team, a deployment, and a traffic
   migration is a control that ships next quarter, or never.
3. **In-process enforcement can see things a proxy cannot.** Tool calls,
   retrieved documents, agent memory writes and streaming tokens are all
   *inside* the application. A proxy sees the model call and nothing else, so
   the entire runtime-protection module — the part that covers indirect
   injection and excessive agency, which is where real agent compromises happen
   — would be out of reach.

### What that decision does *not* cost us

The enforcement modules are deliberately free of any assumption that they run
in-process. `Pipeline.evaluate()` takes a payload, a stage and a context and
returns a decision; it does not know whether the caller is an application or a
proxy handler. A sidecar mode is a new transport in front of the same
`Pipeline`, not a rewrite.

**Where the SDK model is genuinely weaker, and what to do about it:**

| Weakness | Mitigation available today |
|---|---|
| App can skip the SDK entirely | Fleet inventory shows which applications report in; an application that never appears is visible. Gate model API keys on a proxy that only the Keeper-integrated path holds. |
| App can run an old SDK with a known gap | Fleet view surfaces SDK versions; the coverage-gap anomaly detector alerts on production instances missing detectors. |
| App can disable detectors locally | Policy can tune a detector but deliberately *cannot* enable one disabled locally — so the control plane never gains code execution inside someone's process. The tradeoff is that local disablement is visible, not preventable: the fleet view reports the detector set of every instance. |
| App can drop telemetry | Ingest gaps are observable. `keeper_cp_instances{status="stale"}` is an alertable metric. |

For a deployment where the application itself is untrusted, the answer is a
proxy — and it ships: **gateway mode** (`keeper gateway`, [`gateway.md`](gateway.md))
is an OpenAI/Anthropic-compatible proxy that runs the *same* `Pipeline`, policy
and risk matrix in front of the model. Hold the provider key in the gateway and
the application cannot reach the model any other way. The SDK remains the
primary path because it sees tool calls, retrieval and memory; the gateway sees
what crosses the wire — messages, tool definitions, tool results and the tool
calls the model proposes.

---

## 3. Request lifecycle

One `chat()` call, in order. Every numbered step that produces a decision emits
exactly one audit event.

```
  ① Access control          authenticate → authorize model → rate limit
        │                   (fails fast; emits an ACCESS event on refusal)
        ▼
  ② Input filtering         resource_abuse → secrets → pii → banned_topics
        │                   → prompt_injection (incl. base64/hex decode-and-rescan)
        │                   → authority_claim → trajectory
        │                   ── then, for every stage ──────────────────────────
        │                   a. name each finding in OWASP terms  (taxonomy.py)
        │                   b. place the stage on the 5x5 risk matrix (risk.py)
        │                   c. evaluate policy (rules can match threat / band)
        │                   d. add the matrix's verdict as a policy trace
        │                   e. combine everything by escalation → act
        │                   BLOCK: return here, the model is never called
        │                   REDACT: rewrite the payload, continue
        ▼
  ③ Model call              provider adapter; latency recorded separately from
        │                   firewall overhead so the two are never confused
        ▼
  ④ Output filtering        secret_leakage → system_prompt_leakage → unsafe_output
        │                   → pii → banned_topics → groundedness
        │                   (or, when streaming, incremental checkpoints with a
        │                    circuit breaker — see §6)
        ▼
     GuardedResponse        text, correlation id, both decisions, token counts
```

Every decision carries `threats` (e.g. `["LLM01", "ASI01"]`) and a `risk`
assessment (likelihood, impact, score 1–25, band, primary threat, per-threat
cells). Both are in the audit event, the Prometheus series, the SIEM export and
the dashboard. See [`owasp-coverage.md`](owasp-coverage.md) and
[`risk-matrix.md`](risk-matrix.md).

Around and between those steps, when the application is an agent:

- **Retrieval** — every retrieved document is screened at ingestion, before it
  enters the context window. Poisoned passages are dropped individually; the
  rest of the answer proceeds.
- **Tool definition** — MCP / function-calling tool metadata is screened for
  embedded directives and pinned by fingerprint; a later change is a rug pull
  (OWASP MCP03 / ASI04).
- **Tool call** — mediated before execution, with the authority of the content
  that *caused* the call as an input. `code_execution` screens the arguments
  themselves for execution payloads (ASI05 / MCP05).
- **Tool result** — screened as untrusted data before it re-enters context.
- **Memory write / read** — provenance recorded at write; authority checked
  against action risk at execution.

### Escalation, not averaging

Detectors return categorical verdicts, and the pipeline takes the **maximum**
severity rather than a weighted mean:

```python
action = ALLOW
for finding in findings:
    if finding.detected and finding.action.escalates_over(action):
        action = finding.action
```

This is the decision rule from the Cognitive Firewall paper, applied to
detectors rather than to its four LLM gates. The paper's argument is that
averaging independent safety signals dilutes a single confident danger signal
until it stops firing — nine detectors saying "fine" should not out-vote one
saying "this is a credential exfiltration attempt". The cost is a higher false
positive rate, which is the correct direction to err for a security control and
is why `monitor_only` exists as a rollout mode.

---

## 4. Data flow to the control plane

### Telemetry: push, asynchronous, bounded, lossy-by-design

```
decision ──► EventBuilder (redaction applied here) ──► local sinks (synchronous)
                                                  └──► bounded queue ──► background
                                                        thread ──► POST /v1/telemetry/events
```

Properties that matter:

- **`emit()` never blocks and never raises.** Worst case it drops an event and
  increments a counter.
- **The queue is bounded** (10,000 events by default). When it fills,
  low-severity events are evicted first; `BLOCK` and `CHALLENGE` events displace
  them. An audit trail that loses the block records under load is worse than
  useless.
- **Failure is bounded.** Batches retry with exponential backoff and jitter,
  then are dropped. Unbounded retry against a struggling control plane is how a
  degraded service becomes an outage.
- **Every drop is counted** with a reason label, so "we stopped receiving audit
  events" is itself an alertable condition rather than a silence.
- **Ingest is idempotent** on `event_id`, because a retried batch whose response
  was lost is a normal occurrence, not an error.

### Policy: pull, ETag-revalidated, cached

```
background thread, every 60s ──► GET /v1/policies/{bundle} + If-None-Match
                                   304 (steady state, no body)  → nothing to do
                                   200 → parse, compile, atomic engine swap
```

**Why pull rather than push.** Push over a persistent connection propagates
faster, but it inverts the dependency: every SDK instance would hold an open
connection to the control plane, and a control-plane restart would become a
fleet-wide event. Pull keeps the data plane's failure domain smaller, which is
the property that lets us promise the firewall keeps working when the dashboard
is down. ETags make the steady-state poll a 304 with no body, so a 60-second
interval across a large fleet costs almost nothing.

**The cost, stated plainly:** a policy change takes up to one refresh interval
to reach every instance. If you need sub-second propagation you want push, and
`PolicyProvider` is shaped so a pushing implementation slots in without touching
the pipeline.

---

## 5. Fail-safe behaviour

Every failure mode has a configured answer. None of them is "hope".

### Per-detector

`fail_mode` decides what happens when *a detector itself* fails — throws, times
out, cannot reach a model. Two rules of thumb:

| Detector class | Default | Why |
|---|---|---|
| Deterministic, local, cheap (`secrets`, `pii`, `secret_leakage`, `token_flow`) | **fail-closed** | If the secret scanner cannot run, we do not know whether a live credential is about to leave. A false block is cheap; a leaked production key is not. |
| Probabilistic or network-bound (`prompt_injection`, `trajectory`, `authority_claim`, `llm_classifier`) | **fail-open** | Blocking all traffic because a classifier endpoint is slow turns a security control into an availability incident. |

A fail-closed detector that fails produces a synthetic `BLOCK` finding
explaining exactly that, so the audit trail distinguishes "we detected
something" from "we could not tell".

### Per-stage latency budget

`input_budget_ms` / `output_budget_ms` (250ms each by default) are real budgets.
Once the accumulated detector cost exceeds the budget, remaining detectors are
skipped, a finding records the fact, and the pipeline fail mode engages.
**Detection depth degrades under load; latency does not grow without bound.**

### When the control plane is unreachable

Configured per organisation via `policy.unreachable_behavior`:

| Setting | Behaviour | Suits |
|---|---|---|
| `last_known_good` (default) | Keep enforcing the last successfully fetched policy, up to `max_staleness_s` (1 hour). Then fall back to the safe default and report degraded. | Most deployments. Silently enforcing a week-old policy is its own incident, hence the ceiling. |
| `safe_default` | Drop immediately to the built-in minimal policy. | Regulated environments that would rather under-enforce a known-simple policy than enforce a stale complex one. |
| `fail_open` | Disable policy enforcement. Detectors still run, events still emit; only the policy layer stops acting. | Availability-first risk tolerance. Must be chosen explicitly. |

The SDK's `health()` always reports `status: "degraded"` and a human-readable
reason while any of these paths is active. Degradation is never silent.

### Telemetry unreachable

Local sinks keep working. The queue absorbs the outage up to capacity, then
sheds low-severity events first. The SDK never fails a request because it could
not ship an audit event.

---

## 6. Streaming enforcement

Filtering a streamed response only after it completes defeats the point of
streaming: the user has already read it. Evaluating every detector on every
token is unaffordable — a 500-token response would run the detector suite 500
times.

The cascade, and what each choice costs:

1. Evaluate every `stream_check_every_chars` (default 120, about a sentence).
   **Detection is late by up to one window.** A smaller window buys earlier
   interception and costs CPU linearly.
2. Each checkpoint runs only the cheap deterministic detectors — leaked
   secrets, banned terms — which are the ones that are both fast and precise on
   partial text.
3. Score at or above `stream_break_threshold` (0.75): break immediately.
4. Score in the ambiguous band (0.45–0.75): escalate that checkpoint once to
   the full detector set. Same cheap-path-plus-escalation arrangement the
   Token-Flow Firewall paper argues for, applied to tokens instead of flows.
5. Whatever happens, the **complete** response goes through the full output
   pipeline before the stream is reported finished. The incremental pass is an
   early-exit optimisation, never a replacement.

**What a caller must understand:** a circuit break means text emitted before the
break has already reached the consumer, and Keeper cannot un-send it. So
`hold_window` defaults to true: one window is buffered, and nothing is released
until it has been checked. That trades a window of time-to-first-token for the
guarantee. Set it false for the fastest first token, accepting that up to one
window of unsafe text may be delivered before the break.

---

## 7. Rate limiting across a fleet

An honest account, because the naive claim is false.

A token bucket inside the application process limits **that process**. Ten
replicas means ten times the quota. Any claim that an in-process limiter
enforces a fleet-wide quota is untrue, so we do not make it.

What local limiting is genuinely good for: immediate zero-latency backpressure
on the obvious cases (a runaway loop, one client hammering one instance), and a
floor that keeps working when the control plane is unreachable.

For an actual fleet-wide quota, `access_control.distributed` enables a two-tier
lease:

1. The local bucket runs first and rejects what it can. Free, synchronous.
2. Consumption is reported asynchronously, and the control plane returns a
   *lease*: this instance's share of the remaining global quota for the next
   window. The local bucket is resized to the lease.

Near-fleet-wide enforcement with no network round trip on the request path. The
cost is **overshoot bounded by one lease window**. Organisations that cannot
tolerate any overshoot should enforce quota at their API gateway, where a
synchronous check is already being paid for. A lease fetch that fails falls back
to the *local* quota — an unreachable control plane must never raise anyone's
limit.

---

## 8. Control plane internals

| Concern | Choice | Reasoning |
|---|---|---|
| API framework | FastAPI | OpenAPI generation for free, which matters when the SDK contract is the product. |
| Storage | SQLAlchemy Core over SQLite (dev) / Postgres (prod) | Core, not the ORM: the access pattern is append-heavy inserts plus aggregate queries over one wide table. An identity map buys nothing. |
| Audit schema | One wide `audit_events` table; findings and traces as JSON | They are always read with their parent event. Normalising them would triple the write cost of the hottest path for a query nobody runs. The two fields that *are* queried across events — `detectors_fired`, `categories` — are lifted out at ingest. |
| Timeline | Rolling per-minute counter table maintained at ingest | Keeps the dashboard's default view O(minutes) rather than O(events). |
| Policy storage | Append-only, versions immutable | A decision recorded under policy 1.4.0 must always be explicable by the exact bundle that produced it. Republishing a version with different content is refused. |
| Background work | Four asyncio tasks in the API process | A separate worker is right at scale but doubles the deployment surface for a system whose pitch is "self-hostable in an afternoon". Every job is safe to run in two replicas; the worst case is duplicate alert evaluation, which cooldowns absorb. `docs/deployment.md` covers splitting them out. |

### Two API surfaces, two credentials

`/v1/*` is called by SDK instances — potentially hundreds of processes, in
application repos and CI. It may write telemetry and read the published policy.

`/api/*` is called by people. It may read the entire audit trail and publish
policy.

These are deliberately separate key spaces. Conflating them would mean any
compromised application could read every other application's audit log.

---

## 9. Observability data flow

Three streams, three purposes:

**Audit events** — one per decision, with full causal context: which detectors
fired with what evidence, which policy rule matched, what action resulted, and
a correlation id tying every stage of one request together. SDK → local sink →
control plane → dashboard and SIEM.

**Metrics** — Prometheus series for request counts, per-detector latency and hit
rates, policy evaluation time, queue depth, error rates. Exposed by the SDK for
the developer's own monitoring, and mirrored in the control plane for the fleet.
Cardinality is bounded on purpose: principal ids and correlation ids never
become labels.

**Traces** — W3C trace context propagated through the pipeline so a single AI
request can be followed from the application call, through each detector, to the
model, through output filtering, and into the audit store. OpenTelemetry when
`opentelemetry-sdk` is installed; correlatable ids regardless.

Redaction is applied at event-construction time, inside the SDK, **before**
anything leaves the process. The default mode is `redacted`: detected spans
replaced with typed placeholders, plus a safety-net pass for patterns no
detector claimed. `hash_only` ships salted digests and no content at all, which
is what makes cross-application probe detection possible under strict data
handling — the control plane can tell that the same prompt hit four
applications without ever holding the prompt.

---

## 10. Non-functional targets

| Property | Target | How it is held |
|---|---|---|
| Added p95 latency | < 5ms for the default detector set on a 2KB prompt | Detectors are regex and arithmetic; measured by `keeper_pipeline_latency_ms`; enforced by the stage budget. |
| Memory footprint | < 20MB beyond the host application | No bundled model weights. Regex-based detectors by default; ML detectors are opt-in and out-of-process. |
| Control-plane dependency on hot path | **Zero** | Telemetry is queued; policy is cached. Verified by an integration test that runs the SDK against an unreachable endpoint. |
| Ingest throughput | Bounded by Postgres insert rate, not by the API | Batched inserts, background alert evaluation, counter table for aggregates. |
| SDK dependencies | Zero required, both languages | Every transitive dependency we add is one our users must audit and patch. |

---

## 11. Extension points

Every one of these is the same interface the built-ins use — there is no
second-class plugin tier.

| Extend | Interface | Registration |
|---|---|---|
| Detector | `Detector.detect(DetectorInput) -> Finding` | `register("name", factory)`, or `extra_detectors=[...]` |
| Model backend | `Provider.complete()` / `.stream()` | Pass to `Keeper(provider=...)`; `CallableProvider` wraps any function |
| Policy engine | `evaluate(facts) -> [PolicyTrace]` | `policy.engine: "embedded" | "opa"` |
| Audit sink | `Sink.emit/flush/close` | `keeper.sink.add(...)` |
| Alert channel | `Notifier.send(alert)` | `AlertEngine.add_notifier(...)` |
| SIEM target | `SIEMExporter.export(events) -> int` | `KEEPER_CP_SIEM_TARGETS` |
| Auth provider | `AuthProvider.authenticate(credential) -> Principal` | `access_control.auth_provider` |

---

## 12. What is deliberately not here

Stated so a reviewer does not have to discover it:

- **No semantic secret-leakage detection.** The `secret_leakage` detector
  matches registered values exactly. A model *describing* a secret rather than
  quoting it is not caught.
- **No ML-based PII detection by default.** Regex plus validators. High
  precision on structured PII, limited recall on names and free-text health
  information. Presidio or an NER model slots in under the same detector name.
- **Groundedness is a lexical screen, not a hallucination oracle.** It flags,
  never blocks, for exactly that reason.
- **No true sandbox.** `ToolGuard` provides the decision point and a
  `sandbox_runner` hook; real isolation is an OS-level concern and
  `docs/deployment.md` covers it. A Python-level fake would be worse than none,
  because it would be trusted.
- **No proxy mode.** Section 2 explains the decision and why the modules are
  shaped so it can be added without a rewrite.
- **`create_all`, not migrations.** Adequate for v1; a deployment that outgrows
  it should adopt Alembic. Said out loud rather than pretending otherwise.
