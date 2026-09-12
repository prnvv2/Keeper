# Open-Source AI Firewall — SDK & Observability Platform

## 0. Role & Operating Mode

You are acting as a **principal security architect, AI security engineer, and
open-source infrastructure maintainer**, working inside this repository as my
engineering partner — not a one-shot code generator.

Operating rules for this engagement:

- **Design before code.** Do not write implementation code until Phase 0's design
  artifacts (Section 6) exist and I've approved them.
- **Ask, don't assume.** Where a requirement is ambiguous or a decision has real
  tradeoffs (e.g., sync vs. async filtering, which policy language, how the SDK
  fetches policy updates), stop and ask me rather than picking silently.
- **Work in phases.** Follow the phased plan in Section 8. Do not jump ahead to
  later phases even if it seems efficient — I want to review and steer between
  phases.
- **Cite your reasoning.** When a design choice is driven by one of the research
  sources in Section 4, say which one and why, in your own words — don't just
  namedrop the paper.

---

## 1. Mission

Design and build a **production-grade, fully open-source AI Firewall** that
introduces **Monitorability and Observability as first-class capabilities for
AI safety and security**.

The product is delivered as two cooperating halves:

1. **An SDK that AI developers integrate directly into their applications** —
   the data plane. Developers `pip install` or `npm install` the library, wrap
   their existing LLM/agent/RAG calls, and immediately gain input filtering,
   output filtering, access control, runtime protection, and deep observability
   of every AI interaction — without changing their application architecture or
   routing traffic through an external proxy.

2. **A central dashboard and backend (the control plane)** that every SDK
   instance reports to — functioning as the organization's **AI-native SIEM**
   and operations center. Security and compliance teams use it to monitor live
   AI traffic across every instrumented application, investigate incidents,
   enforce policy fleet-wide, and export the full audit trail to their existing
   SIEM (Splunk, Elastic, Datadog, Sentinel, etc.).

### Why Monitorability & Observability matter here

Most AI security tools today are **black-box wrappers**: they block or allow a
request, but give the organization no structured visibility into *what* is
flowing through their AI systems, *why* a decision was made, or *how* threat
patterns are evolving across their fleet. This project treats observability —
structured telemetry, traceable policy decisions, cross-application anomaly
detection, and SIEM-grade audit trails — as an equally important deliverable
alongside enforcement. The firewall doesn't just protect; it makes AI traffic
**legible** to the security team.

Concretely, observability means:

- Every SDK enforcement decision (block, allow, redact, flag) produces a
  structured audit event with full causal context: which detectors fired, which
  policy rule matched, the input/output (subject to configurable redaction), and
  a correlation ID that ties the event to the originating application, user,
  session, and model.
- The control plane aggregates these events into a live operational picture —
  dashboards, alerting, anomaly detection — and forwards them to external SIEMs
  in standard formats (OpenTelemetry, Syslog/CEF, webhook) so AI traffic
  becomes a first-class data source in the org's existing security operations
  workflow.
- The SDK itself exposes Prometheus-compatible metrics for the developer's own
  infrastructure monitoring (request counts, latency histograms, detector hit
  rates, error rates) so the AI firewall is observable as infrastructure, not
  just as a security tool.

### Target engineering bar

Comparable in maturity to established API gateways and security platforms (Kong,
Envoy, OPA-based systems) — not a proof-of-concept or a wrapper script. It
should be something a mid-size org's security team could deploy in front of
production LLM traffic and a developer could integrate in under ten minutes.

### Licensing & deployment model

Fully open source under a permissive license (default Apache 2.0 unless there's
a reason to recommend otherwise). Self-hostable with no required SaaS
dependency. Designed for extensibility — organizations will plug in their own
detectors, policies, model backends, and export targets.

### Trust-boundary tradeoff (document explicitly in the architecture doc)

SDK-based enforcement runs inside the developer's own process: faster, no extra
network hop, but a malicious or compromised app could in principle bypass or
tamper with it. An inline proxy (a separate trust boundary the app can't opt out
of) doesn't have that weakness but adds latency and deployment complexity.

**v1 scope decision**: ship the SDK as the primary integration path. Architect
the enforcement modules (Section 2) as swappable so an optional proxy/sidecar
mode using the *same* modules is a natural future addition, not a rewrite. Call
this out as a deliberate, documented decision — not an oversight.

---

## 2. Core Capability Areas

Treat each of these as a **pluggable module** behind a common interface, not a
monolith. Every module should be independently testable and independently
disable-able via config. Sections 2.1–2.5 run **inside the SDK** (data plane).
Section 2.7 is the **control plane** everything else reports to.

### 2.1 Input Filtering (pre-request — before the prompt reaches the model)

- **Prompt injection / jailbreak detection** — both direct (user-authored) and
  indirect (injection via retrieved RAG documents, tool outputs, or multi-turn
  context accumulation).
- **Malicious or policy-violating prompt blocking** — configurable rule sets +
  ML/LLM-based classifiers.
- **PII, credential, and secret detection and redaction** — API keys, passwords,
  tokens, personal data — before the prompt leaves the perimeter.
- Support for both **blocking** and **redact-and-continue** modes, configurable
  per policy.

**Observability hook**: every input-filter decision emits a structured event
(detector name, confidence score, action taken, redacted fields if any) to the
SDK's local audit log and — asynchronously — to the control plane.

### 2.2 Output Filtering (post-response — before it reaches the caller)

- **Sensitive data leakage prevention** — the model echoing secrets from
  context, leaking data across tenants/sessions.
- **Hallucination and policy-violation detection** where feasible (groundedness
  checks against RAG context, banned-claim detection).
- **Harmful or non-compliant content blocking** with configurable severity
  thresholds.

**Observability hook**: same structured event pattern as input filtering —
every output decision is a traceable, auditable record.

### 2.3 Access Control

- **Authentication** — API keys, OAuth2/OIDC, mTLS. Support at least one in v1;
  design for pluggable auth providers.
- **Authorization** — which users/services can reach which models, tools, or
  agents.
- **RBAC** (role-based access control), with room to grow toward ABAC
  (attribute-based) later — don't over-engineer ABAC in v1, but don't paint
  yourself into a corner.
- **Per-tenant and per-model rate limiting / quota enforcement.** In an SDK
  deployment, state explicitly whether rate limits are enforced locally per SDK
  instance, centrally via the control plane, or both — local-only limits are
  trivially bypassed by running more instances. The design doc must address
  this.

### 2.4 Monitoring, Logging & Observability (SDK captures; control plane aggregates)

This is the module that makes the "Monitorability & Observability" mission
concrete. It is not an afterthought bolted onto filtering — it is a co-equal
pillar of the system.

- **Structured audit logging** — every SDK interaction (prompt, response, policy
  decision, detector results) is logged as a structured event with a correlation
  ID linking it to the originating app, user, session, model, and policy
  version. Configurable redaction of sensitive fields in the logs themselves.
- **Usage tracking for compliance and audit** — who called what model, when,
  with what outcome, under which policy version.
- **Anomalous behavior detection** — volume spikes, repeated injection attempts,
  unusual access patterns. Start with rule-based/statistical detection in v1;
  note where ML-based detection plugs in later. Runs partly in the SDK (fast
  local heuristics) and partly in the control plane (cross-application patterns
  a single SDK instance can't see, e.g., the same attacker probing multiple
  apps).
- **Prometheus-compatible metrics** — request counts, latency histograms,
  detector hit rates, error rates, policy evaluation times. Exposed by the SDK
  for the developer's own monitoring stack, and shipped to the control plane for
  fleet-wide aggregation.
- **SIEM-grade audit trail** — structured logs in standard formats (JSON lines /
  OpenTelemetry / CEF), shipped from SDK → control plane → external SIEM
  (Section 2.7). Near-real-time streaming, not batch-only.
- **Distributed tracing** — OpenTelemetry trace context propagated through the
  SDK pipeline so that a single AI request can be traced end-to-end: from the
  application call, through each filter/detector, to the model call, through
  output filtering, and into the control plane's audit store.

### 2.5 Runtime Protection

Protection that operates *during* execution, not just at the request/response
boundary. This module catches threat classes that input filtering (2.1)
structurally cannot — input filtering only sees the user's direct prompt, never
what arrives mid-execution from a tool result, a retrieved document, or an
agent's memory.

**OWASP LLM Top 10 / GenAI threat mapping** (the threat-model doc in Section 6
must make this mapping concrete):

| Threat | OWASP Ref | Where addressed |
|--------|-----------|-----------------|
| Direct prompt injection | LLM01 | Input filtering (2.1) + re-check here for multi-turn accumulation |
| Indirect prompt injection | LLM01 variant | Tool-result/document screening at ingestion point, inside the agent's execution loop — input filtering can't see it |
| RAG/knowledge-base poisoning | LLM04 (runtime scope) | Retrieval-time integrity checks: source allowlisting, embedding anomaly detection, instructional-tone flagging |
| Excessive agency | LLM08 | Tool-call interception and capability-scope enforcement before execution |
| Sensitive information disclosure | LLM06 | Output filtering (2.2) + mid-stream circuit-breaker here |
| Unbounded consumption / model theft | LLM10 | Runtime resource and rate anomaly detection, tied to 2.4 |

Reference MITRE ATLAS for adversarial TTPs underlying each when writing the
threat-model doc.

**Three concrete control layers** (all inside the SDK):

1. **Agent/tool execution guardrails** — intercept tool calls before execution.
   Enforce allowlist/denylist of permitted actions per role or per agent.
   Sandbox execution of untrusted tool calls (filesystem, network, shell).
   Kill-switch to halt an in-progress agent run when it crosses a policy
   boundary. Screen tool results and retrieved documents for injected
   instructions *before* they enter the model's context.

2. **Real-time inference monitoring** — for streaming responses, evaluate
   detectors incrementally against the token stream. Support circuit-breaking
   mid-generation. Document the latency/accuracy tradeoffs explicitly (e.g.,
   fast cheap classifier on partial output → slower precise one on full
   response → escalate only on fast classifier's flag).

3. **Infrastructure/container runtime security** — applies primarily to the
   control plane's deployment. Least-privilege container config, syscall
   monitoring (eBPF / Falco or justified alternative), container escape and
   drift detection, runtime integrity verification of the control plane's
   policy store. Document as a deployment-hardening concern in
   `docs/deployment.md`.

**Observability hook**: every runtime-protection action (tool-call intercept,
circuit-break, kill-switch activation) emits a structured event with full
context — which agent, which tool, what triggered the action, what was blocked.
These are high-signal security events and must be surfaced prominently in the
dashboard and forwarded to SIEM.

### 2.6 Policy Enforcement

- **Declarative policy engine** — evaluate OPA/Rego as the default; justify
  whatever you pick.
- **Central authoring, distributed enforcement** — policies are
  authored/managed in the control plane (2.7) and distributed to SDK instances.
  Define explicitly how: pull-on-interval with local caching (SDK keeps
  last-known-good policy if the control plane is unreachable — tie to
  fail-safe behavior in Section 3), or push via persistent connection. State a
  default and justify it.
- **Compliance policy templates** — starting templates for common regulatory
  patterns (GDPR, HIPAA-relevant controls for AI traffic: data residency, PII
  handling, audit retention). Framed as *starting templates the org must
  adapt*, not compliance guarantees.
- **Policy versioning and dry-run mode** — test policy changes against
  historical traffic before going live.

**Observability hook**: every policy evaluation is logged with the policy
version, rule that matched, evaluation time, and outcome — enabling both audit
and policy-effectiveness analysis in the dashboard.

### 2.7 Control Plane: Dashboard, SIEM Integration & Fleet Operations

This is what makes a fleet of SDK instances into something a security team can
actually operate. It is the **AI-native SIEM view** — purpose-built for AI
traffic, while integrating cleanly with the org's existing general-purpose SIEM.

- **Real-time dashboard** — live view of AI traffic across every instrumented
  application: request volume, block/allow/redact decisions, active policy
  violations, which apps/tenants/models are involved. Answers "what's happening
  right now" at a glance and "what happened to this specific request" on
  drill-down. Includes an **observability overview**: aggregate detector hit
  rates, policy evaluation latencies, SDK health across the fleet.

- **Audit log search & investigation** — full-text/structured search over the
  aggregated audit trail. Enough detail to reconstruct an incident: the prompt,
  the policy decision, which detector fired, the response (subject to the same
  redaction rules as the logs). Correlation IDs let an investigator trace from
  a single flagged event to the full session/user/application context.

- **Alerting** — configurable rules on anomaly-detection and policy-violation
  streams (e.g., N injection attempts from one source in M minutes). Support at
  least one outbound integration for v1 (email, Slack/webhook, or
  PagerDuty-style) — pick one and design the alerting interface so others are
  pluggable.

- **Policy management UI** — where security teams author, version, dry-run, and
  publish policies that SDK instances pull (2.6). Also where RBAC for the
  *dashboard's own users* lives — don't conflate this with the RBAC in 2.3
  (which governs end-user/app access to models).

- **SIEM export** — the org's own SIEM is likely the system of record; the
  dashboard is a first-class *view*, not a silo. Support standard formats:
  Syslog/CEF, OpenTelemetry, and/or a generic webhook/HTTP sink — so the AI
  audit trail feeds into whatever SIEM the org already runs, in near-real-time.

- **Fleet/inventory view** — which applications have the SDK integrated, which
  policy version each is running, SDK version/health per instance. Critical for
  catching apps running a stale or unpatched SDK.

- **Observability analytics** — trend views over time: how are detector hit
  rates changing? Which policy rules fire most? Which applications generate the
  most blocked requests? Where are the coverage gaps (apps with the SDK
  installed but detectors disabled)? This turns the audit trail into actionable
  intelligence, not just a compliance checkbox.

---

## 3. Non-Functional Requirements

These matter as much as the feature list:

- **Latency budget**: filtering adds overhead to every LLM call. Design with a
  target p95 added latency under a stated threshold. Call out where you trade
  detection depth for speed. Since the SDK runs in-process, address its
  resource overhead on the host application (memory footprint of loaded
  detectors, CPU impact of synchronous checks).

- **Scalability**: the control plane must handle telemetry ingestion from many
  concurrent SDK instances without becoming a bottleneck or a required
  synchronous dependency on the hot request path. SDK enforcement must not
  block waiting on the control plane for every call — see fail-safe below.

- **Extensibility**: plugin/adapter architecture for new detectors, model
  backends (OpenAI-compatible, Anthropic, local/self-hosted models), policy
  sources, SIEM export targets, and dashboard widgets.

- **Security of the firewall itself**: this is a security product — treat its
  own attack surface seriously (secrets management, supply-chain integrity,
  least-privilege deployment, dependency scanning in CI). The SDK is installed
  as a dependency in third-party codebases: supply-chain integrity (signed
  releases, minimal transitive dependencies, reproducible builds) matters more
  than for an internal-only service.

- **Fail-safe behavior**: explicit, documented decision on fail-open vs.
  fail-closed per module, and why. Most critical for: (a) runtime guardrails
  (2.5) — define timeout behavior for every runtime check; (b) SDK behavior
  when it can't reach the control plane (policy fetch fails, telemetry can't
  ship): enforce last-known-good policy, a safe default policy, or fail open?
  Make this configurable per-org risk tolerance, not hardcoded.

- **Observability of the firewall itself**: the SDK and control plane must be
  observable as infrastructure — health checks, error rates, internal latency
  metrics, queue depths for async telemetry shipping — so that ops teams can
  monitor the firewall the same way they monitor any other production
  dependency.

- **Self-hostability**: no hard dependency on vendor SaaS. Cloud integrations
  (managed vector DB, hosted classifiers) are optional enhancements.

---

## 4. Research Grounding

Use these as primary sources for threat modeling and control design. Extract
*specific, actionable techniques or threat categories* and map them to concrete
modules/controls — don't cite decoratively.

- **OWASP GenAI Security Project** — Top 10 for LLM Applications, Agentic
  Applications, and MCP. Use as the primary threat taxonomy; map each relevant
  risk to the module in Section 2 that mitigates it.
- **MITRE ATLAS matrix** (atlas.mitre.org) — adversarial TTPs against ML
  systems. Inform the anomaly detection and monitoring design (2.4).
- The four arXiv papers provided (2601.15824, 2607.29167, 2607.08395,
  2607.01277) — read each, summarize its relevant contribution in your own
  words in the threat-model doc, and note which design decisions it influenced.

**Deliverable**: a **threat model document** (Section 6) that traces
OWASP/ATLAS/paper-derived threats → the specific control that addresses each.
This traceability is what makes the project defensible to a security reviewer.

---

## 5. Tech Stack

Propose a stack and justify it against these constraints:

- **SDK language(s)**: Python and TypeScript/Node matter most for AI developers.
  Justify whether to build both simultaneously or ship one fully and design the
  interface so a second-language SDK is a port, not a redesign.
- **SDK internals**: how detectors (ML models, classifiers) ship with or
  alongside the SDK — bundled locally (larger install, no network dependency)
  vs. calling a local/control-plane detector service (smaller SDK, adds a
  network hop). Justify the default; make it configurable.
- **Observability internals**: which telemetry library/protocol underpins the
  SDK's event emission and metrics export. Evaluate OpenTelemetry as the
  default; justify whatever you pick. This choice affects how naturally the
  SDK's telemetry integrates with the developer's existing observability stack.
- **Control plane backend**: high-volume telemetry ingestion, dashboard API,
  policy distribution. Propose specific tech (time-series/log store for
  telemetry, Postgres for durable state, Redis for rate limiting/caching) and
  justify each.
- **Dashboard frontend**: modern React-based stack is the safe default. Justify
  only if deviating.
- **Policy engine**: OPA/Rego vs. simpler embedded rule engine — evaluate and
  justify.
- **Deployment target**: Docker Compose for local/dev, Kubernetes manifests or
  Helm chart for production.
- **SIEM export protocols**: confirm which of Syslog/CEF, OpenTelemetry, and
  webhook/HTTP sink you're building first for v1, and why.

Flag this stack proposal to me for approval before Phase 2 begins.

---

## 6. Design Deliverables (Phase 0 — no code yet)

Produce as Markdown documents in a `docs/` directory:

1. **`docs/architecture.md`** — high-level system architecture: SDK (data
   plane) and control plane (dashboard/backend) as cooperating systems, how
   they communicate (policy pull, telemetry push), the request/response data
   flow through the SDK's pipeline (input filtering → model call → output
   filtering → structured audit event → async ship to control plane), the
   observability data flow (metrics, traces, audit events from SDK → control
   plane → external SIEM), and the trust-boundary tradeoff from Section 1.

2. **`docs/low-level-design.md`** — component-by-component detail: interfaces
   between modules, the plugin/adapter contract for detectors and policies, the
   audit event schema, data models for policy objects, API contracts (OpenAPI
   spec for the control plane's management/dashboard API and the SDK's local
   extension points).

3. **`docs/threat-model.md`** — the OWASP/ATLAS/paper-derived
   threat-to-control mapping from Section 4.

4. **`docs/directory-structure.md`** — proposed repo layout, explained (not a
   tree dump — say why each top-level directory exists, how the SDK packages and
   the control plane service relate, monorepo vs. separate repos).

5. **`docs/deployment.md`** — how to run the control plane locally and in
   production (Docker/K8s), how a developer installs/configures the SDK in
   their own app, and how to verify observability is working end-to-end (SDK →
   control plane → dashboard / SIEM). Configuration reference for both.

6. **`docs/sdk-integration.md`** — developer-facing quickstart: install the
   SDK, wrap an existing LLM call, see it show up in the dashboard, verify
   metrics are flowing. This is the most important adoption-facing doc. **A
   developer should go from zero to "I can see my LLM calls in the dashboard"
   in under ten minutes.**

7. **`docs/observability.md`** — dedicated observability guide: what telemetry
   the SDK emits, what metrics are available, how to configure redaction in
   audit logs, how to connect the control plane to an external SIEM, how to
   set up alerting, and how to monitor the firewall itself as infrastructure.

8. **`README.md`** — project overview, quickstart, and status. Lead with the
   value proposition: "An open-source SDK that gives AI developers built-in
   security filtering and gives security teams full observability into AI
   traffic across every application."

Once these exist, stop and let me review before moving to Phase 1.

---

## 7. Success Criteria

- A **security engineer** unfamiliar with the project could read
  `docs/architecture.md`, `docs/threat-model.md`, and `docs/observability.md`
  and understand what the system does, why each control exists, and what
  visibility they'll get into AI traffic.

- An **AI developer** unfamiliar with the project could read
  `docs/sdk-integration.md` and get the SDK wrapping a real LLM call, showing
  up in the dashboard with full audit trail, in **under ten minutes**.

- Every module in Section 2 has a documented interface before it's fully
  implemented, so the project is contributable and extensible from day one.

- The observability story is **complete end-to-end**: SDK emits structured
  events → control plane aggregates and renders → external SIEM receives the
  forwarded stream. No broken links in the chain.

- The project could plausibly pass a basic due-diligence review from an org
  considering deployment: license clarity, no hardcoded secrets, dependency
  hygiene, clear fail-open/fail-closed behavior, sane SDK supply-chain
  practices.

---

## 8. Phased Build Plan

- **Phase 0** — Design deliverables (Section 6). No code.
- **Phase 1** — SDK skeleton: wrap one model backend's calls (sync,
  non-streaming), emit structured audit events locally and expose basic
  Prometheus metrics. Prove the wrapping pattern and observability plumbing
  work cleanly in a real app before adding any enforcement logic.
- **Phase 2** — Control plane skeleton: minimal backend that receives
  telemetry from the SDK, stores it, and serves a bare-bones dashboard listing
  incoming requests with their audit metadata. Connect SDK → control plane
  end-to-end before either side gets sophisticated.
- **Phase 3** — Access control: auth + RBAC + rate limiting (local-SDK and
  control-plane-aware, per the Section 2.3 decision).
- **Phase 4** — Input filtering modules, starting with PII/secret redaction
  (deterministic, easiest to get right) before prompt-injection detection
  (harder, needs a detection strategy decision).
- **Phase 5** — Output filtering modules, including streaming support.
- **Phase 6** — Policy engine + policy distribution (control plane
  authors/serves, SDK fetches/caches), including compliance policy templates.
- **Phase 7** — Full monitoring/logging pipeline and the real dashboard: live
  traffic view, audit log search, anomaly detection, alerting, observability
  analytics.
- **Phase 8** — Runtime protection: agent/tool execution guardrails, mid-stream
  inference monitoring, infra/container runtime hardening for the control plane
  (Section 2.5).
- **Phase 9** — SIEM export integrations (OpenTelemetry, Syslog/CEF, webhook),
  fleet/inventory view.
- **Phase 10** — Deployment hardening: Docker/K8s manifests, CI/CD, security
  scanning, SDK supply-chain checks, load testing against the latency budget.
- **Phase 11** — Documentation pass, example policies, contribution guide,
  observability runbook.

Confirm the phase plan with me before starting Phase 0, and check in at the
end of every phase before starting the next.
