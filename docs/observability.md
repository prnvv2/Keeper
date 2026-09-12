# Observability

Keeper treats observability as a deliverable equal to enforcement, not as
logging bolted onto a filter. The reason is practical: most AI security tooling
tells you it blocked something and nothing else. That is enough to satisfy a
procurement checkbox and not enough to run an incident, tune a control, or
answer an auditor.

This guide covers the three telemetry streams, what redaction does to them, how
to get them into your SIEM, how to alert on them, and how to monitor the
firewall itself.

---

## 1. The three streams

| Stream | Question it answers | Cardinality | Where it goes |
|---|---|---|---|
| **Audit events** | What happened, and why | High — one per decision | Local sink → control plane → SIEM |
| **Metrics** | How is it behaving | Bounded, deliberately | Your Prometheus |
| **Traces** | Where did the time go | Per request | Your tracing backend |

They are separate on purpose. Putting a principal id in a metric label produces
an unbounded time series and a very unhappy Prometheus; putting an aggregate
count in an audit event makes it unusable for investigation.

---

## 2. Audit events

One decision produces exactly one audit event. That invariant is what makes the
correlation view reliable.

### Schema

Stable, versioned by `schema_version` (`keeper.audit.v1`). Additions are
backwards compatible; removals are not.

```jsonc
{
  "event_id": "evt_9f2c...",
  "correlation_id": "req_3f19...",     // ties every stage of one request together
  "timestamp_ms": 1789146555013,
  "stage": "input",                     // input|output|stream|tool_call|tool_result|
                                        // retrieval|memory_write|memory_read|access
  "action": "block",                    // allow|flag|redact|challenge|block
  "severity": "critical",

  "application": "support-bot",
  "environment": "production",
  "instance_id": "inst_4b1c...",
  "sdk_version": "0.1.0",
  "schema_version": "keeper.audit.v1",

  "session_id": "s-1",
  "principal_id": "u-42",
  "principal_roles": ["analyst"],
  "tenant": "acme",

  "model": "gpt-4o-mini",
  "provider": "openai",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "policy_version": "acme.default@1.4.0",

  "findings": [{
    "detector": "secrets",
    "detected": true,
    "score": 1.0,
    "severity": "critical",
    "action": "block",
    "summary": "credential material detected: github_token",
    "category": "credential_exposure",
    "spans": [{"start": 41, "end": 81, "label": "github_token"}],
    "evidence": {"labels": ["github_token"], "vendor_matches": 1},
    "elapsed_ms": 0.42,
    "error": null
  }],

  "policy_traces": [{
    "policy_id": "acme.default",
    "policy_version": "1.4.0",
    "rule_id": "block-credential-egress",
    "matched": true,
    "action": "block",
    "elapsed_ms": 0.018,
    "note": "This request contains credential material and was blocked."
  }],

  "prompt": "here is my token [REDACTED:github_token]",
  "response": null,
  "redacted_fields": ["github_token"],

  "latency_ms": 1.83,
  "tokens_in": 12,
  "tokens_out": null,
  "error": null,
  "tags": {"trust": "user", "prompt_sha256": "a3f1..."}
}
```

### What makes an event useful

Four fields do most of the work:

- **`correlation_id`** — the whole point. An investigator pastes it into the
  dashboard and gets the complete interaction: what came in, which documents
  were retrieved, which tools were attempted, what came out, and where the
  firewall intervened. It is returned to the caller on every response and quoted
  in every block message, so a user reporting "it refused my request" hands you
  the exact identifier.
- **`findings[].evidence`** — *why*, not just *what*. Which signals matched,
  their weights, the trust multiplier applied, the offsets. This is what makes a
  block reviewable rather than a black box.
- **`policy_traces`** — which rule, at which version, taking how long. Both an
  audit requirement and the input to policy-effectiveness analysis.
- **`tags.prompt_sha256`** — a salted digest that ships even when the content
  does not. It is what makes cross-application probe detection possible under
  strict redaction.

### Local sinks

Every event is written locally first, synchronously, before any attempt to ship
it. The local trail keeps working when the control plane does not.

```python
keeper = Keeper(application="support-bot", telemetry={"local_log_path": "/var/log/keeper/audit.jsonl"})
```

Deliberately **not** routed through `logging`: an audit trail must not inherit
the host application's log level, formatters or filters. An operator setting
their app to `WARNING` should not silently disable the audit trail.

Available sinks: `MemorySink` (always on, powers `keeper.recent_events()`),
`JSONLinesSink` (append-only with rotation), `StreamSink` (stdout, for
container log collection), `CallbackSink` (hand each event to your own
pipeline), `FanoutSink` (all of the above).

```python
from keeper_firewall.observability import CallbackSink
keeper.sink.add(CallbackSink(lambda event: my_pipeline.write(event.to_dict())))
```

---

## 3. Redaction

An AI firewall that ships every prompt verbatim to a central store has created a
new, highly concentrated data-protection problem in the name of solving a
security one. So redaction happens **inside the SDK, before anything leaves the
process** — the control plane cannot un-redact what it never received.

| Mode | What is stored | Use when |
|---|---|---|
| `none` | No payload at all. Findings, spans and policy traces still recorded. | Strictest handling. You still see *that* a card number was present at offsets 41–57. |
| `hash_only` | A salted digest and nothing else. | You need cross-application correlation without storing content. |
| `redacted` **(default)** | Detected spans replaced with typed placeholders, plus a safety-net pass. | Most deployments. |
| `full` | The raw payload. | Staging, or a regulated workload where the audit store is already the system of record. Never the default. |

### The safety net

In `redacted` mode a second pass runs regardless of which detectors were
enabled — emails, card-shaped numbers, token-shaped strings, bearer headers,
private key blocks. A disabled PII detector must not silently become a data leak
into the audit store.

### Salt

```bash
export KEEPER_REDACTION_SALT="$(openssl rand -hex 32)"
```

Set it. Without one, Keeper generates a random per-process salt: digests stay
correlatable within a process but not across restarts, which quietly disables
cross-application detection. An *unsalted* digest of a short prompt is trivially
reversible by brute force, which is why there is no unsalted option.

`keeper.health()["redaction"]["ephemeral_salt"]` reports whether you are in the
degraded mode.

---

## 4. Metrics

Prometheus-compatible, registered in `prometheus_client`'s default registry when
that package is installed, so they appear on whatever `/metrics` endpoint you
already serve. No dependency required — there is a built-in registry otherwise,
producing identical exposition.

### SDK series

| Metric | Type | Labels | Alert on |
|---|---|---|---|
| `keeper_requests_total` | counter | stage, action, application | A sudden drop = the firewall stopped seeing traffic |
| `keeper_blocked_total` | counter | stage, category, application | Rate spikes by category |
| `keeper_detector_runs_total` | counter | detector, stage, outcome, application | `outcome="error"` climbing |
| `keeper_detector_hits_total` | counter | detector, severity, action, application | Hit-rate shifts after a deploy |
| `keeper_detector_errors_total` | counter | detector, fail_mode, application | **Any** sustained value |
| `keeper_policy_evaluations_total` | counter | policy_id, action, application | Confirms policy is live |
| `keeper_access_denied_total` | counter | reason, application | Auth/quota pressure |
| `keeper_telemetry_events_total` | counter | outcome, application | Shipping health |
| `keeper_telemetry_dropped_total` | counter | reason, application | **Any** value = losing audit data |
| `keeper_pipeline_latency_ms` | histogram | stage, application | p95 against your budget |
| `keeper_detector_latency_ms` | histogram | detector, application | Which detector costs what |
| `keeper_policy_latency_ms` | histogram | policy_id, application | Policy complexity creep |
| `keeper_model_latency_ms` | histogram | provider, application | Separates model time from firewall time |
| `keeper_telemetry_queue_depth` | gauge | application | Rising = control plane struggling |
| `keeper_policy_age_seconds` | gauge | policy_id, application | Rising = policy not refreshing |
| `keeper_info` | gauge | application, sdk_version, environment | Version inventory |

### Cardinality

Labels are bounded sets. `principal_id`, `correlation_id` and caller-supplied
model names never become labels — that data belongs in the audit trail, which is
built for high cardinality. This is a design constraint, not an oversight.

### Control-plane series

`GET /metrics`, unauthenticated so a scraper needs no credential:

```
keeper_cp_events_ingested_total
keeper_cp_ingest_batches_total
keeper_cp_events_stored
keeper_cp_instances{status="healthy"|"stale"}
keeper_cp_siem_exported_total
keeper_cp_siem_failed_batches_total
```

### Alerts worth having

```yaml
groups:
  - name: keeper
    rules:
      - alert: KeeperLosingAuditEvents
        expr: rate(keeper_telemetry_dropped_total[5m]) > 0
        for: 5m
        annotations:
          summary: "Keeper is dropping audit events ({{ $labels.reason }})"

      - alert: KeeperDetectorFailing
        expr: rate(keeper_detector_errors_total[5m]) > 0.01
        for: 10m
        annotations:
          summary: "Detector {{ $labels.detector }} is failing (fail-{{ $labels.fail_mode }})"

      - alert: KeeperOverheadHigh
        expr: histogram_quantile(0.95, rate(keeper_pipeline_latency_ms_bucket[5m])) > 50
        for: 10m

      - alert: KeeperStoppedSeeingTraffic
        expr: rate(keeper_requests_total[10m]) == 0 and keeper_info > 0
        for: 15m
        annotations:
          summary: "An instrumented application stopped reporting — bypass or outage?"

      - alert: KeeperPolicyStale
        expr: keeper_policy_age_seconds > 3600

      - alert: KeeperSIEMExportFailing
        expr: rate(keeper_cp_siem_failed_batches_total[15m]) > 0
        annotations:
          summary: "The audit trail is not reaching the SIEM"
```

That last one matters more than it looks. The worst observability failure is not
a missing alert — it is a pipeline that has been silently broken for a fortnight
while the dashboard still looks healthy.

---

## 5. Tracing

W3C trace context is propagated through the pipeline, so a single AI request can
be followed from the application call, through each detector, to the model,
through output filtering, and into the audit store.

With `opentelemetry-sdk` installed, Keeper emits real spans nested inside your
application's trace. Without it, it still produces and propagates
`trace_id`/`span_id`, which land in every audit event — tracing degrades to
"correlatable ids", never to nothing.

```bash
pip install "keeper-firewall[otel]"
export KEEPER_OTEL_ENABLED=true
export KEEPER_OTEL_ENDPOINT=http://otel-collector:4318
```

```python
# Continue an inbound trace
ctx = keeper.context(traceparent=request.headers.get("traceparent"))
```

Span attributes: `keeper.input_action`, `keeper.output_action`,
`keeper.model_latency_ms`, plus a `keeper.blocked` event when something is
stopped.

---

## 6. SIEM export

Your SIEM is almost certainly the system of record; Keeper's dashboard is a
purpose-built *view*, not a silo. Three targets ship in v1.

```bash
KEEPER_CP_SIEM_ENABLED=true
KEEPER_CP_SIEM_TARGETS=webhook:https://http-inputs.splunk.example.com/services/collector/raw
KEEPER_CP_SIEM_MIN_SEVERITY=low
KEEPER_CP_SIEM_BATCH_SIZE=100
KEEPER_CP_SIEM_FLUSH_INTERVAL_S=5
```

### webhook — built first, and why

Newline-delimited JSON over HTTPS. Every SIEM has an HTTP collector — Splunk
HEC, Elastic, Datadog, Sentinel via Logic App — so this one target unblocks
every destination at once without us implementing a vendor SDK per backend.
That is the reason it is first rather than the most standards-pure option.

### syslog — CEF over RFC 5424

Still the lingua franca for on-prem SIEM and syslog relays.

```
KEEPER_CP_SIEM_TARGETS=syslog:siem.internal:514
KEEPER_CP_SIEM_TARGETS=syslog+tcp:siem.internal:601
```

```
<109>1 2026-09-12T09:15:32Z support-bot keeper - - - CEF:0|Keeper|AI Firewall|1.0|
credential_exposure|credential material detected: github_token|10|
rt=1789146555013 externalId=evt_9f2c cs1Label=correlationId cs1=req_3f19
cs2Label=detectors cs2=secrets cs3Label=policyVersion cs3=acme.default@1.4.0
act=block outcome=failure suser=u-42 app=support-bot deviceProcessName=input
```

The mapping is done properly, including the escaping rules people usually get
wrong: `\` and `|` in the header, `\`, `=` and newlines in extensions.

### otlp — OpenTelemetry logs

```
KEEPER_CP_SIEM_TARGETS=otlp:https://otel-collector.internal:4318
```

Emitted as log *records*, not spans — an audit event is a discrete fact, not a
duration. `trace_id` is carried through so a security event joins to the
application trace that produced it, which is the property that makes this worth
supporting alongside the webhook.

### Delivery semantics

**At-least-once, with a checkpoint.** Events carry a stable `event_id` so the
receiving SIEM can deduplicate. Promising exactly-once over a sink we do not
control would be a lie.

The checkpoint is `received_ms`, not `timestamp_ms`: events arrive out of order
(an SDK that was offline ships an hour of backlog at once), and checkpointing on
event time would silently skip them.

On partial failure the checkpoint **still advances**. A permanently broken
target must not pin the checkpoint and re-send the same batch forever. The
failure is counted, surfaced in `/health`, and alertable.

### Writing your own target

```python
class MyExporter:
    name = "my-siem"
    def export(self, events: list[dict]) -> int: ...
    def close(self) -> None: ...
```

---

## 7. Alerting

Three rule kinds, covering what security teams actually ask for.

| Kind | Fires on | Evaluated |
|---|---|---|
| `match` | Any single event matching a filter | On the ingest path, sub-second |
| `threshold` | A count over a window crossing a number | On a timer (30s) |
| `anomaly` | Cross-application anomaly findings | On a timer (60s) |

Five rules are seeded on first start, chosen so a fresh deployment alerts on
things nobody would argue about and nothing else:

| Rule | Fires when |
|---|---|
| `rule_credential_leak` | Credential material blocked on input or output |
| `rule_indirect_injection` | Injection found in retrieved or tool-supplied content |
| `rule_unsafe_tool_flow` | Low-authority content attempted a privileged tool call |
| `rule_injection_burst` | 10 blocked injections from one principal in 5 minutes |
| `rule_anomalies` | Any high-severity cross-application anomaly |

```json
PUT /api/alert-rules
{
  "id": "rule_pii_in_checkout",
  "name": "PII blocked in checkout",
  "kind": "threshold",
  "severity": "high",
  "spec": {
    "window_s": 600,
    "count": 5,
    "group_by": "principal_id",
    "filter": {"application": "checkout", "category": ["sensitive_data"], "action": ["block"]}
  },
  "channels": ["slack", "webhook"],
  "cooldown_s": 900
}
```

**Every rule has a cooldown**, because the failure mode of alerting is not a
missed alert — it is four hundred alerts, after which people mute the channel
and you have negative security value.

### Delivery is recorded, not assumed

Each alert stores what happened to each channel. A rule firing correctly into a
webhook that has been returning 500 for two weeks shows as `failed` in red next
to the alert, on the dashboard. Test channels before you need them:

```bash
curl -X POST -H "Authorization: Bearer $ADMIN_KEY" \
  -d '{"channels":["slack","webhook"]}' http://localhost:8080/api/alerts/test
```

---

## 8. Cross-application anomaly detection

The division of labour with the SDK: the SDK runs fast local heuristics on a
single conversation. What it structurally cannot see is the fleet.

| Detector | Finds | Why only the control plane can see it |
|---|---|---|
| `repeated_injection` | One principal, many blocked attempts | Behind a load balancer the attempts hit different instances |
| `cross_application_probe` | The **same payload** hitting several applications | No instance sees another application's traffic |
| `volume_spike` | Request or block volume far above a rolling baseline (z-score) | Needs a fleet baseline |
| `new_attack_surface` | An application that never blocked anything suddenly does | Needs history across the window |
| `coverage_gap` | Production instances with detectors disabled or in monitor-only | Needs the fleet inventory |

`cross_application_probe` is the highest-signal detection in the system, and it
works on the salted prompt hash — so it functions under `redaction.mode: none`,
where no prompt text is stored anywhere. That is precisely why the SDK ships the
digest even when it ships no content.

`coverage_gap` is not an attack. It is the auditor's first question, answered
automatically.

---

## 9. Analytics

The Analytics page turns the audit trail into decisions rather than a
compliance checkbox.

**Detector effectiveness** — runs, hits, hit rate, average latency, error count,
per detector. This is how you answer "is this detector worth its latency?" and
"did that threshold change actually do anything?". A detector at a 30% hit rate
is either finding a real problem or is misconfigured for your domain.

**Policy rules that fired** — matches, action breakdown, average evaluation
time. A rule that never fires is either well-targeted or dead weight; dry-run it
against recorded traffic before removing it.

**Where the latency goes** — per-detector cost, ranked. Usually surprising.

**Coverage** — how often each detector actually ran, which reveals detectors
disabled by config or short-circuited by an earlier block.

---

## 10. Monitoring the firewall itself

Both halves expose their own health, because an ops team needs to monitor
Keeper the way they monitor any other production dependency.

```python
keeper.health()
```

```jsonc
{
  "status": "ok",                       // or "degraded", with a reason below
  "sdk_version": "0.1.0",
  "uptime_ms": 3_600_000,
  "monitor_only": false,
  "detectors": ["secrets", "pii", "prompt_injection", ...],
  "policy": {
    "source": "control_plane",
    "policy_id": "acme.default", "policy_version": "1.4.0",
    "age_seconds": 42, "refreshes": 60,
    "degraded": null, "last_error": null
  },
  "telemetry": {
    "queue_depth": 3, "queue_capacity": 10000,
    "shipped": 15234, "dropped": 0, "failed_batches": 0,
    "healthy": true
  },
  "rate_limiter": {"scopes": 12},
  "memory": {"total": 84, "by_trust": {"external": 12, "user": 72}},
  "redaction": {"mode": "redacted", "ephemeral_salt": false}
}
```

Control plane: `/healthz` (liveness, no database touch — a liveness probe that
fails when the database is down gets the process killed, which does not fix the
database and does lose the in-flight ingest queue), `/readyz` (readiness, with
the round trip), and `/health` (detailed, authenticated, including every startup
warning).

### The four things worth watching

1. **`telemetry.dropped > 0`** — you are losing audit data.
2. **`policy.degraded != null`** — you are not enforcing the policy you think.
3. **`keeper_detector_errors_total` rising** — a control is silently
   non-functional. Check `fail_mode` to know whether that is failing open.
4. **`keeper_cp_siem_failed_batches_total` rising** — the audit trail is not
   reaching the system of record.

---

## 11. Compliance and retention

- **Retention** — `KEEPER_CP_RETENTION_DAYS` (90 by default). Zero disables
  deletion entirely, which some regimes require; the operator then owns the
  disk-space problem.
- **Right to erasure** — `principal_id` is indexed. Deleting one subject's
  events is a single `DELETE`. Under `redaction.mode: hash_only` there is
  usually nothing personal to erase in the first place, which is the better
  answer.
- **Data residency** — the control plane is self-hosted; nothing leaves your
  infrastructure unless you configure a SIEM target that sends it there.
- **Audit integrity** — policy versions are immutable and append-only, so a
  decision recorded under version 1.4.0 is always explicable by the exact bundle
  that produced it.
- **Templates in `policies/templates/`** are starting points an organisation
  adapts. They are not compliance guarantees and are labelled as such in the
  files themselves.
