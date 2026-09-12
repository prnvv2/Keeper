# Directory structure

Why each top-level directory exists, how the pieces relate, and the decisions
that shaped the layout.

---

## Monorepo, and why

```
keeper/
├── sdk/python/          data plane, reference implementation
├── sdk/typescript/      data plane, port
├── control-plane/       aggregation, policy distribution, alerting, SIEM
├── dashboard/           the control plane's UI
├── docs/                design and operations documentation
├── policies/            example and template policy bundles
├── deploy/              Docker, Compose, Kubernetes
├── examples/            runnable integrations
└── .github/workflows/   CI
```

Five artefacts, four languages, one repository. The alternative — a repo per
SDK, a repo for the control plane, a repo for the dashboard — was rejected for
one reason that dominates the others:

**The audit event schema is a contract between four components.** It is defined
in `sdk/python/keeper_firewall/types.py`, mirrored in
`sdk/typescript/src/types.ts`, validated in
`control-plane/keeper_control/api/schemas.py`, and typed in
`dashboard/src/lib/api.ts`. In a monorepo, a change that breaks one of those
breaks a single CI run and gets fixed in a single pull request. Split across
four repos, it becomes a version-compatibility matrix and a release-ordering
problem — for a project whose entire value proposition is that the observability
chain has no broken links.

The same argument applies, slightly less forcefully, to the policy document
format (three implementations) and the control-plane API (two clients).

**What the monorepo costs, and how it is paid:** CI runs more than it strictly
needs to on a docs-only change, and contributors clone more than they need. Both
are mitigated by path filters in the workflows. Neither is worth a compatibility
matrix.

**Independent versioning is preserved.** `keeper-firewall` (PyPI),
`keeper-firewall` (npm) and `keeper-control-plane` each have their own version
and release cadence. A monorepo is a source layout, not a release strategy.

---

## `sdk/python/` — the reference implementation

```
sdk/python/
├── keeper_firewall/
│   ├── __init__.py          the public surface; everything else is internal
│   ├── types.py             the cross-language contract
│   ├── config.py            layered configuration + fail-mode defaults
│   ├── errors.py            one exception hierarchy
│   ├── client.py            Keeper — the facade a developer touches
│   ├── pipeline.py          stage evaluation, budgets, fail modes, emission
│   ├── cli.py               the `keeper` command
│   │
│   ├── detectors/           base contract + registry, then one file per family
│   │   ├── base.py          Detector, DetectorInput, registry
│   │   ├── secrets.py  pii.py  injection.py
│   │   ├── cognitive.py     authority_claim + trajectory (one paper, one file)
│   │   ├── tokenflow.py  output.py  llm.py
│   │
│   ├── policy/              models.py (documents + conditions), engine.py, loader.py
│   ├── accesscontrol/       auth.py, rbac.py, ratelimit.py
│   ├── observability/       events.py, metrics.py, tracing.py, redaction.py
│   ├── runtime/             guardrails.py, stream.py, memory.py
│   ├── providers/           base.py (Callable, Echo), remote.py (OpenAI, Anthropic)
│   └── transport/           client.py (stdlib HTTP), shipper.py (async queue)
│
├── tests/                   test_detectors.py, test_firewall.py
├── pyproject.toml
└── README.md
```

### Why this shape

**One directory per Section-2 capability.** `detectors/` is input and output
filtering, `accesscontrol/` is Section 2.3, `observability/` is 2.4, `runtime/`
is 2.5, `policy/` is 2.6. A reviewer reading the brief can find the
implementation of any requirement without a map.

**`types.py` at the root, imported by everything, importing nothing.** It is the
contract; a cycle through it would be a design error.

**`pipeline.py` separate from `client.py`.** `Pipeline` is the enforcement
engine and knows nothing about how it was invoked. `Keeper` is the ergonomic
facade. That separation is exactly what makes a future proxy mode a new
transport rather than a rewrite — see `architecture.md` §2.

**`cognitive.py` holds two detectors.** `authority_claim` and `trajectory` come
from one paper and share its reasoning; splitting them would separate the
explanation from half of what it explains.

**`transport/` is stdlib-only.** `urllib`, not `httpx`. The SDK is installed
into third-party codebases and a client that posts JSON and follows an ETag does
not justify a dependency tree. The control plane uses `httpx` freely — it is a
service we deploy, not a library we inject.

---

## `sdk/typescript/` — the port

```
sdk/typescript/
├── src/
│   ├── types.ts  config.ts  errors.ts  client.ts  pipeline.ts
│   ├── detectors/           base.ts, secrets.ts, pii.ts, injection.ts,
│   │                        cognitive.ts, tokenflow.ts, output.ts, index.ts
│   ├── policy.ts            documents + conditions + engine + provider
│   ├── observability.ts     redaction + events + metrics
│   ├── transport.ts         fetch client + shipper
│   ├── runtime.ts           ToolGuard + StreamGuard + MemoryFirewall
│   ├── accesscontrol.ts     Authorizer + RateLimiter
│   └── providers.ts
├── test/firewall.test.ts
└── package.json
```

The module boundaries mirror Python one-to-one; several Python packages collapse
to a single TypeScript file because the idiom differs — a three-file package for
four exported symbols is Python convention, not TypeScript's.

**Why both languages, rather than shipping one fully.** The brief asks for a
justification, and the honest one is that the decision was made *after* the
Python SDK was complete. Once the interfaces were settled, the TypeScript port
was mechanical: the same ladders, the same escalation rule, the same detector
contract, the same audit schema. What made it a port rather than a redesign was
`types.py` being pure data with no framework in it. A second SDK also validates
the claim that the design is language-independent — if it had not ported
cleanly, that would have been evidence the interfaces were wrong.

Parity is enforced by the test suites sharing a case list. Python is the
reference implementation and carries the `llm_classifier` detector and the CLI.

---

## `control-plane/`

```
control-plane/
├── keeper_control/
│   ├── app.py               FastAPI factory + four background schedulers
│   ├── config.py            settings + startup warnings
│   ├── api/
│   │   ├── deps.py          shared state; the two credential tiers
│   │   ├── schemas.py       request/response models
│   │   ├── ingest.py        /v1/*  — SDK-facing
│   │   ├── dashboard.py     /api/* — human-facing
│   │   └── health.py        /healthz, /readyz, /health, /metrics
│   ├── store/               db.py (schema), repository.py (every query)
│   ├── anomaly/detectors.py cross-application analysis
│   ├── alerting/engine.py   rules, evaluation, notifiers
│   └── siem/exporters.py    webhook, CEF/syslog, OTLP
├── tests/                   test_api.py, test_integration.py
└── pyproject.toml
```

**`api/ingest.py` and `api/dashboard.py` are separate files, not one router.**
They have different audiences, different credentials, and different blast
radii. A compromised application holding an ingest key must not be able to read
every other application's audit log; keeping the surfaces in separate modules
with separate dependencies makes that hard to get wrong by accident.

**Every query lives in `store/repository.py`.** The API layer stays about HTTP
and the aggregation logic is testable without a client. It also makes it
obvious which queries exist, which matters when working out whether the
dashboard survives a hundred million audit rows.

**The control plane depends on the SDK package** (`keeper-firewall`). It parses
and validates the same policy documents the SDK enforces, and depending on the
SDK rather than reimplementing the parser is what guarantees a bundle that
publishes here will load out there. The dependency is one-directional; the SDK
never imports the control plane.

**`tests/test_integration.py` is the load-bearing test.** It starts the control
plane on a socket, points a real `Keeper` at it over HTTP, and asserts the whole
chain: enforcement → audit event → shipper → ingest → storage → dashboard
search, plus policy flowing back the other way, plus graceful degradation when
the endpoint is unreachable. If it passes, the observability story in
`docs/observability.md` has no broken links.

---

## `dashboard/`

```
dashboard/
├── src/
│   ├── App.tsx              shell, nav, admin-key gate
│   ├── lib/api.ts           typed client — the fourth definition of the schema
│   ├── components/ui.tsx    primitives, including hand-drawn SVG charts
│   ├── pages/               Overview, Events, Investigate, Analytics,
│   │                        Fleet, Policies, Alerts
│   └── styles.css           one stylesheet, CSS custom properties
└── package.json
```

**One page per question a security team asks**, which is why the routes are
named for the questions rather than the data: "Live traffic", "Audit log",
"Investigate", not "Events", "Table", "Detail".

**Charts are hand-drawn SVG, not a charting library.** Three reasons: this ships
as part of a security product, so every dependency is one more thing to audit
and patch; the two shapes needed are a stacked bar timeline and a horizontal
bar, about forty lines each; and inline SVG inherits the theme's CSS variables,
so light and dark work without a second theme definition.

**Filters live in the URL.** A search is a link. Half of incident response is
one person pasting a view to another, and a dashboard whose state exists only in
component memory cannot be shared.

---

## `policies/`

```
policies/
├── default.yaml             a sensible starting point, annotated
├── templates/               gdpr.yaml, hipaa.yaml, pci.yaml, agent-safety.yaml
└── rego/keeper.rego         the equivalent policy in Rego, for OPA users
```

Templates are **starting points an organisation adapts**, not compliance
guarantees, and each file says so in its own header rather than relying on this
document to say it.

`rego/` exists to make the OPA support concrete: the same decisions expressed in
Rego, so an organisation evaluating `policy.engine: opa` has a working reference
rather than an interface and a promise.

---

## `deploy/`

```
deploy/
├── docker/     Dockerfile.control-plane, Dockerfile.dashboard,
│               docker-compose.yml, .env.example
└── k8s/        namespace, secrets, deployments, services, ingress,
                network policy, HPA, ServiceMonitor
```

Compose is the "self-hostable in an afternoon" path — `docker compose up` gives
a working control plane, dashboard and Postgres. Kubernetes manifests are plain
YAML rather than a Helm chart, deliberately: a reader can see exactly what is
being applied, and `kustomize` handles the environment differences. A chart is a
reasonable future addition once the manifests stabilise.

---

## `examples/`

Runnable, not illustrative. Each one is a file you can execute:

```
examples/python/       quickstart.py, rag_application.py, agent_with_tools.py,
                       streaming.py, custom_detector.py, fastapi_service.py
examples/typescript/   quickstart.ts, express_service.ts
```

They double as integration smoke tests — CI runs the ones that need no
credentials.

---

## Where the schema is defined, four times

Worth stating explicitly, because it is the thing most likely to drift:

| Component | File | Role |
|---|---|---|
| Python SDK | `keeper_firewall/types.py` | **Source of truth** |
| TypeScript SDK | `src/types.ts` | Mirror; snake_case on the wire |
| Control plane | `api/schemas.py` | Validation; permissive about unknown fields |
| Dashboard | `src/lib/api.ts` | Consumer types |

A change to the audit event schema touches all four in one commit, and CI runs
all four test suites. That is the monorepo earning its keep.
