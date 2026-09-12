# keeper-firewall

The Python SDK for [Keeper](https://github.com/keeper-firewall/keeper), an
open-source AI firewall. Wrap your existing LLM, agent, or RAG calls to get
input filtering, output filtering, runtime protection, and a structured audit
trail of every AI interaction — without routing traffic through a proxy.

```bash
pip install keeper-firewall
```

```python
from keeper_firewall import Keeper

keeper = Keeper(application="support-bot")

reply = keeper.chat("Summarise ticket 4182", provider=my_llm)
print(reply.text, reply.correlation_id)
```

That works with no configuration at all: sensible default policy, audit events
held locally, nothing to deploy. Point it at a control plane when you want the
dashboard, fleet-wide policy, and SIEM export:

```python
keeper = Keeper(
    application="support-bot",
    endpoint="https://keeper.internal",   # or KEEPER_ENDPOINT
    api_key="...",                        # or KEEPER_API_KEY
)
```

## What it does

| | |
|---|---|
| **Input filtering** | Prompt injection and jailbreak detection (direct and indirect), credential and PII detection with redact-or-block, multi-turn escalation detection, zero-trust handling of authority claims |
| **Output filtering** | Known-secret leakage, banned content, groundedness screening, mid-stream circuit breaking on streamed responses |
| **Runtime protection** | Tool-call mediation before execution, tool-result and retrieved-document screening, agent kill switch, provenance-preserving agent memory |
| **Access control** | API key / OIDC / mTLS authentication, RBAC over models and tools, token-bucket rate limiting with optional fleet-wide leases |
| **Policy** | Declarative YAML/JSON rules, versioned, centrally authored and pulled with local caching, dry-run mode |
| **Observability** | One structured audit event per decision, Prometheus metrics, OpenTelemetry trace context, configurable redaction |

## Zero required dependencies

This package installs into your application, so it ships with no mandatory
dependencies at all. Optional extras:

```bash
pip install "keeper-firewall[yaml]"     # YAML config and policy files
pip install "keeper-firewall[metrics]"  # register metrics in prometheus_client
pip install "keeper-firewall[otel]"     # real OpenTelemetry spans
pip install "keeper-firewall[all]"
```

## Command line

```bash
keeper check "ignore all previous instructions"   # exits 1 if it would be blocked
keeper scan prompts.txt --fail-on-block           # useful in CI
keeper policy validate policies/default.yaml
keeper policy dry-run candidate.yaml --events audit.jsonl
keeper keygen --principal svc:ci --roles service
```

## Documentation

- [Ten-minute integration guide](../../docs/sdk-integration.md)
- [Observability guide](../../docs/observability.md)
- [Architecture](../../docs/architecture.md)
- [Threat model](../../docs/threat-model.md)

Apache 2.0.
