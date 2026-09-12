# keeper-firewall (TypeScript)

The TypeScript/Node SDK for [Keeper](https://github.com/keeper-firewall/keeper),
an open-source AI firewall. Wrap your existing LLM, agent, or RAG calls to get
input filtering, output filtering, runtime protection, and a structured audit
trail of every AI interaction — without routing traffic through a proxy.

```bash
npm install keeper-firewall
```

```ts
import { Keeper } from "keeper-firewall";

const keeper = new Keeper({ application: "support-bot" });

const reply = await keeper.chat("Summarise ticket 4182");
console.log(reply.text, reply.correlationId);
```

That works with no configuration at all. Point it at a control plane when you
want the dashboard, fleet-wide policy, and SIEM export:

```ts
const keeper = new Keeper({
  application: "support-bot",
  telemetry: { endpoint: "https://keeper.internal", apiKey: process.env.KEEPER_API_KEY },
  policy: { source: "control_plane", bundle: "default" },
});
```

## Wrapping an existing call

The least invasive integration keeps your provider SDK, retry policy and
parameters exactly as they are:

```ts
const guarded = keeper.wrap(async (messages) => {
  const completion = await openai.chat.completions.create({ model: "gpt-4o-mini", messages });
  return completion.choices[0].message.content ?? "";
});

const reply = await guarded("Summarise ticket 4182");
```

## Parity with the Python SDK

The two SDKs are ports of one design, not two designs sharing a name. The audit
event schema, the action and trust ladders, the escalation combination rule and
the policy document format are identical by construction — the control plane
cannot tell which language produced an event, and the same published policy
bundle loads in both. The test suites assert the same behaviours in both
languages, so a detector whose verdict diverges fails a build.

Python is the reference implementation and carries two extra pieces: the
`llm_classifier` escalation detector and the `keeper` CLI. Everything in
Section 2 of the design — input filtering, output filtering, access control,
observability, runtime protection, policy — is present in both.

## Zero dependencies

Nothing at runtime. `fetch`, `crypto.getRandomValues` and `performance.now` are
all standard in Node 18+, Deno, Bun and the browser. This package is installed
into other people's applications, so every dependency we add is one they have
to audit and patch too.

## Documentation

- [Ten-minute integration guide](../../docs/sdk-integration.md)
- [Observability guide](../../docs/observability.md)
- [Architecture](../../docs/architecture.md)
- [Threat model](../../docs/threat-model.md)

Apache 2.0.
