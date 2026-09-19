# Keeper — live motion visualization

A self-contained, animated diagram of the Keeper architecture: synthetic
requests flow through the SDK pipeline, get evaluated by detectors, and
their audit events stream into the control plane in real time on screen.

**This is illustrative, not connected to a real Keeper instance.** Every
number and event you see is generated locally by `index.html`'s own
simulation loop — it exists to make the request lifecycle in
[`docs/architecture.md`](../docs/architecture.md) legible at a glance, not
to report on real traffic. The header and footer say so on screen too.

## Open it

No build step, no server, no dependencies. Just open the file:

```
visualization/index.html
```

double-click it, or open it in a browser directly from disk.

## What's shown

- **The SDK pipeline** (top box): Access control → input filters
  (`secrets`, `pii`, `prompt_injection`, `authority_claim`, `trajectory`) →
  model call → output filters (`secret_leakage`, `pii`, `banned_topics`,
  `groundedness`) → reply back to the app.
- **Boundary awareness**: roughly a fifth of requests are tagged as
  originating from a retrieved document or tool result (dashed ring) rather
  than the user — and are scored more harshly at the input filter, the same
  trust-multiplier behavior the real `prompt_injection` detector implements.
- **Every decision — allow, flag, redact, block — spawns an audit event**
  (small dot) that travels down to the local sink/queue regardless of
  outcome, then ships asynchronously to the control plane, exactly as
  described in `docs/architecture.md` §4–5: nothing on the animated
  "request" path ever waits on that shipment.
- **The control plane** (bottom box): ingest → audit store → dashboard,
  alerts, SIEM export, fleet inventory, with an occasional cross-application
  anomaly pulse.
- Colors match the dashboard's own action palette (`dashboard/src/styles.css`):
  green = allow, amber = flag, violet = redact, red = block.

Click **Pause new traffic** to stop new spawns and let in-flight particles
finish, useful for reading the live feed on the right without it scrolling
out from under you.
