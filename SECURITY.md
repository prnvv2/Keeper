# Security policy

Keeper is a security product, so its own vulnerabilities matter more than most.
This document covers how to report one, what we consider in scope, and what we
already know is a limitation rather than a bug.

---

## Reporting a vulnerability

**Do not open a public issue.**

Use GitHub's private vulnerability reporting (Security → Report a vulnerability
on this repository), or email **security@keeper-firewall.dev** with the PGP key
published at `https://keeper-firewall.dev/.well-known/security.txt`.

Please include:

- The component and version (SDK Python/TypeScript, control plane, dashboard)
- What an attacker gains, in one sentence
- Reproduction steps, ideally as a failing test
- Any suggested fix

### What to expect

| | |
|---|---|
| Acknowledgement | Within 3 working days |
| Initial assessment | Within 7 working days |
| Fix for critical / high | Target 14 days, coordinated disclosure |
| Fix for medium / low | Next scheduled release |
| Credit | In the release notes and advisory, unless you prefer otherwise |

We will keep you updated even when the answer is slow, and we will tell you if
we disagree that something is a vulnerability rather than going quiet.

---

## In scope

Anything that lets an attacker:

- **Bypass a detector** with input that should have been caught — an evasion in
  `secrets`, `pii`, `prompt_injection`, `token_flow`, or the trust ladder.
- **Escape the authority model** — make low-authority content authorise a
  high-risk action, or raise a value's position on the trust ladder through any
  transformation.
- **Read the audit trail without an admin credential**, or reach an admin
  endpoint with an ingest key.
- **Forge or tamper with audit events**, or cause them to be silently dropped.
- **Extract redacted content** from a stored audit event.
- **Poison policy distribution** — cause an SDK to enforce a policy the control
  plane did not publish, or to enable a detector the operator disabled locally.
- **Escalate within the control plane** — SQL injection, SSRF via a configured
  SIEM or alert target, container escape, path traversal.
- **Denial of service** through a pathological input: catastrophic regex
  backtracking in a detector, unbounded memory growth, a policy that does not
  terminate.

Evasions are genuinely welcome. A detector that can be trivially bypassed is
worse than no detector, because it is trusted. If you have a prompt that gets
past `prompt_injection`, that is a useful report even if it feels mundane.

---

## Out of scope

These are documented limitations, not vulnerabilities. Reporting them is fine;
we will simply point here.

**A hostile first-party application bypassing the SDK.** Keeper runs in the
process it protects. Code in the same process cannot be prevented from
tampering with it. This is the accepted tradeoff of the v1 deployment model and
is discussed at length in
[`architecture.md` §2](docs/architecture.md#2-the-trust-boundary-tradeoff),
with detection-based mitigations. A proxy is the answer for an untrusted
application, and the modules are shaped so one can be added.

**False negatives in probabilistic detection, in general.** A specific,
reproducible evasion is in scope. "An LLM could phrase an attack the regex does
not match" is a known property of heuristic detection, addressed by the
`llm_classifier` escalation path.

**Semantic secret leakage.** `secret_leakage` matches registered values
exactly. A model *describing* a secret rather than quoting it is out of scope
and stated as such in the threat model.

**Groundedness missing a hallucination.** It is a lexical screen. It flags and
never blocks, precisely because it cannot be relied on.

**Tool sandboxing.** `ToolGuard` provides the decision point and a
`sandbox_runner` hook. Real isolation is an OS-level concern covered in
[`deployment.md`](docs/deployment.md#6-hardening). A Python-level fake would be
worse than none, because it would be trusted.

**Attacks requiring an already-compromised control plane or database.** If an
attacker has write access to the policy table, they have write access to your
enforcement configuration, and that is the incident.

**Misconfiguration the startup warnings already flag** — anonymous ingest in
production, the default session secret, dashboard auth disabled. The control
plane says so loudly at startup, in `/health`, and on the dashboard.

---

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |
| < 0.1 | No |

Pre-1.0, security fixes land on the latest minor version only. Once 1.0 ships,
the current and previous minor versions will be supported.

---

## How we secure this project

Because a security product's own supply chain is part of its threat model:

- **Zero required runtime dependencies** in both SDKs. Verified by CI on every
  push, not just asserted in the README — an installed-bare import test and a
  check that `dependencies` stays empty.
- **Dependency audit** (`pip-audit`, `npm audit`) on every push and weekly on a
  schedule, because a dependency clean on Monday is not necessarily clean on
  Friday.
- **Secret scanning** (gitleaks) plus a check that the deliberately
  realistic-looking test fixtures are synthetic — and Keeper's own `secrets`
  detector runs over the documentation, which has caught a real token in a
  docstring before.
- **CodeQL** with the security-extended query set, Python and TypeScript.
- **Container scanning** (Trivy) with results in the security tab, and a CI
  assertion that the control-plane image does not run as root.
- **Signed releases** built from a tagged commit with provenance attestation.
- **Least-privilege CI**: `permissions: contents: read` by default; individual
  jobs widen only where they must.

---

## Hardening your deployment

The short version; the long version is
[`deployment.md` §6](docs/deployment.md#6-hardening).

1. **Never use the same key for ingest and admin.** Ingest keys live in
   hundreds of application processes and in CI. Admin keys read the entire
   audit trail.
2. **Set `KEEPER_REDACTION_SALT`.** Without it, digests do not correlate across
   restarts, which quietly disables cross-application detection.
3. **Choose the redaction mode deliberately.** `hash_only` gives
   cross-application correlation with no content stored anywhere.
4. **Put SSO in front of the dashboard.** Admin API keys are a stopgap.
5. **Apply the shipped Kubernetes manifests as-is** — non-root, read-only root
   filesystem, dropped capabilities, seccomp, default-deny egress.
6. **Alert on `keeper_telemetry_dropped_total` and
   `keeper_cp_siem_failed_batches_total`.** A silently broken audit pipeline
   looks exactly like a quiet week.
7. **Back up the `policies` table.** Write access to it is equivalent to write
   access to every SDK's enforcement configuration.
