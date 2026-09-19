# Contributing

Keeper is designed to be extended. New detectors, model backends, SIEM targets
and policy templates all use the same interfaces the built-ins use — there is
no second-class plugin tier, and that is deliberate: a plugin API that is worse
than the internal one produces plugins that are worse than the internals.

---

## Getting set up

```bash
git clone https://github.com/prnvv2/Keeper
cd Keeper
make dev        # installs both SDKs, the control plane, and the dashboard
make test       # runs all four test suites
```

Or by hand:

```bash
python -m venv .venv && . .venv/bin/activate     # .venv\Scripts\activate on Windows
pip install -e "sdk/python[dev]" -e "control-plane[dev]"
cd sdk/typescript && npm install && cd ../..
cd dashboard && npm install && cd ..
```

| Command | What it runs |
|---|---|
| `make test` | Python SDK, TypeScript SDK, control plane, integration |
| `make lint` | ruff + mypy + tsc |
| `make run-control-plane` | SQLite-backed control plane on :8080 |
| `make run-dashboard` | Vite dev server on :5173, proxying to :8080 |
| `make validate-policies` | Every shipped policy through the real parser |

---

## The highest-value contributions

**Detector evasions.** If you have a prompt that gets past
`prompt_injection`, or a credential format `secrets` misses, that is more
valuable than a new feature. Open an issue with the input and the expected
verdict, or better, a failing test.

**New detectors.** Especially for domains we cannot anticipate — sector-specific
PII, regulated phrasing, organisation-specific content policy.

**Model backends.** `Provider` is two methods.

**SIEM targets.** `SIEMExporter` is two methods.

**Policy templates.** If you have adapted Keeper for a regulatory regime and
the result generalises, others would benefit.

---

## Writing a detector

```python
from keeper_firewall import Action, Detector, DetectorInput, Severity, Span, Stage

class MyDetector(Detector):
    name = "my_detector"
    stages = (Stage.INPUT, Stage.OUTPUT)
    category = "content_policy"
    mutates = False

    def detect(self, data: DetectorInput):
        if not self._pattern.search(data.payload):
            return self.clean("nothing found")
        return self.hit(
            score=0.8,
            summary="a sentence a dashboard reader will understand",
            severity=Severity.MEDIUM,
            action=Action.FLAG,
            spans=[...],
            why="the reasoning, in structured form",   # becomes finding.evidence
        )
```

See [`examples/python/custom_detector.py`](examples/python/custom_detector.py)
for a runnable version.

### Rules a detector must follow

1. **Do not raise for "nothing found."** Return a clean `Finding`. Exceptions
   are for genuine failure and trigger the configured fail mode.
2. **Be side-effect free.** Detectors may run twice (escalation) and in any
   order.
3. **Compile regexes once, in `__init__`.** A detector runs on every request;
   the per-request cost should be a match, not a compile.
4. **Put the reasoning in `evidence`.** A finding with no evidence is a black
   box, and a block nobody can review gets the whole control switched off.
5. **Write the `summary` for a human under pressure.** It appears in the
   dashboard at 3am.
6. **Declare `mutates = True` only if `redact()` genuinely works.** The pipeline
   will call it.
7. **Choose an honest default action.** A lexical heuristic should `FLAG`, not
   `BLOCK`. Overreaching costs the user's trust in every other detector too.

### Choosing a fail mode

`fail_mode` decides what happens when *the detector itself* fails, not when it
detects something.

- **Deterministic, local, cheap** → `FAIL_CLOSED`. If it cannot run, we do not
  know, and the cost of a false block is low.
- **Probabilistic or network-bound** → `FAIL_OPEN`. Turning a detection outage
  into a traffic outage is the wrong trade.

---

## Testing

Tests are the specification. Every detector needs both directions:

```python
def test_detects_the_thing():
    assert run("my_detector", "the bad thing").detected

def test_leaves_benign_traffic_alone():        # the important one
    assert not run("my_detector", "a normal request").detected
```

**Negative cases carry more weight than positive ones here.** A firewall that
blocks benign traffic gets turned off, and then it protects nothing. Every
built-in detector has at least as many negative tests as positive.

Name tests for the behaviour, not the function:
`test_consolidation_cannot_launder_authority`, not `test_consolidate_2`.

### Cross-language parity

If you change a detector, the policy format, or the audit schema, change **both
SDKs** and both test suites. The suites deliberately assert the same behaviours;
a verdict that diverges between languages fails a build, and that is the
mechanism keeping the two SDKs one design rather than two.

---

## Code style

Match the surrounding code.

- **Python**: ruff (line length 110), mypy on `keeper_firewall`, dataclasses
  over dicts, `from __future__ import annotations`.
- **TypeScript**: strict mode, no `any` in public signatures, explicit return
  types on exported functions.
- **Comments explain *why*.** The code already says what it does. If a
  threshold is 0.6, the comment should say what made it 0.6. If a design is
  unusual, say what the obvious alternative was and why it lost.
- **Docstrings on modules** should state what the module is for and the one
  design decision a reader would otherwise ask about.

### Dependencies

**The SDKs have zero required runtime dependencies, and CI enforces it.** A pull
request that adds one to `sdk/python` or `sdk/typescript` will fail. If you need
a library, make it an optional extra and degrade cleanly without it — see how
`prometheus_client`, `PyYAML` and OpenTelemetry are handled.

The control plane and dashboard may take dependencies, within reason. They are
services we deploy, not libraries injected into someone else's process.

---

## Pull requests

1. Branch from `main`.
2. One logical change per PR.
3. Tests for anything behavioural, including a negative case.
4. Update the docs when you change behaviour — especially
   [`threat-model.md`](docs/threat-model.md) if you add or change a control.
5. Run `make test lint` before pushing.

A good PR description says what changed, why, and what you considered and
rejected. The last part is the most useful to reviewers and to whoever reads
`git blame` in two years.

### Changes needing discussion first

Open an issue before starting on:

- Anything touching the audit event schema (four components depend on it)
- Changing a default fail mode
- Adding a required dependency to an SDK
- Changing the escalation combination rule

---

## Security

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

Detector evasions are the exception: those are ordinary issues, and we would
rather have them in the open where someone can fix them.

---

## Code of conduct

Be straightforward and be kind. Assume the other person has a reason. Disagree
with the argument, not the person.

## License

Contributions are licensed under Apache 2.0, the same as the project.
