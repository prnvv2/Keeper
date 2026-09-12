"""Policy distribution: central authoring, distributed enforcement.

**Pull, not push.** The control plane is the authoring and versioning system;
SDK instances poll it on an interval with an ETag and cache the result. Push
over a persistent connection would propagate faster, but it inverts the
dependency: every SDK instance would hold an open connection to the control
plane, and a control-plane restart would become a fleet-wide event. Pull keeps
the data plane's failure domain strictly smaller than the control plane's,
which is the property that lets us promise the firewall keeps working when the
dashboard is down. ETags make the steady-state poll a 304 with no body, so the
cost of a 60-second interval across a large fleet stays trivial.

The consequence is a propagation delay bounded by ``refresh_interval_s``.
That is stated plainly in ``docs/architecture.md`` rather than hidden: if you
need a policy change live in under a second, you are asking for push, and the
provider interface here is shaped so a pushing implementation slots in without
touching the pipeline.

**When the control plane is unreachable** the behaviour is configured, not
assumed — see ``policy.unreachable_behavior``:

``last_known_good`` (default)
    Keep enforcing the last policy we successfully fetched, until
    ``max_staleness_s``. After that, fall back to the safe default and flag it
    loudly, because silently enforcing a week-old policy is its own incident.

``safe_default``
    Drop straight to the built-in minimal policy.

``fail_open``
    Disable policy enforcement entirely. Detectors still run and still emit
    audit events; only the policy layer stops acting. For teams whose risk
    tolerance puts availability first, and it must be an explicit choice.
"""

from __future__ import annotations

import json
import os
import threading
import time
from typing import Any, Callable, Mapping

from ..config import PolicyConfig
from ..errors import PolicyError, TransportError
from ..types import now_ms
from .engine import PolicyEngine, build_engine
from .models import SAFE_DEFAULT_POLICY, Policy


def load_policy_document(path: str) -> dict[str, Any]:
    """Read a policy document from a YAML or JSON file."""
    if not os.path.exists(path):
        raise PolicyError(f"policy file not found: {path}")
    with open(path, "r", encoding="utf-8") as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as exc:  # pragma: no cover - env dependent
            raise PolicyError(
                "YAML policies require PyYAML; install keeper-firewall[yaml] or use JSON"
            ) from exc
        return yaml.safe_load(text) or {}
    return json.loads(text or "{}")


def safe_default_policy() -> Policy:
    return Policy.from_dict(SAFE_DEFAULT_POLICY, source="builtin")


class PolicyProvider:
    """Owns the active policy and keeps it fresh.

    Thread-safe: the refresh thread swaps a whole engine object under a lock,
    and readers take the current engine reference once. A request never sees a
    half-updated policy.
    """

    def __init__(
        self,
        config: PolicyConfig,
        *,
        client: Any = None,
        on_change: Callable[[Policy], None] | None = None,
        on_error: Callable[[BaseException], None] | None = None,
    ) -> None:
        self.config = config
        self.client = client
        self.on_change = on_change
        self.on_error = on_error

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._etag: str | None = None
        self._last_success_ms: int | None = None
        self._last_error: str | None = None
        self._degraded: str | None = None
        self._refreshes = 0

        policy = self._initial_policy()
        self._engine: PolicyEngine = build_engine(
            policy, engine=config.engine, opa_url=config.opa_url, dry_run=config.dry_run
        )

        if config.source == "control_plane" and self.client is not None:
            self._start_refresh()

    # -- accessors ---------------------------------------------------------

    @property
    def engine(self) -> PolicyEngine:
        with self._lock:
            return self._engine

    @property
    def policy(self) -> Policy:
        return self.engine.policy

    @property
    def degraded(self) -> str | None:
        """Non-None when the active policy is not the intended one."""
        with self._lock:
            return self._degraded

    def health(self) -> dict[str, Any]:
        with self._lock:
            policy = self._engine.policy
            age_s = (now_ms() - self._last_success_ms) / 1000 if self._last_success_ms else None
            return {
                "source": self.config.source,
                "policy_id": policy.id,
                "policy_version": policy.version,
                "rules": len(policy.rules),
                "dry_run": self.config.dry_run,
                "etag": self._etag,
                "age_seconds": age_s,
                "refreshes": self._refreshes,
                "degraded": self._degraded,
                "last_error": self._last_error,
            }

    # -- loading -----------------------------------------------------------

    def _initial_policy(self) -> Policy:
        if self.config.source == "local":
            if not self.config.path:
                return safe_default_policy()
            policy = Policy.from_dict(load_policy_document(self.config.path), source=self.config.path)
            policy.loaded_at_ms = now_ms()
            self._last_success_ms = policy.loaded_at_ms
            return policy

        # control_plane: try once synchronously so a correctly configured app
        # starts with the right policy rather than a fallback it then swaps.
        try:
            policy = self._fetch()
            if policy is not None:
                return policy
        except Exception as exc:  # noqa: BLE001 - startup must not hard-fail
            self._last_error = str(exc)
            if self.on_error:
                self.on_error(exc)
        self._degraded = "control plane unreachable at startup; using safe default policy"
        return safe_default_policy()

    def _fetch(self) -> Policy | None:
        """Fetch the bundle. Returns None on 304 (unchanged)."""
        if self.client is None:
            raise PolicyError("policy.source='control_plane' requires a control plane client")
        response = self.client.fetch_policy(self.config.bundle, self._etag)
        if response.status == 304:
            self._last_success_ms = now_ms()
            return None
        if not response.ok:
            raise TransportError(f"policy fetch returned HTTP {response.status}")
        body = response.json() or {}
        document = body.get("policy", body)
        policy = Policy.from_dict(document, source=f"control-plane:{self.config.bundle}")
        policy.etag = response.headers.get("ETag") or body.get("etag")
        policy.loaded_at_ms = now_ms()
        self._etag = policy.etag
        self._last_success_ms = policy.loaded_at_ms
        return policy

    # -- refresh loop ------------------------------------------------------

    def _start_refresh(self) -> None:
        self._thread = threading.Thread(target=self._run, name="keeper-policy", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        while not self._stop.wait(self.config.refresh_interval_s):
            self.refresh()

    def refresh(self) -> bool:
        """Fetch once. Returns True if the active policy changed."""
        try:
            policy = self._fetch()
        except Exception as exc:  # noqa: BLE001 - refresh failure is handled, not fatal
            self._last_error = str(exc)
            if self.on_error:
                self.on_error(exc)
            self._apply_unreachable_behavior()
            return False

        with self._lock:
            self._refreshes += 1
            self._degraded = None
        if policy is None:
            return False

        engine = build_engine(
            policy,
            engine=self.config.engine,
            opa_url=self.config.opa_url,
            dry_run=self.config.dry_run,
        )
        with self._lock:
            previous = self._engine.policy.ref
            self._engine = engine
        if self.on_change and previous != policy.ref:
            self.on_change(policy)
        return previous != policy.ref

    def _apply_unreachable_behavior(self) -> None:
        behavior = self.config.unreachable_behavior
        age_s = (now_ms() - self._last_success_ms) / 1000 if self._last_success_ms else float("inf")

        if behavior == "last_known_good" and age_s <= self.config.max_staleness_s:
            with self._lock:
                self._degraded = (
                    f"control plane unreachable; enforcing last-known-good policy "
                    f"({age_s:.0f}s old, limit {self.config.max_staleness_s}s)"
                )
            return

        if behavior == "fail_open":
            with self._lock:
                if self._engine.policy.id != "keeper.disabled":
                    self._engine = build_engine(
                        Policy(id="keeper.disabled", version="0", description="policy enforcement disabled"),
                        engine="embedded",
                    )
                self._degraded = "control plane unreachable; policy enforcement disabled (fail_open)"
            return

        with self._lock:
            if self._engine.policy.id != "keeper.safe-default":
                self._engine = build_engine(safe_default_policy(), engine="embedded")
            reason = (
                f"policy stale for {age_s:.0f}s (limit {self.config.max_staleness_s}s)"
                if behavior == "last_known_good"
                else "control plane unreachable"
            )
            self._degraded = f"{reason}; enforcing safe default policy"

    def set_policy(self, policy: Policy) -> None:
        """Replace the active policy. Used by tests and by local hot-reload."""
        engine = build_engine(
            policy, engine=self.config.engine, opa_url=self.config.opa_url, dry_run=self.config.dry_run
        )
        with self._lock:
            self._engine = engine
            self._degraded = None
            self._last_success_ms = now_ms()

    def close(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread and thread.is_alive():
            thread.join(timeout=1.0)


def dry_run_report(policy: Policy, events: list[Mapping[str, Any]]) -> dict[str, Any]:
    """Replay historical audit events against a candidate policy.

    This is what makes ``policy.dry_run`` more than a config flag: the control
    plane ships a candidate bundle, an operator replays the last N thousand
    audit events through it, and sees exactly which requests would have changed
    outcome before anything is enforced.
    """
    from .engine import EmbeddedEngine

    engine = EmbeddedEngine(policy)
    changes: list[dict[str, Any]] = []
    counts: dict[str, int] = {}
    for event in events:
        facts = {
            "stage": event.get("stage"),
            "environment": event.get("environment"),
            "application": event.get("application"),
            "model": event.get("model"),
            "provider": event.get("provider"),
            "tenant": event.get("tenant"),
            "principal_id": event.get("principal_id"),
            "roles": event.get("principal_roles") or [],
            "authenticated": bool(event.get("principal_id")),
            "trust": (event.get("tags") or {}).get("trust", "user"),
            "tool": (event.get("tags") or {}).get("tool"),
            "detectors_fired": [f["detector"] for f in event.get("findings", []) if f.get("detected")],
            "categories": sorted({f["category"] for f in event.get("findings", []) if f.get("detected")}),
            "labels": sorted(
                {s["label"] for f in event.get("findings", []) if f.get("detected") for s in f.get("spans", [])}
            ),
            "severity": event.get("severity", "info"),
            "max_score": max((f.get("score", 0.0) for f in event.get("findings", [])), default=0.0),
            "tags": event.get("tags") or {},
            "payload": None,
            "turn_count": 0,
        }
        traces = engine.evaluate(facts)
        new_action = max(
            (t.action for t in traces if t.matched),
            key=lambda a: a.severity(),
            default=None,
        )
        new_value = new_action.value if new_action else "allow"
        old_value = event.get("action", "allow")
        counts[f"{old_value}->{new_value}"] = counts.get(f"{old_value}->{new_value}", 0) + 1
        if new_value != old_value:
            changes.append(
                {
                    "event_id": event.get("event_id"),
                    "correlation_id": event.get("correlation_id"),
                    "from": old_value,
                    "to": new_value,
                    "rules": [t.rule_id for t in traces if t.matched],
                }
            )
    return {
        "policy": policy.ref,
        "events_replayed": len(events),
        "changed": len(changes),
        "transitions": counts,
        "examples": changes[:50],
    }
