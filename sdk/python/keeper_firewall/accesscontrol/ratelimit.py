"""Rate limiting and quota enforcement.

**The honest problem with SDK-side rate limiting.** A token bucket inside the
application process limits *that process*. Run ten replicas and the tenant gets
ten times the quota; a determined insider who controls the deployment can get
as much as they like. Any claim that an in-process limiter enforces a
fleet-wide quota is false, so we do not make it.

What local limiting *is* good for, and what it is used for here:

* Immediate, zero-latency backpressure on the obvious cases — a runaway loop, a
  single client hammering one instance.
* A floor that keeps working when the control plane is unreachable.

For an actual fleet-wide quota you need shared state, so :class:`RateLimiter`
supports a two-tier arrangement (``distributed=true``):

1. The local bucket runs first and rejects what it can. Free, synchronous.
2. Consumption is reported to the control plane asynchronously, and the control
   plane hands back a *lease*: this instance's share of the remaining global
   quota for the next window. The local bucket is resized to the lease.

That gives near-fleet-wide enforcement without putting a network round trip on
every request. The cost is overshoot bounded by one lease window, which is
stated in ``docs/architecture.md`` rather than papered over. Organisations that
cannot tolerate any overshoot should enforce quota at their API gateway, where
a synchronous check is already being paid for.
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Mapping

from ..errors import RateLimitError
from ..types import Principal


@dataclass(slots=True)
class Quota:
    """A limit expressed as a sustained rate plus a burst allowance."""

    rpm: int = 60
    burst: int = 10
    #: Optional token budget per minute, checked separately from request count.
    tokens_per_minute: int | None = None

    @property
    def refill_per_second(self) -> float:
        return self.rpm / 60.0

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "Quota":
        return cls(
            rpm=int(data.get("rpm", 60)),
            burst=int(data.get("burst", max(1, int(data.get("rpm", 60)) // 6))),
            tokens_per_minute=data.get("tokens_per_minute"),
        )


@dataclass(slots=True)
class Bucket:
    """A token bucket. Not thread safe on its own; the limiter holds the lock."""

    capacity: float
    tokens: float
    refill_per_second: float
    updated: float = field(default_factory=time.monotonic)

    def take(self, amount: float = 1.0, now: float | None = None) -> tuple[bool, float]:
        """Try to consume. Returns ``(allowed, retry_after_seconds)``."""
        now = now if now is not None else time.monotonic()
        elapsed = max(0.0, now - self.updated)
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_per_second)
        self.updated = now
        if self.tokens >= amount:
            self.tokens -= amount
            return True, 0.0
        deficit = amount - self.tokens
        retry = deficit / self.refill_per_second if self.refill_per_second > 0 else float("inf")
        return False, retry

    def resize(self, capacity: float, refill_per_second: float) -> None:
        self.capacity = capacity
        self.tokens = min(self.tokens, capacity)
        self.refill_per_second = refill_per_second


class RateLimiter:
    """Multi-scope token-bucket limiter with optional distributed leases."""

    def __init__(
        self,
        *,
        default: Quota | None = None,
        quotas: Mapping[str, Quota] | None = None,
        distributed: bool = False,
        lease_client: Callable[[str, int], Mapping[str, Any]] | None = None,
        lease_interval_s: float = 10.0,
        max_buckets: int = 10_000,
    ) -> None:
        self.default = default or Quota()
        # Scope key -> quota. Keys are "role:<name>", "tenant:<id>",
        # "principal:<id>", "model:<name>", or "*".
        self.quotas: dict[str, Quota] = dict(quotas or {})
        self.distributed = distributed
        self.lease_client = lease_client
        self.lease_interval_s = lease_interval_s
        self.max_buckets = max_buckets

        self._buckets: dict[str, Bucket] = {}
        self._consumed: dict[str, int] = {}
        self._leases: dict[str, tuple[float, Quota]] = {}
        self._lock = threading.Lock()

    # -- configuration -----------------------------------------------------

    def apply_policy(self, rate_limits: Mapping[str, Mapping[str, Any]]) -> None:
        """Adopt limits distributed by the control plane in a policy bundle."""
        parsed = {scope: Quota.from_dict(spec) for scope, spec in rate_limits.items()}
        with self._lock:
            self.quotas = parsed
            if "*" in parsed:
                self.default = parsed["*"]
            # Resize live buckets so a tightened quota takes effect at once
            # rather than after the old bucket drains.
            for key, bucket in self._buckets.items():
                quota = self._quota_for_key(key)
                bucket.resize(float(quota.burst), quota.refill_per_second)

    def _quota_for_key(self, key: str) -> Quota:
        return self.quotas.get(key, self.default)

    # -- enforcement -------------------------------------------------------

    def scopes_for(self, principal: Principal, model: str | None = None) -> list[str]:
        """Every scope a request is charged against, narrowest first."""
        scopes = [f"principal:{principal.id}"]
        if principal.tenant:
            scopes.append(f"tenant:{principal.tenant}")
        for role in principal.roles:
            scopes.append(f"role:{role}")
        if model:
            scopes.append(f"model:{model}")
        scopes.append("*")
        # Only scopes with a configured quota (or the catch-all) are charged;
        # otherwise every distinct principal id would allocate a bucket.
        return [s for s in scopes if s in self.quotas or s == "*"]

    def check(self, principal: Principal, *, model: str | None = None, cost: float = 1.0) -> None:
        """Charge the request against every applicable scope, or raise."""
        now = time.monotonic()
        with self._lock:
            scopes = self.scopes_for(principal, model)
            charged: list[str] = []
            for scope in scopes:
                bucket = self._bucket(scope)
                allowed, retry = bucket.take(cost, now)
                if allowed:
                    charged.append(scope)
                    self._consumed[scope] = self._consumed.get(scope, 0) + int(cost)
                    continue
                # Refund the scopes we already charged: a rejected request must
                # not consume quota it never used.
                for done in charged:
                    self._buckets[done].tokens += cost
                    self._consumed[done] = max(0, self._consumed.get(done, 0) - int(cost))
                raise RateLimitError(
                    f"rate limit exceeded for {scope} "
                    f"({self._quota_for_key(scope).rpm} rpm, retry in {retry:.1f}s)",
                    retry_after=retry,
                    scope=scope,
                )
        if self.distributed:
            self._maybe_renew_leases()

    def _bucket(self, scope: str) -> Bucket:
        bucket = self._buckets.get(scope)
        if bucket is None:
            if len(self._buckets) >= self.max_buckets:
                # Bounded memory: evict the least recently touched bucket. An
                # unbounded dict keyed by principal id is a denial-of-service
                # vector against the limiter itself.
                oldest = min(self._buckets, key=lambda k: self._buckets[k].updated)
                del self._buckets[oldest]
                self._consumed.pop(oldest, None)
            quota = self._quota_for_key(scope)
            bucket = Bucket(
                capacity=float(quota.burst),
                tokens=float(quota.burst),
                refill_per_second=quota.refill_per_second,
            )
            self._buckets[scope] = bucket
        return bucket

    # -- distributed leases ------------------------------------------------

    def _maybe_renew_leases(self) -> None:
        if self.lease_client is None:
            return
        now = time.monotonic()
        with self._lock:
            due = [
                scope
                for scope in self._buckets
                if now - self._leases.get(scope, (0.0, self.default))[0] >= self.lease_interval_s
            ]
            consumed = {scope: self._consumed.get(scope, 0) for scope in due}
        for scope in due:
            try:
                response = self.lease_client(scope, consumed[scope])
            except Exception:  # noqa: BLE001 - lease failure falls back to local
                # Fail to the *local* quota, not to unlimited: an unreachable
                # control plane must not raise anyone's limit.
                with self._lock:
                    self._leases[scope] = (now, self._quota_for_key(scope))
                continue
            quota = Quota.from_dict(response.get("lease") or {})
            with self._lock:
                self._leases[scope] = (now, quota)
                self._consumed[scope] = 0
                bucket = self._buckets.get(scope)
                if bucket is not None:
                    bucket.resize(float(quota.burst), quota.refill_per_second)

    # -- introspection -----------------------------------------------------

    def state(self) -> dict[str, Any]:
        with self._lock:
            return {
                "distributed": self.distributed,
                "scopes": len(self._buckets),
                "buckets": {
                    scope: {
                        "tokens": round(bucket.tokens, 2),
                        "capacity": bucket.capacity,
                        "rpm": round(bucket.refill_per_second * 60),
                    }
                    for scope, bucket in list(self._buckets.items())[:50]
                },
            }

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()
            self._consumed.clear()
            self._leases.clear()
