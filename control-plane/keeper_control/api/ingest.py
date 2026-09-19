"""The SDK-facing API: telemetry in, policy out, fleet inventory.

Everything here is called by SDK instances, never by humans, and it is on the
critical path of somebody's production application. Three rules follow:

1. **Never block the caller.** Ingest persists the batch and returns. Alert
   evaluation, anomaly analysis and SIEM forwarding happen in background tasks.
   A slow webhook must not turn into latency in a customer's chatbot.
2. **Be generous about what you accept.** A batch with three malformed events
   and forty-seven good ones stores the forty-seven and reports the three. The
   alternative loses an entire application's audit trail over one bad field.
3. **Policy reads must be cheap.** ETag first, body only on change.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, BackgroundTasks, Depends, Header, HTTPException, Response, status

from ..anomaly.detectors import analyse
from ..store.repository import normalise_event, now_ms
from .deps import AppState, get_state, require_ingest_auth
from .schemas import (
    HeartbeatRequest,
    IngestRequest,
    IngestResponse,
    PolicyResponse,
    QuotaRequest,
    QuotaResponse,
    RegisterRequest,
)

log = logging.getLogger("keeper.ingest")
router = APIRouter(prefix="/v1", tags=["sdk"])


@router.post("/telemetry/events", response_model=IngestResponse)
async def ingest_events(
    payload: IngestRequest,
    background: BackgroundTasks,
    state: AppState = Depends(get_state),
    _auth: str = Depends(require_ingest_auth),
) -> IngestResponse:
    """Receive a batch of audit events from one SDK instance."""
    if len(payload.events) > state.settings.max_events_per_batch:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"batch of {len(payload.events)} exceeds the limit of {state.settings.max_events_per_batch}",
        )

    events = [e.model_dump() for e in payload.events]
    accepted, duplicates = state.repo.insert_events(events)
    state.repo.touch_instance(payload.instance_id, accepted)
    state.stats["events_ingested"] += accepted
    state.stats["batches"] += 1

    if state.settings.alerting_enabled and accepted:
        # Alert rules match on the derived fields (detectors_fired,
        # categories), which only exist after normalisation — see
        # keeper_control.store.repository.normalise_event.
        background.add_task(_evaluate_alerts, state, [normalise_event(e) for e in events])

    return IngestResponse(accepted=accepted, duplicates=duplicates)


def _evaluate_alerts(state: AppState, events: list[dict]) -> None:
    """Run match rules on the batch. Never raises into the request."""
    try:
        state.alerts.on_events(events)
    except Exception:
        log.exception("alert evaluation failed")


@router.get("/policies/{bundle}")
async def fetch_policy(
    bundle: str,
    response: Response,
    state: AppState = Depends(get_state),
    if_none_match: str | None = Header(default=None, alias="If-None-Match"),
    _auth: str = Depends(require_ingest_auth),
):
    """Serve the published policy bundle, with ETag revalidation.

    The steady state across a large fleet is a 304 with no body, which is what
    makes a short poll interval affordable — see the pull-vs-push reasoning in
    ``keeper_firewall.policy.loader``.
    """
    record = state.repo.get_published_policy(bundle)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"no published policy for bundle {bundle!r}")

    etag = f'"{record["etag"]}"'
    if if_none_match and if_none_match.strip() in (etag, record["etag"]):
        return Response(status_code=status.HTTP_304_NOT_MODIFIED, headers={"ETag": etag})

    response.headers["ETag"] = etag
    response.headers["Cache-Control"] = "no-cache"
    return PolicyResponse(
        bundle=bundle, version=record["version"], etag=record["etag"], policy=record["document"]
    )


@router.post("/fleet/register", status_code=status.HTTP_202_ACCEPTED)
async def register_instance(
    payload: RegisterRequest,
    state: AppState = Depends(get_state),
    _auth: str = Depends(require_ingest_auth),
) -> dict[str, str]:
    """Announce an SDK instance to the fleet inventory."""
    state.repo.upsert_instance(payload.model_dump())
    return {"status": "registered", "instance_id": payload.instance_id}


@router.post("/fleet/heartbeat", status_code=status.HTTP_202_ACCEPTED)
async def heartbeat(
    payload: HeartbeatRequest,
    state: AppState = Depends(get_state),
    _auth: str = Depends(require_ingest_auth),
) -> dict[str, str]:
    """Liveness plus the SDK's own health snapshot."""
    health = payload.health
    policy = health.get("policy") if isinstance(health.get("policy"), dict) else {}
    snapshot = {
        "instance_id": payload.instance_id,
        "application": payload.application or health.get("application"),
        "environment": health.get("environment"),
        "sdk_version": health.get("sdk_version"),
        "policy_id": policy.get("policy_id"),
        "policy_version": policy.get("policy_version"),
        "detectors": health.get("detectors"),
        "health": health,
    }
    if "monitor_only" in health:
        snapshot["monitor_only"] = bool(health["monitor_only"])
    # Partial: a heartbeat must not erase what registration recorded.
    state.repo.upsert_instance(snapshot, partial=True)
    return {"status": "ok"}


@router.post("/quota/check", response_model=QuotaResponse)
async def check_quota(
    payload: QuotaRequest,
    state: AppState = Depends(get_state),
    _auth: str = Depends(require_ingest_auth),
) -> QuotaResponse:
    """Issue this instance's share of a fleet-wide quota.

    The lease model, and its honest limitation, are described in
    ``keeper_firewall.accesscontrol.ratelimit``: the instance keeps enforcing
    locally and reports consumption; we divide the remaining global budget by
    the number of live instances and hand back a share. Overshoot is bounded by
    one lease window. Anyone who cannot tolerate that should enforce quota at
    their API gateway, synchronously, where the round trip is already paid for.
    """
    policy = state.repo.get_published_policy("default")
    limits = (policy or {}).get("document", {}).get("rate_limits", {})
    limit = limits.get(payload.scope) or limits.get("*") or {"rpm": 120, "burst": 20}

    live = [i for i in state.repo.list_instances() if i["status"] == "healthy"] or [None]
    share = max(1, len(live))
    lease = {
        "rpm": max(1, int(limit.get("rpm", 120)) // share),
        "burst": max(1, int(limit.get("burst", 20)) // share),
    }
    return QuotaResponse(scope=payload.scope, lease=lease, window_s=10)


@router.post("/anomaly/run", include_in_schema=False)
async def run_anomaly_analysis(
    state: AppState = Depends(get_state),
    _auth: str = Depends(require_ingest_auth),
) -> dict[str, object]:
    """Trigger cross-application analysis on demand (the scheduler also runs it)."""
    settings = state.settings
    since = now_ms() - settings.anomaly_window_minutes * 60_000
    findings = analyse(
        state.repo.recent_for_anomaly(since),
        {
            "injection_threshold": settings.anomaly_injection_threshold,
            "cross_app_threshold": settings.anomaly_cross_app_threshold,
            "volume_sigma": settings.anomaly_volume_sigma,
            "instances": state.repo.list_instances(),
        },
    )
    fired = state.alerts.on_anomalies(findings) if settings.alerting_enabled else []
    return {"findings": [f.to_dict() for f in findings], "alerts_fired": len(fired)}
