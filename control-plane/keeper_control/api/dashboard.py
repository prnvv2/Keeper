"""The human-facing API: investigation, analytics, policy, alerts.

This is the AI-native SIEM view. Every endpoint here requires admin
authentication, because collectively they expose the full audit trail.

The endpoints map one-to-one onto the questions a security team asks:

* "What is happening right now?" -> ``/overview``, ``/timeline``
* "What happened to this request?" -> ``/events/correlation/{id}``
* "Show me everything matching..." -> ``/events``
* "Which controls are earning their keep?" -> ``/analytics/detectors``,
  ``/analytics/policy``
* "What is running out there?" -> ``/fleet``
* "What should I change?" -> ``/policies`` + ``/policies/dry-run``
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Body, Depends, HTTPException, Query, status

from ..anomaly.detectors import analyse
from ..store.repository import EventQuery, now_ms
from .deps import AppState, get_state, require_admin_auth
from .schemas import AlertRuleModel, EventPage, PolicyDryRunRequest, PolicyPublishRequest

router = APIRouter(prefix="/api", tags=["dashboard"], dependencies=[Depends(require_admin_auth)])


def _window_ms(hours: float) -> int:
    return now_ms() - int(hours * 3_600_000)


# --- live picture ----------------------------------------------------------


@router.get("/overview")
async def overview(
    hours: float = Query(24, ge=0.01, le=24 * 90),
    environment: str | None = None,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    """Everything the landing page needs, in one round trip."""
    since = _window_ms(hours)
    data = state.repo.overview(since, environment=environment)
    data["top_offenders"] = state.repo.top_offenders(since)
    data["recent_alerts"] = state.repo.list_alerts(limit=5)
    data["window_hours"] = hours
    return data


@router.get("/timeline")
async def timeline(
    hours: float = Query(6, ge=0.01, le=24 * 30),
    bucket_minutes: int = Query(1, ge=1, le=60),
    application: str | None = None,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    return {
        "buckets": state.repo.timeline(_window_ms(hours), bucket_minutes=bucket_minutes, application=application),
        "bucket_minutes": bucket_minutes,
    }


# --- investigation ---------------------------------------------------------


@router.get("/events", response_model=EventPage)
async def search_events(
    hours: float | None = Query(None, ge=0.01, le=24 * 365),
    since_ms: int | None = None,
    until_ms: int | None = None,
    application: str | None = None,
    environment: str | None = None,
    action: str | None = None,
    severity: str | None = None,
    min_severity: str | None = None,
    stage: str | None = None,
    principal_id: str | None = None,
    tenant: str | None = None,
    correlation_id: str | None = None,
    trace_id: str | None = None,
    detector: str | None = None,
    category: str | None = None,
    model: str | None = None,
    q: str | None = Query(None, description="free-text search over prompt, response, and finding summaries"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    state: AppState = Depends(get_state),
) -> EventPage:
    """Structured and free-text search over the aggregated audit trail."""
    events, total = state.repo.search_events(
        EventQuery(
            since_ms=since_ms if since_ms is not None else (_window_ms(hours) if hours else None),
            until_ms=until_ms,
            application=application,
            environment=environment,
            action=action,
            severity=severity,
            min_severity=min_severity,
            stage=stage,
            principal_id=principal_id,
            tenant=tenant,
            correlation_id=correlation_id,
            trace_id=trace_id,
            detector=detector,
            category=category,
            model=model,
            search=q,
            limit=limit,
            offset=offset,
        )
    )
    return EventPage(events=events, total=total, limit=limit, offset=offset)


@router.get("/events/{event_id}")
async def get_event(event_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    event = state.repo.get_event(event_id)
    if event is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "event not found")
    return event


@router.get("/events/correlation/{correlation_id}")
async def get_correlation(correlation_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Reconstruct a whole interaction: input, tools, retrieval, output.

    This is the endpoint that turns a single flagged event into an incident
    narrative — every stage of the request, in order, with the decision and
    evidence at each one.
    """
    events = state.repo.get_correlation(correlation_id)
    if not events:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "no events for that correlation id")
    first, last = events[0], events[-1]
    return {
        "correlation_id": correlation_id,
        "events": events,
        "summary": {
            "application": first["application"],
            "principal_id": first["principal_id"],
            "session_id": first["session_id"],
            "model": first["model"],
            "trace_id": first["trace_id"],
            "policy_version": first["policy_version"],
            "started_ms": first["timestamp_ms"],
            "ended_ms": last["timestamp_ms"],
            "duration_ms": last["timestamp_ms"] - first["timestamp_ms"],
            "stages": [e["stage"] for e in events],
            "outcome": max(
                (e["action"] for e in events),
                key=lambda a: {"allow": 0, "flag": 1, "redact": 2, "challenge": 3, "block": 4}.get(a, 0),
            ),
            "detectors_fired": sorted({d for e in events for d in (e["detectors_fired"] or [])}),
        },
    }


# --- analytics -------------------------------------------------------------


@router.get("/analytics/detectors")
async def detector_analytics(
    hours: float = Query(24, ge=0.01, le=24 * 90), state: AppState = Depends(get_state)
) -> dict[str, Any]:
    """Hit rate, latency and error rate per detector.

    The view that answers "is this detector worth its latency?" and "did that
    threshold change actually do anything?".
    """
    return {"detectors": state.repo.detector_stats(_window_ms(hours)), "window_hours": hours}


@router.get("/analytics/policy")
async def policy_analytics(
    hours: float = Query(24, ge=0.01, le=24 * 90), state: AppState = Depends(get_state)
) -> dict[str, Any]:
    """Which policy rules fire, how often, and how long they take."""
    return {"rules": state.repo.policy_stats(_window_ms(hours)), "window_hours": hours}


@router.get("/analytics/anomalies")
async def anomalies(
    minutes: int = Query(15, ge=1, le=24 * 60), state: AppState = Depends(get_state)
) -> dict[str, Any]:
    settings = state.settings
    findings = analyse(
        state.repo.recent_for_anomaly(now_ms() - minutes * 60_000),
        {
            "injection_threshold": settings.anomaly_injection_threshold,
            "cross_app_threshold": settings.anomaly_cross_app_threshold,
            "volume_sigma": settings.anomaly_volume_sigma,
            "instances": state.repo.list_instances(),
        },
    )
    return {"findings": [f.to_dict() for f in findings], "window_minutes": minutes}


# --- fleet -----------------------------------------------------------------


@router.get("/fleet")
async def fleet(state: AppState = Depends(get_state)) -> dict[str, Any]:
    """Which applications run the SDK, on what version, with what policy."""
    instances = state.repo.list_instances()
    versions: dict[str, int] = {}
    policy_versions: dict[str, int] = {}
    for instance in instances:
        versions[instance["sdk_version"] or "unknown"] = versions.get(instance["sdk_version"] or "unknown", 0) + 1
        key = f"{instance['policy_id']}@{instance['policy_version']}"
        policy_versions[key] = policy_versions.get(key, 0) + 1
    return {
        "instances": instances,
        "total": len(instances),
        "healthy": sum(1 for i in instances if i["status"] == "healthy"),
        "stale": sum(1 for i in instances if i["status"] == "stale"),
        "sdk_versions": versions,
        "policy_versions": policy_versions,
        "monitor_only": [i["instance_id"] for i in instances if i["monitor_only"]],
    }


# --- policy management -----------------------------------------------------


@router.get("/policies")
async def list_policies(bundle: str | None = None, state: AppState = Depends(get_state)) -> dict[str, Any]:
    return {"policies": state.repo.list_policies(bundle)}


@router.get("/policies/{bundle}/{version}")
async def get_policy_version(bundle: str, version: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    record = state.repo.get_policy_version(bundle, version)
    if record is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "policy version not found")
    return record


@router.post("/policies", status_code=status.HTTP_201_CREATED)
async def publish_policy(
    payload: PolicyPublishRequest,
    state: AppState = Depends(get_state),
    who: str = Depends(require_admin_auth),
) -> dict[str, Any]:
    """Validate and store a policy bundle, optionally publishing it.

    Validation uses the SDK's own parser, so a bundle that publishes here is a
    bundle that will load in every SDK instance. Rejecting it at publish time
    is the only place the error is cheap; rejecting it at pull time would leave
    a fleet enforcing a stale policy and logging errors.
    """
    try:
        from keeper_firewall.policy.models import Policy

        Policy.from_dict(payload.policy, source="control-plane")
    except Exception as exc:  # noqa: BLE001 - surfaced to the author
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid policy: {exc}") from exc

    try:
        record = state.repo.save_policy(
            payload.bundle, payload.policy, published=payload.publish, created_by=who, note=payload.note
        )
    except ValueError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from exc
    return {"status": "published" if payload.publish else "saved", "policy": record}


@router.post("/policies/dry-run")
async def dry_run_policy(
    payload: PolicyDryRunRequest, state: AppState = Depends(get_state)
) -> dict[str, Any]:
    """Replay recent traffic against a candidate policy.

    The answer to "what would this change actually do?", computed against real
    historical events rather than someone's intuition.
    """
    from keeper_firewall.policy.loader import dry_run_report
    from keeper_firewall.policy.models import Policy

    try:
        policy = Policy.from_dict(payload.policy, source="dry-run")
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"invalid policy: {exc}") from exc

    events, _total = state.repo.search_events(
        EventQuery(since_ms=_window_ms(payload.hours), limit=min(payload.limit, 20_000))
    )
    return dry_run_report(policy, events)


# --- alerts ----------------------------------------------------------------


@router.get("/alerts")
async def list_alerts(
    limit: int = Query(100, ge=1, le=500),
    unacknowledged_only: bool = False,
    state: AppState = Depends(get_state),
) -> dict[str, Any]:
    return {"alerts": state.repo.list_alerts(limit=limit, unacknowledged_only=unacknowledged_only)}


@router.post("/alerts/{alert_id}/acknowledge")
async def acknowledge(
    alert_id: str, state: AppState = Depends(get_state), who: str = Depends(require_admin_auth)
) -> dict[str, Any]:
    if not state.repo.acknowledge_alert(alert_id, who):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "alert not found or already acknowledged")
    return {"status": "acknowledged", "alert_id": alert_id}


@router.get("/alert-rules")
async def list_alert_rules(state: AppState = Depends(get_state)) -> dict[str, Any]:
    return {"rules": state.repo.list_alert_rules()}


@router.put("/alert-rules")
async def upsert_alert_rule(rule: AlertRuleModel, state: AppState = Depends(get_state)) -> dict[str, Any]:
    return {"rule": state.repo.save_alert_rule(rule.model_dump())}


@router.delete("/alert-rules/{rule_id}")
async def delete_alert_rule(rule_id: str, state: AppState = Depends(get_state)) -> dict[str, Any]:
    if not state.repo.delete_alert_rule(rule_id):
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    return {"status": "deleted"}


@router.post("/alerts/test")
async def test_alert_delivery(
    channels: list[str] = Body(default=["log"], embed=True), state: AppState = Depends(get_state)
) -> dict[str, Any]:
    """Send a test alert. Verifying the channel works *before* an incident."""
    alert = {
        "id": "test",
        "title": "Keeper test alert",
        "description": "Delivery test triggered from the dashboard. No action needed.",
        "severity": "info",
        "context": {"entities": {"source": "manual test"}},
    }
    return {"delivery": state.alerts.deliver(alert, channels)}
