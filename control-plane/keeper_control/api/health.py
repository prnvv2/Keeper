"""Health, readiness and the control plane's own metrics.

The control plane is production infrastructure for somebody's security team, so
it has to be monitorable the same way anything else in their estate is:
liveness and readiness for the orchestrator, Prometheus metrics for the
dashboards, and a detailed status endpoint for a human debugging at 3am.

``/healthz`` and ``/readyz`` are unauthenticated by design — a Kubernetes probe
cannot hold a credential — and expose nothing beyond whether the process is up
and the database answers.
"""

from __future__ import annotations

import time

from fastapi import APIRouter, Depends, Response, status
from sqlalchemy import text

from ..version import __version__
from .deps import AppState, get_state, require_admin_auth
from .schemas import HealthResponse

router = APIRouter(tags=["operations"])


@router.get("/healthz", include_in_schema=False)
async def liveness() -> dict[str, str]:
    """Is the process alive? Deliberately does not touch the database.

    A liveness probe that fails when the database is down gets the process
    killed and restarted, which does not fix the database and does lose the
    in-flight ingest queue. Database trouble belongs in readiness.
    """
    return {"status": "ok"}


@router.get("/readyz", include_in_schema=False)
async def readiness(response: Response, state: AppState = Depends(get_state)) -> dict[str, str]:
    """Can we serve traffic? Checks the database round trip."""
    try:
        with state.repo.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
    except Exception as exc:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "unavailable", "detail": str(exc)[:200]}
    return {"status": "ready"}


@router.get("/health", response_model=HealthResponse)
async def health(state: AppState = Depends(get_state), _auth: str = Depends(require_admin_auth)) -> HealthResponse:
    """Detailed status, including the warnings raised at startup."""
    instances = state.repo.list_instances()
    return HealthResponse(
        status="degraded" if state.warnings else "ok",
        version=__version__,
        uptime_ms=int(time.time() * 1000) - state.started_ms,
        environment=state.settings.environment,
        database=state.repo.engine.dialect.name,
        events_stored=state.repo.count_events(),
        active_instances=sum(1 for i in instances if i["status"] == "healthy"),
        ingest=dict(state.stats),
        siem=state.siem.health() if state.siem else None,
        warnings=list(state.warnings),
    )


@router.get("/metrics", include_in_schema=False)
async def metrics(state: AppState = Depends(get_state)) -> Response:
    """Prometheus exposition for the control plane itself.

    Kept small and hand-rolled rather than pulling in an instrumentation
    framework: these six series are what an operator alerts on, and each one
    maps to a specific failure ("ingest stopped", "a SIEM target is down",
    "instances went stale").
    """
    instances = state.repo.list_instances()
    healthy = sum(1 for i in instances if i["status"] == "healthy")
    siem = state.siem.health() if state.siem else {"exported": 0, "failed_batches": 0}
    lines = [
        "# HELP keeper_cp_events_ingested_total Audit events accepted by ingest.",
        "# TYPE keeper_cp_events_ingested_total counter",
        f"keeper_cp_events_ingested_total {state.stats['events_ingested']}",
        "# HELP keeper_cp_ingest_batches_total Telemetry batches received.",
        "# TYPE keeper_cp_ingest_batches_total counter",
        f"keeper_cp_ingest_batches_total {state.stats['batches']}",
        "# HELP keeper_cp_events_stored Audit events currently retained.",
        "# TYPE keeper_cp_events_stored gauge",
        f"keeper_cp_events_stored {state.repo.count_events()}",
        "# HELP keeper_cp_instances Registered SDK instances by status.",
        "# TYPE keeper_cp_instances gauge",
        f'keeper_cp_instances{{status="healthy"}} {healthy}',
        f'keeper_cp_instances{{status="stale"}} {len(instances) - healthy}',
        "# HELP keeper_cp_siem_exported_total Events forwarded to SIEM targets.",
        "# TYPE keeper_cp_siem_exported_total counter",
        f"keeper_cp_siem_exported_total {siem.get('exported', 0)}",
        "# HELP keeper_cp_siem_failed_batches_total SIEM export batches that failed.",
        "# TYPE keeper_cp_siem_failed_batches_total counter",
        f"keeper_cp_siem_failed_batches_total {siem.get('failed_batches', 0)}",
    ]
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")
