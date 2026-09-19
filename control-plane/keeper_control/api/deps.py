"""Shared dependencies: application state and authentication.

Two distinct trust levels, deliberately separated rather than sharing one key
space:

* **Ingest credentials** are held by every SDK instance — potentially hundreds
  of processes, in application repos, in CI. They may write telemetry and read
  the published policy. Nothing else.
* **Admin credentials** are held by people. They may read the audit trail and
  publish policy.

Conflating them would mean any compromised application could read every other
application's audit log. Keys are compared with :func:`hmac.compare_digest`.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass, field
from typing import Any

from fastapi import Depends, Header, HTTPException, Request, status

from ..alerting.engine import AlertEngine
from ..config import Settings
from ..siem.exporters import SIEMForwarder
from ..store.repository import Repository


@dataclass
class AppState:
    """Everything the routes need, assembled once at startup."""

    settings: Settings
    repo: Repository
    alerts: AlertEngine
    siem: SIEMForwarder | None = None
    started_ms: int = 0
    warnings: list[str] = field(default_factory=list)
    stats: dict[str, Any] = field(default_factory=lambda: {"events_ingested": 0, "batches": 0, "rejected": 0})


def get_state(request: Request) -> AppState:
    state: AppState | None = getattr(request.app.state, "keeper", None)
    if state is None:  # pragma: no cover - only if startup failed
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "control plane is not ready")
    return state


def get_repo(state: AppState = Depends(get_state)) -> Repository:
    return state.repo


def _extract_key(authorization: str | None, x_api_key: str | None) -> str | None:
    if x_api_key:
        return x_api_key
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return None


def _matches(candidate: str, allowed: list[str]) -> bool:
    # Compare against every key rather than short-circuiting: a loop that exits
    # on first match leaks which prefix was right through timing.
    found = False
    for key in allowed:
        if hmac.compare_digest(candidate, key):
            found = True
    return found


async def require_ingest_auth(
    state: AppState = Depends(get_state),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Authenticate an SDK instance."""
    settings = state.settings
    if settings.allow_anonymous_ingest:
        return "anonymous"
    key = _extract_key(authorization, x_api_key)
    if not key or not _matches(key, settings.ingest_api_keys):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid or missing ingest API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return key[:8]


async def require_admin_auth(
    state: AppState = Depends(get_state),
    authorization: str | None = Header(default=None),
    x_api_key: str | None = Header(default=None, alias="X-API-Key"),
) -> str:
    """Authenticate a dashboard or API user."""
    settings = state.settings
    if not settings.dashboard_auth_required:
        return "anonymous"
    key = _extract_key(authorization, x_api_key)
    # An admin key works everywhere; an ingest key never grants admin.
    if not key or not _matches(key, settings.admin_api_keys):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "invalid or missing admin API key",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return key[:8]
