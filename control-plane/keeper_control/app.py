"""FastAPI application factory and background schedulers.

Four periodic jobs run alongside the API, all as asyncio tasks in the same
process. That is a deliberate v1 simplification: a separate worker is the right
answer at scale, but it doubles the deployment surface for a system whose whole
pitch is "self-hostable in an afternoon". ``docs/deployment.md`` explains how to
split them out when you outgrow one process, and every job is written to be
safely concurrent so running two replicas does not corrupt anything — the worst
case is duplicate alert evaluation, which the cooldowns absorb.

* **Threshold alerts** — evaluate counting rules.
* **Anomaly analysis** — cross-application patterns no SDK can see.
* **SIEM forwarding** — drain new events to every configured target.
* **Retention** — delete events past the retention window.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse

from .alerting.engine import AlertEngine, LogNotifier, SlackNotifier, WebhookNotifier, default_rules
from .anomaly.detectors import analyse
from .api import dashboard, health, ingest
from .api.deps import AppState
from .api.middleware import DecompressRequestMiddleware
from .config import Settings, get_settings
from .siem.exporters import SIEMForwarder, build_exporter
from .store.db import create_engine_from_url, init_db
from .store.repository import Repository, now_ms
from .version import __version__

log = logging.getLogger("keeper.control")

DESCRIPTION = """
The control plane for the Keeper AI firewall: telemetry ingestion, audit-log
search, policy distribution, alerting, fleet inventory, and SIEM export.

Two API surfaces with separate credentials:

* `/v1/*` — called by SDK instances. Ingest telemetry, pull policy, register.
* `/api/*` — called by humans and the dashboard. Requires an admin key.
"""


def build_alert_engine(repo: Repository, settings: Settings) -> AlertEngine:
    engine = AlertEngine(repo, [LogNotifier()])
    if settings.alert_webhook_url:
        engine.add_notifier(WebhookNotifier(settings.alert_webhook_url))
    if settings.alert_slack_webhook_url:
        engine.add_notifier(SlackNotifier(settings.alert_slack_webhook_url))
    return engine


def build_siem_forwarder(repo: Repository, settings: Settings) -> SIEMForwarder | None:
    if not settings.siem_enabled or not settings.siem_targets:
        return None
    exporters = []
    for spec in settings.siem_targets:
        try:
            exporters.append(build_exporter(spec))
        except ValueError as exc:
            log.error("ignoring SIEM target %r: %s", spec, exc)
    if not exporters:
        return None
    return SIEMForwarder(
        repo, exporters, batch_size=settings.siem_batch_size, min_severity=settings.siem_min_severity
    )


def seed(repo: Repository) -> None:
    """First-run seed: a published safe-default policy and the default alerts.

    Without this a fresh control plane serves 404 for the policy bundle, and
    every SDK pointed at it falls back to its built-in policy while logging an
    error — technically correct, operationally confusing.
    """
    if not repo.get_published_policy("default"):
        from keeper_firewall.policy.models import SAFE_DEFAULT_POLICY

        repo.save_policy("default", SAFE_DEFAULT_POLICY, published=True, created_by="system",
                         note="Seeded on first start. Edit and publish a new version to replace it.")
    existing = {r["id"] for r in repo.list_alert_rules()}
    for rule in default_rules():
        if rule["id"] not in existing:
            repo.save_alert_rule(rule)


async def _loop(name: str, interval_s: float, fn) -> None:
    """Run ``fn`` every ``interval_s``, surviving individual failures."""
    while True:
        try:
            await asyncio.sleep(interval_s)
            await asyncio.get_running_loop().run_in_executor(None, fn)
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed tick must not kill the loop
            log.exception("background job %s failed", name)


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        engine = create_engine_from_url(
            settings.database_url, pool_size=settings.pool_size, max_overflow=settings.max_overflow
        )
        init_db(engine)
        repo = Repository(engine)
        seed(repo)

        state = AppState(
            settings=settings,
            repo=repo,
            alerts=build_alert_engine(repo, settings),
            siem=build_siem_forwarder(repo, settings),
            started_ms=int(time.time() * 1000),
            warnings=settings.startup_warnings(),
        )
        app.state.keeper = state
        for warning in state.warnings:
            log.warning("startup: %s", warning)

        tasks: list[asyncio.Task] = []
        if settings.alerting_enabled:
            tasks.append(
                asyncio.create_task(
                    _loop("alerts", settings.alert_evaluation_interval_s, state.alerts.evaluate_thresholds)
                )
            )
        if settings.anomaly_enabled:
            def run_anomaly() -> None:
                since = now_ms() - settings.anomaly_window_minutes * 60_000
                findings = analyse(
                    repo.recent_for_anomaly(since),
                    {
                        "injection_threshold": settings.anomaly_injection_threshold,
                        "cross_app_threshold": settings.anomaly_cross_app_threshold,
                        "volume_sigma": settings.anomaly_volume_sigma,
                        "instances": repo.list_instances(),
                    },
                )
                if findings and settings.alerting_enabled:
                    state.alerts.on_anomalies(findings)

            tasks.append(asyncio.create_task(_loop("anomaly", 60, run_anomaly)))
        if state.siem is not None:
            tasks.append(
                asyncio.create_task(_loop("siem", settings.siem_flush_interval_s, state.siem.run_once))
            )
        if settings.retention_days > 0:
            def purge() -> None:
                cutoff = now_ms() - settings.retention_days * 86_400_000
                deleted = repo.purge_old_events(cutoff)
                if deleted:
                    log.info("retention: deleted %d events older than %d days", deleted, settings.retention_days)

            tasks.append(asyncio.create_task(_loop("retention", settings.retention_interval_s, purge)))

        try:
            yield
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            if state.siem is not None:
                state.siem.close()
            engine.dispose()

    app = FastAPI(
        title="Keeper Control Plane",
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        docs_url="/docs",
        openapi_url="/openapi.json",
    )

    # Outermost, so the CORS and security-header middleware below see a
    # plain body. The SDK gzips telemetry batches above a few kilobytes and no
    # ASGI server decompresses request bodies on its own.
    app.add_middleware(DecompressRequestMiddleware, max_bytes=settings.max_body_bytes)

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "Content-Encoding", "X-API-Key", "If-None-Match"],
        expose_headers=["ETag"],
    )

    @app.middleware("http")
    async def security_headers(request, call_next):
        """Headers that cost nothing and close off a class of browser attacks."""
        response = await call_next(request)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault("Cache-Control", "no-store")
        return response

    app.include_router(health.router)
    app.include_router(ingest.router)
    app.include_router(dashboard.router)

    @app.get("/", include_in_schema=False)
    async def root() -> RedirectResponse:
        return RedirectResponse("/docs")

    @app.exception_handler(Exception)
    async def unhandled(request, exc: Exception) -> JSONResponse:
        """Never leak a stack trace to a client of a security product."""
        log.exception("unhandled error on %s %s", request.method, request.url.path)
        return JSONResponse(
            status_code=500,
            content={"detail": "internal error", "path": request.url.path},
        )

    return app


app = create_app()
