"""Queries. Everything that touches the database lives here.

Keeping SQL in one module means the API layer stays about HTTP and the
aggregation logic can be tested without a client. It also makes it obvious
which queries exist, which matters when you are trying to work out whether the
dashboard will survive a hundred million audit rows.
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from sqlalchemy import and_, delete, desc, func, insert, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from .db import alert_rules, alerts, audit_events, event_counters, instances, policies

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ACTION_ORDER = {"allow": 0, "flag": 1, "redact": 2, "challenge": 3, "block": 4}


def now_ms() -> int:
    return int(time.time() * 1000)


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex}"


@dataclass(slots=True)
class EventQuery:
    """Filters for the audit log search. All fields are optional."""

    since_ms: int | None = None
    until_ms: int | None = None
    application: str | None = None
    environment: str | None = None
    action: str | None = None
    severity: str | None = None
    min_severity: str | None = None
    stage: str | None = None
    principal_id: str | None = None
    tenant: str | None = None
    correlation_id: str | None = None
    trace_id: str | None = None
    detector: str | None = None
    category: str | None = None
    model: str | None = None
    search: str | None = None
    threat: str | None = None
    min_risk: int | None = None
    risk_band: str | None = None
    limit: int = 100
    offset: int = 0


class Repository:
    """All database access for the control plane."""

    def __init__(self, engine: Engine) -> None:
        self.engine = engine
        self.dialect = engine.dialect.name

    # -- ingest ------------------------------------------------------------

    def insert_events(self, events: Sequence[Mapping[str, Any]]) -> tuple[int, int]:
        """Insert a batch. Returns ``(accepted, duplicates)``.

        Duplicates are expected, not exceptional: the SDK retries a batch whose
        response was lost, so the same events legitimately arrive twice. Ingest
        is therefore idempotent on ``event_id`` and a duplicate is a normal
        outcome rather than an error the SDK should keep retrying.
        """
        if not events:
            return 0, 0
        rows = [self._to_row(e) for e in events]
        accepted = 0
        duplicates = 0
        with self.engine.begin() as conn:
            for row in rows:
                stmt = insert(audit_events).values(**row)
                if self.dialect == "sqlite":
                    stmt = sqlite_insert(audit_events).values(**row).on_conflict_do_nothing(
                        index_elements=["event_id"]
                    )
                    result = conn.execute(stmt)
                    if result.rowcount:
                        accepted += 1
                    else:
                        duplicates += 1
                        continue
                elif self.dialect == "postgresql":
                    from sqlalchemy.dialects.postgresql import insert as pg_insert

                    stmt = pg_insert(audit_events).values(**row).on_conflict_do_nothing(
                        index_elements=["event_id"]
                    )
                    result = conn.execute(stmt)
                    if result.rowcount:
                        accepted += 1
                    else:
                        duplicates += 1
                        continue
                else:  # pragma: no cover - other backends
                    try:
                        conn.execute(stmt)
                        accepted += 1
                    except Exception:
                        duplicates += 1
                        continue
                self._bump_counter(conn, row)
        return accepted, duplicates

    def _bump_counter(self, conn: Any, row: Mapping[str, Any]) -> None:
        bucket = (row["timestamp_ms"] // 60_000) * 60_000
        key = {"bucket_ms": bucket, "application": row["application"], "action": row["action"]}
        updated = conn.execute(
            update(event_counters)
            .where(
                and_(
                    event_counters.c.bucket_ms == bucket,
                    event_counters.c.application == row["application"],
                    event_counters.c.action == row["action"],
                )
            )
            .values(count=event_counters.c.count + 1)
        )
        if not updated.rowcount:
            try:
                conn.execute(insert(event_counters).values(**key, count=1))
            except Exception:  # pragma: no cover - lost race, someone else inserted
                conn.execute(
                    update(event_counters)
                    .where(
                        and_(
                            event_counters.c.bucket_ms == bucket,
                            event_counters.c.application == row["application"],
                            event_counters.c.action == row["action"],
                        )
                    )
                    .values(count=event_counters.c.count + 1)
                )

    @staticmethod
    def _to_row(event: Mapping[str, Any]) -> dict[str, Any]:
        """Turn a raw SDK payload into a storable row.

        This lifts ``detectors_fired`` and ``categories`` out of the nested
        findings. Those derived fields are what the alert matcher and the
        dashboard filters query, so anything evaluating rules against events
        must use the normalised form, not the payload as it arrived.
        """
        findings = event.get("findings") or []
        fired = [f["detector"] for f in findings if f.get("detected")]
        categories = sorted({f.get("category", "unspecified") for f in findings if f.get("detected")})
        # Events from SDKs older than schema v1.1 carry no threats/risk: derive
        # the threat list from findings where possible, leave risk empty.
        threats = list(event.get("threats") or dict.fromkeys(
            t for f in findings if f.get("detected") for t in (f.get("threats") or [])
        ))
        risk = event.get("risk") or {}
        # One lowercased haystack per event so free-text search is a single
        # LIKE rather than a scan across eight columns.
        haystack = " ".join(
            str(part)
            for part in (
                event.get("prompt"),
                event.get("response"),
                event.get("principal_id"),
                event.get("application"),
                event.get("model"),
                " ".join(f.get("summary", "") for f in findings),
                " ".join(fired),
                " ".join(threats),
            )
            if part
        ).lower()[:8000]
        return {
            "event_id": event.get("event_id") or new_id("evt_"),
            "correlation_id": event.get("correlation_id", ""),
            "timestamp_ms": int(event.get("timestamp_ms") or now_ms()),
            "received_ms": now_ms(),
            "stage": event.get("stage", "input"),
            "action": event.get("action", "allow"),
            "severity": event.get("severity", "info"),
            "application": event.get("application", "unknown"),
            "environment": event.get("environment", "unknown"),
            "instance_id": event.get("instance_id"),
            "sdk_version": event.get("sdk_version"),
            "schema_version": event.get("schema_version"),
            "session_id": event.get("session_id"),
            "principal_id": event.get("principal_id"),
            "principal_roles": event.get("principal_roles") or [],
            "tenant": event.get("tenant"),
            "model": event.get("model"),
            "provider": event.get("provider"),
            "trace_id": event.get("trace_id"),
            "span_id": event.get("span_id"),
            "policy_version": event.get("policy_version"),
            "findings": findings,
            "policy_traces": event.get("policy_traces") or [],
            "detectors_fired": fired,
            "categories": categories,
            "prompt": event.get("prompt"),
            "response": event.get("response"),
            "redacted_fields": event.get("redacted_fields") or [],
            "latency_ms": float(event.get("latency_ms") or 0.0),
            "tokens_in": event.get("tokens_in"),
            "tokens_out": event.get("tokens_out"),
            "error": event.get("error"),
            "tags": event.get("tags") or {},
            "search_text": haystack,
            "threats": threats,
            "risk_score": int(risk.get("score") or 0),
            "risk_band": str(risk.get("band") or "none"),
            "risk_likelihood": int(risk.get("likelihood") or 0),
            "risk_impact": int(risk.get("impact") or 0),
        }

    # -- search ------------------------------------------------------------

    def _filters(self, query: EventQuery) -> list[Any]:
        clauses: list[Any] = []
        c = audit_events.c
        if query.since_ms:
            clauses.append(c.timestamp_ms >= query.since_ms)
        if query.until_ms:
            clauses.append(c.timestamp_ms <= query.until_ms)
        for column, value in (
            (c.application, query.application),
            (c.environment, query.environment),
            (c.action, query.action),
            (c.severity, query.severity),
            (c.stage, query.stage),
            (c.principal_id, query.principal_id),
            (c.tenant, query.tenant),
            (c.correlation_id, query.correlation_id),
            (c.trace_id, query.trace_id),
            (c.model, query.model),
        ):
            if value:
                clauses.append(column == value)
        if query.min_severity:
            allowed = [s for s, rank in SEVERITY_ORDER.items() if rank >= SEVERITY_ORDER.get(query.min_severity, 0)]
            clauses.append(c.severity.in_(allowed))
        if query.detector:
            # JSON containment differs per backend, and the portable form is a
            # LIKE over the serialised array. Acceptable because this is an
            # investigation filter, not a hot path.
            clauses.append(func.lower(func.cast(c.detectors_fired, __import__("sqlalchemy").Text)).like(f'%"{query.detector.lower()}"%'))
        if query.category:
            clauses.append(func.lower(func.cast(c.categories, __import__("sqlalchemy").Text)).like(f'%"{query.category.lower()}"%'))
        if query.search:
            clauses.append(c.search_text.like(f"%{query.search.lower()}%"))
        if query.threat:
            clauses.append(func.upper(func.cast(c.threats, __import__("sqlalchemy").Text)).like(f'%"{query.threat.upper()}"%'))
        if query.min_risk:
            clauses.append(c.risk_score >= query.min_risk)
        if query.risk_band:
            clauses.append(c.risk_band == query.risk_band)
        return clauses

    def search_events(self, query: EventQuery) -> tuple[list[dict[str, Any]], int]:
        clauses = self._filters(query)
        base = select(audit_events)
        if clauses:
            base = base.where(and_(*clauses))
        stmt = base.order_by(desc(audit_events.c.timestamp_ms)).limit(query.limit).offset(query.offset)
        count_stmt = select(func.count()).select_from(audit_events)
        if clauses:
            count_stmt = count_stmt.where(and_(*clauses))
        with self.engine.connect() as conn:
            rows = [dict(r._mapping) for r in conn.execute(stmt)]
            total = conn.execute(count_stmt).scalar_one()
        return rows, int(total)

    def get_event(self, event_id: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(select(audit_events).where(audit_events.c.event_id == event_id)).first()
        return dict(row._mapping) if row else None

    def get_correlation(self, correlation_id: str) -> list[dict[str, Any]]:
        """Every event of one request, oldest first — the investigation view."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(audit_events)
                .where(audit_events.c.correlation_id == correlation_id)
                .order_by(audit_events.c.timestamp_ms)
            )
            return [dict(r._mapping) for r in rows]

    # -- aggregates --------------------------------------------------------

    def overview(self, since_ms: int, *, environment: str | None = None) -> dict[str, Any]:
        c = audit_events.c
        clauses = [c.timestamp_ms >= since_ms]
        if environment:
            clauses.append(c.environment == environment)
        where = and_(*clauses)
        with self.engine.connect() as conn:
            totals = conn.execute(
                select(c.action, func.count().label("n")).where(where).group_by(c.action)
            ).all()
            severities = conn.execute(
                select(c.severity, func.count().label("n")).where(where).group_by(c.severity)
            ).all()
            apps = conn.execute(
                select(c.application, func.count().label("n"))
                .where(where)
                .group_by(c.application)
                .order_by(desc("n"))
                .limit(20)
            ).all()
            latency = conn.execute(
                select(func.avg(c.latency_ms), func.max(c.latency_ms)).where(where)
            ).first()
            active_instances = conn.execute(
                select(func.count()).select_from(instances).where(instances.c.last_seen_ms >= since_ms)
            ).scalar_one()

        by_action = {row.action: row.n for row in totals}
        total = sum(by_action.values())
        blocked = by_action.get("block", 0) + by_action.get("challenge", 0)
        return {
            "window_start_ms": since_ms,
            "total_events": total,
            "by_action": by_action,
            "by_severity": {row.severity: row.n for row in severities},
            "top_applications": [{"application": row.application, "events": row.n} for row in apps],
            "blocked": blocked,
            "block_rate": round(blocked / total, 4) if total else 0.0,
            "avg_latency_ms": round(float(latency[0] or 0.0), 2),
            "max_latency_ms": round(float(latency[1] or 0.0), 2),
            "active_instances": int(active_instances),
        }

    def timeline(self, since_ms: int, *, bucket_minutes: int = 1, application: str | None = None) -> list[dict[str, Any]]:
        """Per-bucket action counts, served from the rolling counter table."""
        width = bucket_minutes * 60_000
        clauses = [event_counters.c.bucket_ms >= since_ms]
        if application:
            clauses.append(event_counters.c.application == application)
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(event_counters).where(and_(*clauses)).order_by(event_counters.c.bucket_ms)
            ).all()
        buckets: dict[int, dict[str, Any]] = {}
        for row in rows:
            key = (row.bucket_ms // width) * width
            bucket = buckets.setdefault(key, {"bucket_ms": key, "total": 0})
            bucket[row.action] = bucket.get(row.action, 0) + row.count
            bucket["total"] += row.count
        return [buckets[k] for k in sorted(buckets)]

    def detector_stats(self, since_ms: int) -> list[dict[str, Any]]:
        """Hit rates and latency per detector — the coverage view.

        Computed in Python over the findings JSON rather than in SQL: the
        per-detector breakdown needs the nested structure, and this runs on a
        dashboard request, not on ingest.
        """
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(audit_events.c.findings).where(audit_events.c.timestamp_ms >= since_ms)
            ).all()
        stats: dict[str, dict[str, Any]] = {}
        for (findings,) in rows:
            for finding in findings or []:
                entry = stats.setdefault(
                    finding["detector"],
                    {"detector": finding["detector"], "runs": 0, "hits": 0, "errors": 0,
                     "total_ms": 0.0, "categories": set(), "severities": {}},
                )
                entry["runs"] += 1
                entry["total_ms"] += float(finding.get("elapsed_ms") or 0.0)
                if finding.get("error"):
                    entry["errors"] += 1
                if finding.get("detected"):
                    entry["hits"] += 1
                    entry["categories"].add(finding.get("category", "unspecified"))
                    sev = finding.get("severity", "info")
                    entry["severities"][sev] = entry["severities"].get(sev, 0) + 1
        out = []
        for entry in stats.values():
            runs = entry["runs"] or 1
            out.append(
                {
                    "detector": entry["detector"],
                    "runs": entry["runs"],
                    "hits": entry["hits"],
                    "hit_rate": round(entry["hits"] / runs, 4),
                    "errors": entry["errors"],
                    "avg_latency_ms": round(entry["total_ms"] / runs, 3),
                    "categories": sorted(entry["categories"]),
                    "severities": entry["severities"],
                }
            )
        return sorted(out, key=lambda e: -e["hits"])

    def risk_stats(self, since_ms: int, *, application: str | None = None) -> dict[str, Any]:
        """The risk picture: a 5x5 likelihood x impact heat map, band counts,
        per-OWASP-threat hit counts, and the riskiest recent events."""
        c = audit_events.c
        clauses = [c.timestamp_ms >= since_ms]
        if application:
            clauses.append(c.application == application)
        where = and_(*clauses)
        grid = [[0] * 5 for _ in range(5)]
        with self.engine.connect() as conn:
            cells = conn.execute(
                select(c.risk_likelihood, c.risk_impact, func.count().label("n"))
                .where(and_(where, c.risk_score > 0))
                .group_by(c.risk_likelihood, c.risk_impact)
            ).all()
            bands = conn.execute(select(c.risk_band, func.count().label("n")).where(where).group_by(c.risk_band)).all()
            threat_rows = conn.execute(
                select(c.threats, c.action).where(and_(where, c.risk_score > 0))
            ).all()
            top = conn.execute(
                select(c.event_id, c.correlation_id, c.timestamp_ms, c.application, c.stage, c.action,
                       c.risk_score, c.risk_band, c.risk_likelihood, c.risk_impact, c.threats, c.principal_id)
                .where(and_(where, c.risk_score > 0))
                .order_by(desc(c.risk_score), desc(c.timestamp_ms))
                .limit(15)
            ).all()
        for row in cells:
            if row.risk_likelihood and row.risk_impact and 1 <= row.risk_likelihood <= 5 and 1 <= row.risk_impact <= 5:
                grid[row.risk_likelihood - 1][row.risk_impact - 1] += row.n
        threats: dict[str, dict[str, Any]] = {}
        for ids, action in threat_rows:
            for tid in ids or []:
                entry = threats.setdefault(tid, {"threat": tid, "events": 0, "blocked": 0})
                entry["events"] += 1
                if action in ("block", "challenge"):
                    entry["blocked"] += 1
        return {
            "matrix": grid,
            "by_band": {row.risk_band or "none": row.n for row in bands},
            "threats": sorted(threats.values(), key=lambda e: -e["events"]),
            "top_events": [dict(r._mapping) for r in top],
        }

    def policy_stats(self, since_ms: int) -> list[dict[str, Any]]:
        """Which rules actually fire — policy-effectiveness analysis."""
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(audit_events.c.policy_traces).where(audit_events.c.timestamp_ms >= since_ms)
            ).all()
        stats: dict[tuple[str, str | None], dict[str, Any]] = {}
        for (traces,) in rows:
            for trace in traces or []:
                if not trace.get("matched"):
                    continue
                key = (trace.get("policy_id", "?"), trace.get("rule_id"))
                entry = stats.setdefault(
                    key,
                    {"policy_id": key[0], "rule_id": key[1], "matches": 0, "total_ms": 0.0, "actions": {}},
                )
                entry["matches"] += 1
                entry["total_ms"] += float(trace.get("elapsed_ms") or 0.0)
                action = trace.get("action", "allow")
                entry["actions"][action] = entry["actions"].get(action, 0) + 1
        out = []
        for entry in stats.values():
            out.append(
                {
                    **{k: v for k, v in entry.items() if k != "total_ms"},
                    "avg_eval_ms": round(entry["total_ms"] / max(1, entry["matches"]), 4),
                }
            )
        return sorted(out, key=lambda e: -e["matches"])

    def top_offenders(self, since_ms: int, limit: int = 10) -> list[dict[str, Any]]:
        c = audit_events.c
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(c.principal_id, c.application, func.count().label("n"))
                .where(and_(c.timestamp_ms >= since_ms, c.action.in_(["block", "challenge"])))
                .group_by(c.principal_id, c.application)
                .order_by(desc("n"))
                .limit(limit)
            ).all()
        return [
            {"principal_id": r.principal_id, "application": r.application, "blocked_events": r.n}
            for r in rows
        ]

    # -- fleet -------------------------------------------------------------

    def upsert_instance(self, payload: Mapping[str, Any]) -> None:
        now = now_ms()
        values = {
            "instance_id": payload["instance_id"],
            "application": payload.get("application", "unknown"),
            "environment": payload.get("environment", "unknown"),
            "sdk_version": payload.get("sdk_version"),
            "language": payload.get("language", "python"),
            "policy_id": payload.get("policy_id"),
            "policy_version": payload.get("policy_version"),
            "detectors": payload.get("detectors") or [],
            "monitor_only": bool(payload.get("monitor_only", False)),
            "last_seen_ms": now,
            "health": payload.get("health") or {},
        }
        with self.engine.begin() as conn:
            updated = conn.execute(
                update(instances)
                .where(instances.c.instance_id == values["instance_id"])
                .values(**values)
            )
            if not updated.rowcount:
                conn.execute(insert(instances).values(**values, first_seen_ms=now, events_received=0))

    def touch_instance(self, instance_id: str, events: int) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                update(instances)
                .where(instances.c.instance_id == instance_id)
                .values(last_seen_ms=now_ms(), events_received=instances.c.events_received + events)
            )

    def list_instances(self, *, stale_after_s: int = 300) -> list[dict[str, Any]]:
        cutoff = now_ms() - stale_after_s * 1000
        with self.engine.connect() as conn:
            rows = conn.execute(select(instances).order_by(desc(instances.c.last_seen_ms))).all()
        out = []
        for row in rows:
            record = dict(row._mapping)
            record["status"] = "healthy" if record["last_seen_ms"] >= cutoff else "stale"
            out.append(record)
        return out

    # -- policy ------------------------------------------------------------

    def save_policy(
        self, bundle: str, document: Mapping[str, Any], *, published: bool = False, created_by: str | None = None, note: str = ""
    ) -> dict[str, Any]:
        version = str(document.get("version", "0"))
        etag = hashlib.sha256(
            json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()[:32]
        row = {
            "bundle": bundle,
            "version": version,
            "etag": etag,
            "document": dict(document),
            "published": published,
            "created_ms": now_ms(),
            "created_by": created_by,
            "note": note,
        }
        with self.engine.begin() as conn:
            existing = conn.execute(
                select(policies).where(
                    and_(policies.c.bundle == bundle, policies.c.version == version)
                )
            ).first()
            if existing:
                # Versions are immutable. Republishing the same version with
                # different content would make historical audit rows
                # unexplainable, so it is refused.
                if existing.etag != etag:
                    raise ValueError(
                        f"policy {bundle}@{version} already exists with different content; "
                        "bump the version rather than editing a published bundle"
                    )
                if published:
                    conn.execute(
                        update(policies)
                        .where(and_(policies.c.bundle == bundle, policies.c.published.is_(True)))
                        .values(published=False)
                    )
                    conn.execute(
                        update(policies).where(policies.c.id == existing.id).values(published=True)
                    )
                return dict(existing._mapping) | {"published": published}
            if published:
                conn.execute(
                    update(policies)
                    .where(and_(policies.c.bundle == bundle, policies.c.published.is_(True)))
                    .values(published=False)
                )
            conn.execute(insert(policies).values(**row))
        return row

    def get_published_policy(self, bundle: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(policies)
                .where(and_(policies.c.bundle == bundle, policies.c.published.is_(True)))
                .order_by(desc(policies.c.created_ms))
                .limit(1)
            ).first()
        return dict(row._mapping) if row else None

    def list_policies(self, bundle: str | None = None) -> list[dict[str, Any]]:
        stmt = select(policies).order_by(desc(policies.c.created_ms))
        if bundle:
            stmt = stmt.where(policies.c.bundle == bundle)
        with self.engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(stmt)]

    def get_policy_version(self, bundle: str, version: str) -> dict[str, Any] | None:
        with self.engine.connect() as conn:
            row = conn.execute(
                select(policies).where(and_(policies.c.bundle == bundle, policies.c.version == version))
            ).first()
        return dict(row._mapping) if row else None

    # -- alerts ------------------------------------------------------------

    def save_alert_rule(self, rule: Mapping[str, Any]) -> dict[str, Any]:
        values = {
            "id": rule.get("id") or new_id("rule_"),
            "name": rule["name"],
            "description": rule.get("description", ""),
            "enabled": bool(rule.get("enabled", True)),
            "kind": rule.get("kind", "threshold"),
            "spec": dict(rule.get("spec") or {}),
            "severity": rule.get("severity", "medium"),
            "channels": list(rule.get("channels") or []),
            "cooldown_s": int(rule.get("cooldown_s", 300)),
            "created_ms": now_ms(),
        }
        with self.engine.begin() as conn:
            updated = conn.execute(
                update(alert_rules).where(alert_rules.c.id == values["id"]).values(
                    **{k: v for k, v in values.items() if k != "created_ms"}
                )
            )
            if not updated.rowcount:
                conn.execute(insert(alert_rules).values(**values))
        return values

    def list_alert_rules(self, *, enabled_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(alert_rules)
        if enabled_only:
            stmt = stmt.where(alert_rules.c.enabled.is_(True))
        with self.engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(stmt)]

    def delete_alert_rule(self, rule_id: str) -> bool:
        with self.engine.begin() as conn:
            return bool(conn.execute(delete(alert_rules).where(alert_rules.c.id == rule_id)).rowcount)

    def mark_rule_fired(self, rule_id: str) -> None:
        with self.engine.begin() as conn:
            conn.execute(
                update(alert_rules).where(alert_rules.c.id == rule_id).values(last_fired_ms=now_ms())
            )

    def create_alert(self, alert: Mapping[str, Any]) -> dict[str, Any]:
        values = {
            "id": alert.get("id") or new_id("alt_"),
            "rule_id": alert.get("rule_id"),
            "title": alert["title"],
            "description": alert.get("description", ""),
            "severity": alert.get("severity", "medium"),
            "created_ms": now_ms(),
            "context": dict(alert.get("context") or {}),
            "delivery": list(alert.get("delivery") or []),
        }
        with self.engine.begin() as conn:
            conn.execute(insert(alerts).values(**values))
        return values

    def list_alerts(self, *, limit: int = 100, unacknowledged_only: bool = False) -> list[dict[str, Any]]:
        stmt = select(alerts).order_by(desc(alerts.c.created_ms)).limit(limit)
        if unacknowledged_only:
            stmt = stmt.where(alerts.c.acknowledged_ms.is_(None))
        with self.engine.connect() as conn:
            return [dict(r._mapping) for r in conn.execute(stmt)]

    def acknowledge_alert(self, alert_id: str, who: str) -> bool:
        with self.engine.begin() as conn:
            return bool(
                conn.execute(
                    update(alerts)
                    .where(and_(alerts.c.id == alert_id, alerts.c.acknowledged_ms.is_(None)))
                    .values(acknowledged_ms=now_ms(), acknowledged_by=who)
                ).rowcount
            )

    # -- maintenance -------------------------------------------------------

    def purge_old_events(self, older_than_ms: int) -> int:
        with self.engine.begin() as conn:
            deleted = conn.execute(
                delete(audit_events).where(audit_events.c.timestamp_ms < older_than_ms)
            ).rowcount
            conn.execute(delete(event_counters).where(event_counters.c.bucket_ms < older_than_ms))
        return int(deleted or 0)

    def count_events(self) -> int:
        with self.engine.connect() as conn:
            return int(conn.execute(select(func.count()).select_from(audit_events)).scalar_one())

    def recent_for_anomaly(self, since_ms: int, limit: int = 5000) -> list[dict[str, Any]]:
        """Lightweight projection for the anomaly detectors."""
        c = audit_events.c
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(
                    c.event_id, c.timestamp_ms, c.application, c.principal_id, c.action,
                    c.severity, c.categories, c.detectors_fired, c.tags, c.correlation_id,
                )
                .where(c.timestamp_ms >= since_ms)
                .order_by(desc(c.timestamp_ms))
                .limit(limit)
            )
            return [dict(r._mapping) for r in rows]

    def events_for_export(self, after_ms: int, limit: int = 500, min_severity: str = "info") -> list[dict[str, Any]]:
        """Events not yet forwarded to SIEM, oldest first."""
        allowed = [s for s, rank in SEVERITY_ORDER.items() if rank >= SEVERITY_ORDER.get(min_severity, 0)]
        c = audit_events.c
        with self.engine.connect() as conn:
            rows = conn.execute(
                select(audit_events)
                .where(and_(c.received_ms > after_ms, c.severity.in_(allowed)))
                .order_by(c.received_ms)
                .limit(limit)
            )
            return [dict(r._mapping) for r in rows]


def normalise_event(event: Mapping[str, Any]) -> dict[str, Any]:
    """Public name for :meth:`Repository._to_row`.

    Alert rules and anomaly detectors match on the derived ``detectors_fired``
    and ``categories`` fields, which only exist after normalisation. Anything
    evaluating an event before it is read back from the database has to
    normalise it first, so that step is exposed here rather than duplicated.
    """
    return Repository._to_row(event)
