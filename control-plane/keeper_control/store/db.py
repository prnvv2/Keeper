"""Database schema and engine.

SQLAlchemy Core, not the ORM. The control plane's data access is a handful of
append-heavy inserts and a lot of aggregate queries over one wide table; an
identity map and lazy-loading relationships buy nothing and cost clarity when
the query that matters is a GROUP BY over a million rows.

Schema shape, and why:

``audit_events``
    One row per decision, mirroring the SDK's ``AuditEvent``. Findings and
    policy traces are stored as JSON rather than normalised into child tables:
    they are always read with their parent event, never queried across events
    except by the denormalised columns we lift out at ingest
    (``detectors_fired``, ``categories``). Normalising them would triple the
    write cost of the hottest path in the system for a query nobody runs.

``instances``
    Fleet inventory: which app is running which SDK and policy version, and
    when it last checked in. The table that answers "is anything still running
    the version with the bad detector?".

``policies``
    Versioned bundles. Append-only: publishing never mutates a row, so a
    decision made under policy ``1.4.0`` can always be re-examined against the
    exact bundle that produced it.

``alerts`` / ``alert_rules``
    Alert definitions and firings.

Indexes are chosen for the three queries the dashboard actually makes:
timeline-by-time, filter-by-application/action/severity, and lookup-by
correlation-id.
"""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    Column,
    Float,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
)
from sqlalchemy.engine import Engine

metadata = MetaData()

audit_events = Table(
    "audit_events",
    metadata,
    Column("event_id", String(64), primary_key=True),
    Column("correlation_id", String(64), nullable=False, index=True),
    Column("timestamp_ms", BigInteger, nullable=False, index=True),
    Column("received_ms", BigInteger, nullable=False),
    Column("stage", String(32), nullable=False),
    Column("action", String(16), nullable=False),
    Column("severity", String(16), nullable=False),
    Column("application", String(128), nullable=False),
    Column("environment", String(32), nullable=False),
    Column("instance_id", String(64)),
    Column("sdk_version", String(32)),
    Column("schema_version", String(32)),
    Column("session_id", String(64)),
    Column("principal_id", String(128), index=True),
    Column("principal_roles", JSON),
    Column("tenant", String(128), index=True),
    Column("model", String(128)),
    Column("provider", String(64)),
    Column("trace_id", String(64), index=True),
    Column("span_id", String(64)),
    Column("policy_version", String(64)),
    Column("findings", JSON),
    Column("policy_traces", JSON),
    # Lifted out of findings at ingest so the dashboard can filter without
    # cracking JSON on every row.
    Column("detectors_fired", JSON),
    Column("categories", JSON),
    Column("prompt", Text),
    Column("response", Text),
    Column("redacted_fields", JSON),
    Column("latency_ms", Float),
    Column("tokens_in", Integer),
    Column("tokens_out", Integer),
    Column("error", Text),
    Column("tags", JSON),
    Column("search_text", Text),  # denormalised haystack for LIKE search
    # OWASP threat ids and the risk-matrix cell, lifted out of the event so the
    # risk views aggregate with plain GROUP BYs.
    Column("threats", JSON),
    Column("risk_score", Integer),
    Column("risk_band", String(16)),
    Column("risk_likelihood", Integer),
    Column("risk_impact", Integer),
    Index("ix_events_app_time", "application", "timestamp_ms"),
    Index("ix_events_risk_time", "risk_score", "timestamp_ms"),
    Index("ix_events_action_time", "action", "timestamp_ms"),
    Index("ix_events_severity_time", "severity", "timestamp_ms"),
)

instances = Table(
    "instances",
    metadata,
    Column("instance_id", String(64), primary_key=True),
    Column("application", String(128), nullable=False, index=True),
    Column("environment", String(32), nullable=False),
    Column("sdk_version", String(32)),
    Column("language", String(32)),
    Column("policy_id", String(64)),
    Column("policy_version", String(64)),
    Column("detectors", JSON),
    Column("monitor_only", Boolean, default=False),
    Column("first_seen_ms", BigInteger, nullable=False),
    Column("last_seen_ms", BigInteger, nullable=False, index=True),
    Column("events_received", BigInteger, default=0),
    Column("health", JSON),
)

policies = Table(
    "policies",
    metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("bundle", String(64), nullable=False, index=True),
    Column("version", String(64), nullable=False),
    Column("etag", String(64), nullable=False),
    Column("document", JSON, nullable=False),
    Column("published", Boolean, default=False, index=True),
    Column("created_ms", BigInteger, nullable=False),
    Column("created_by", String(128)),
    Column("note", Text),
    Index("ix_policies_bundle_version", "bundle", "version", unique=True),
)

alert_rules = Table(
    "alert_rules",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(128), nullable=False),
    Column("description", Text),
    Column("enabled", Boolean, default=True),
    Column("kind", String(32), nullable=False),  # threshold | anomaly | match
    Column("spec", JSON, nullable=False),
    Column("severity", String(16), default="medium"),
    Column("channels", JSON),
    Column("cooldown_s", Integer, default=300),
    Column("created_ms", BigInteger, nullable=False),
    Column("last_fired_ms", BigInteger),
)

alerts = Table(
    "alerts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("rule_id", String(64), index=True),
    Column("title", String(256), nullable=False),
    Column("description", Text),
    Column("severity", String(16), nullable=False, index=True),
    Column("created_ms", BigInteger, nullable=False, index=True),
    Column("acknowledged_ms", BigInteger),
    Column("acknowledged_by", String(128)),
    Column("context", JSON),
    Column("delivery", JSON),
)

#: Rolling per-minute counters, maintained at ingest. Computing the timeline by
#: scanning audit_events works until the table is large; this keeps the
#: dashboard's default view O(minutes) instead of O(events).
event_counters = Table(
    "event_counters",
    metadata,
    Column("bucket_ms", BigInteger, primary_key=True),
    Column("application", String(128), primary_key=True),
    Column("action", String(16), primary_key=True),
    Column("count", Integer, nullable=False, default=0),
    Index("ix_counters_bucket", "bucket_ms"),
)


def create_engine_from_url(url: str, *, pool_size: int = 10, max_overflow: int = 20, echo: bool = False) -> Engine:
    """Create the engine, with the settings each backend actually needs."""
    if url.startswith("sqlite"):
        engine = create_engine(
            url,
            echo=echo,
            future=True,
            # FastAPI serves requests from a thread pool; SQLite's default
            # same-thread check would reject those connections.
            connect_args={"check_same_thread": False, "timeout": 30},
        )
        with engine.begin() as conn:
            # WAL lets readers (the dashboard) run while the ingest path
            # writes, which is the difference between usable and not.
            conn.exec_driver_sql("PRAGMA journal_mode=WAL")
            conn.exec_driver_sql("PRAGMA synchronous=NORMAL")
        return engine
    return create_engine(
        url,
        echo=echo,
        future=True,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_pre_ping=True,
    )


def init_db(engine: Engine) -> None:
    """Create tables if they do not exist.

    Deliberately idempotent and migration-free for v1. A real deployment that
    outgrows this should adopt Alembic; ``docs/deployment.md`` says so rather
    than pretending ``create_all`` is a migration strategy.
    """
    metadata.create_all(engine)
    _add_missing_columns(engine)


def _add_missing_columns(engine: Engine) -> None:
    """Additive-only schema evolution for databases created by older versions.

    ``create_all`` never alters an existing table, so a v0.1 database would
    lack the threat/risk columns. Adding nullable columns is safe on every
    supported backend; anything more invasive is Alembic's job.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(engine)
    for table in metadata.sorted_tables:
        if not inspector.has_table(table.name):
            continue
        existing = {c["name"] for c in inspector.get_columns(table.name)}
        missing = [c for c in table.columns if c.name not in existing]
        if not missing:
            continue
        with engine.begin() as conn:
            for column in missing:
                ddl = column.type.compile(dialect=engine.dialect)
                conn.execute(text(f'ALTER TABLE {table.name} ADD COLUMN {column.name} {ddl}'))
