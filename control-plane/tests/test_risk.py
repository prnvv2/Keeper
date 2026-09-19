"""Risk matrix and OWASP threat views in the control plane."""

from __future__ import annotations

import sqlite3

import test_api
from sqlalchemy import inspect
from test_api import admin_headers, make_event, post_events

from keeper_control.store.db import create_engine_from_url, init_db

client = test_api.client  # reuse the API-test fixture


def risky(n: int, likelihood: int, impact: int, threats: list[str], action: str = "block"):
    score = likelihood * impact
    band = "critical" if score > 16 else "high" if score > 9 else "medium" if score > 4 else "low"
    return make_event(
        n=n,
        action=action,
        severity="high",
        threats=threats,
        risk={"likelihood": likelihood, "impact": impact, "score": score, "band": band},
        findings=[{"detector": "prompt_injection", "detected": True, "category": "prompt_injection",
                   "severity": "high", "action": action, "score": 0.9, "threats": threats}],
    )


def test_risk_heatmap_and_threat_counts(client):
    post_events(client, [
        risky(1, 5, 4, ["LLM01", "ASI01"]),
        risky(2, 5, 4, ["LLM01", "ASI01"]),
        risky(3, 2, 4, ["LLM01"], action="flag"),
        risky(4, 5, 5, ["MCP03", "ASI04"]),
        make_event(n=5),
    ])
    data = client.get("/api/analytics/risk", headers=admin_headers()).json()
    assert data["matrix"][4][3] == 2          # likelihood 5, impact 4
    assert data["matrix"][1][3] == 1
    assert data["matrix"][4][4] == 1
    assert data["by_band"]["critical"] == 3
    llm01 = next(t for t in data["threats"] if t["threat"] == "LLM01")
    assert llm01 == {"threat": "LLM01", "events": 3, "blocked": 2}
    assert data["top_events"][0]["risk_score"] == 25


def test_events_filter_by_threat_and_risk(client):
    post_events(client, [risky(1, 5, 4, ["LLM01"]), risky(2, 5, 5, ["MCP03"]), make_event(n=3)])
    by_threat = client.get("/api/events", params={"threat": "mcp03"}, headers=admin_headers()).json()
    assert by_threat["total"] == 1
    by_risk = client.get("/api/events", params={"min_risk": 20}, headers=admin_headers()).json()
    assert by_risk["total"] == 2


def test_threat_catalog_includes_every_owasp_list_with_hits(client):
    post_events(client, [risky(1, 5, 4, ["ASI06"])])
    rows = client.get("/api/threats", headers=admin_headers()).json()["threats"]
    ids = {r["id"] for r in rows}
    assert {"LLM01", "LLM10", "ASI01", "ASI10", "MCP01", "MCP10"} <= ids
    assert next(r for r in rows if r["id"] == "ASI06")["hits"] == 1


def test_legacy_events_without_risk_are_accepted(client):
    event = make_event(n=1, findings=[{"detector": "pii", "detected": True, "category": "sensitive_data",
                                        "severity": "medium", "action": "redact", "score": 0.9}])
    assert post_events(client, [event]).status_code in (200, 202)
    stored = client.get("/api/events", headers=admin_headers()).json()["events"][0]
    assert stored["risk_score"] == 0 and stored["risk_band"] == "none"


def test_old_databases_gain_the_new_columns(tmp_path):
    path = tmp_path / "old.db"
    with sqlite3.connect(path) as conn:
        conn.execute("CREATE TABLE audit_events (event_id VARCHAR(64) PRIMARY KEY, correlation_id VARCHAR(64))")
    engine = create_engine_from_url(f"sqlite:///{path}")
    init_db(engine)
    columns = {c["name"] for c in inspect(engine).get_columns("audit_events")}
    assert {"threats", "risk_score", "risk_band", "risk_likelihood", "risk_impact"} <= columns
