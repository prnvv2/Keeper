"""Control-plane API tests.

Uses a real SQLite database in a temp directory and FastAPI's TestClient, so
these exercise the actual SQL and the actual lifespan wiring rather than mocks.
"""

from __future__ import annotations

import time

import pytest
from fastapi.testclient import TestClient

from keeper_control.app import create_app
from keeper_control.config import Settings

INGEST_KEY = "ingest-test-key"
ADMIN_KEY = "admin-test-key"


@pytest.fixture
def client(tmp_path):
    settings = Settings(
        environment="development",
        database_url=f"sqlite:///{tmp_path / 'test.db'}",
        ingest_api_keys=[INGEST_KEY],
        admin_api_keys=[ADMIN_KEY],
        alerting_enabled=True,
        anomaly_enabled=False,   # the scheduler is exercised separately
        siem_enabled=False,
        retention_days=0,
    )
    with TestClient(create_app(settings)) as c:
        yield c


def ingest_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {INGEST_KEY}"}


def admin_headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {ADMIN_KEY}"}


def make_event(**overrides):
    now = int(time.time() * 1000)
    event = {
        "event_id": f"evt_{overrides.get('n', 0)}_{now}",
        "correlation_id": overrides.get("correlation_id", "req_abc"),
        "timestamp_ms": now,
        "stage": "input",
        "action": "allow",
        "severity": "info",
        "application": "support-bot",
        "environment": "production",
        "instance_id": "inst_1",
        "principal_id": "u1",
        "findings": [],
        "policy_traces": [],
        "tags": {},
    }
    event.update({k: v for k, v in overrides.items() if k != "n"})
    return event


def post_events(client, events):
    return client.post(
        "/v1/telemetry/events",
        json={"instance_id": "inst_1", "events": events},
        headers=ingest_headers(),
    )


# --- auth ------------------------------------------------------------------


def test_ingest_requires_a_key(client):
    assert post_events(client, [make_event()]).status_code == 200
    unauth = client.post("/v1/telemetry/events", json={"instance_id": "i", "events": []})
    assert unauth.status_code == 401


def test_ingest_key_does_not_grant_admin(client):
    """A compromised application must not be able to read everyone's audit log."""
    response = client.get("/api/overview", headers=ingest_headers())
    assert response.status_code == 401


def test_admin_endpoints_require_a_key(client):
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/overview", headers=admin_headers()).status_code == 200


def test_liveness_needs_no_credential(client):
    assert client.get("/healthz").json()["status"] == "ok"
    assert client.get("/readyz").json()["status"] == "ready"


# --- ingest ----------------------------------------------------------------


def test_ingest_stores_events_and_is_idempotent(client):
    event = make_event()
    first = post_events(client, [event]).json()
    second = post_events(client, [event]).json()
    assert first == {"accepted": 1, "duplicates": 0, "rejected": 0, "alerts_fired": 0}
    assert second["accepted"] == 0 and second["duplicates"] == 1


def test_ingest_rejects_an_oversized_batch(client):
    events = [make_event(n=i, event_id=f"evt_{i}") for i in range(600)]
    assert post_events(client, events).status_code == 413


def test_ingest_accepts_unknown_fields_from_a_newer_sdk(client):
    """A fleet is never on one SDK version."""
    event = make_event(some_future_field={"x": 1}, another="value")
    assert post_events(client, [event]).json()["accepted"] == 1


def test_ingest_rejects_a_malformed_event(client):
    response = client.post(
        "/v1/telemetry/events",
        json={"instance_id": "inst_1", "events": [{"event_id": "x"}]},
        headers=ingest_headers(),
    )
    assert response.status_code == 422


# --- search and investigation ---------------------------------------------


def test_search_filters_and_paginates(client):
    post_events(
        client,
        [
            make_event(event_id="e1", action="block", severity="critical",
                       findings=[{"detector": "secrets", "detected": True, "score": 1.0,
                                  "severity": "critical", "action": "block",
                                  "summary": "credential material detected",
                                  "category": "credential_exposure", "spans": []}]),
            make_event(event_id="e2", action="allow", application="other-app"),
            make_event(event_id="e3", action="flag", severity="low"),
        ],
    )
    blocked = client.get("/api/events", params={"action": "block"}, headers=admin_headers()).json()
    assert blocked["total"] == 1 and blocked["events"][0]["event_id"] == "e1"

    by_app = client.get("/api/events", params={"application": "other-app"}, headers=admin_headers()).json()
    assert by_app["total"] == 1

    by_detector = client.get("/api/events", params={"detector": "secrets"}, headers=admin_headers()).json()
    assert by_detector["total"] == 1

    by_severity = client.get("/api/events", params={"min_severity": "low"}, headers=admin_headers()).json()
    assert by_severity["total"] == 2

    page = client.get("/api/events", params={"limit": 1, "offset": 1}, headers=admin_headers()).json()
    assert len(page["events"]) == 1 and page["total"] == 3


def test_free_text_search_covers_findings(client):
    post_events(
        client,
        [make_event(event_id="e1", prompt="please refund my order",
                    findings=[{"detector": "pii", "detected": True, "score": 1.0, "severity": "medium",
                               "action": "redact", "summary": "1 PII item detected: email",
                               "category": "sensitive_data", "spans": []}])],
    )
    hits = client.get("/api/events", params={"q": "refund"}, headers=admin_headers()).json()
    assert hits["total"] == 1
    by_summary = client.get("/api/events", params={"q": "pii item"}, headers=admin_headers()).json()
    assert by_summary["total"] == 1


def test_correlation_reconstructs_a_whole_interaction(client):
    post_events(
        client,
        [
            make_event(event_id="c1", correlation_id="req_x", stage="input", action="allow"),
            make_event(event_id="c2", correlation_id="req_x", stage="tool_call", action="block",
                       severity="critical",
                       findings=[{"detector": "token_flow", "detected": True, "score": 1.0,
                                  "severity": "critical", "action": "block", "summary": "unsafe flow",
                                  "category": "unsafe_flow", "spans": []}]),
            make_event(event_id="c3", correlation_id="req_x", stage="output", action="allow"),
        ],
    )
    data = client.get("/api/events/correlation/req_x", headers=admin_headers()).json()
    assert len(data["events"]) == 3
    assert data["summary"]["stages"] == ["input", "tool_call", "output"]
    assert data["summary"]["outcome"] == "block"
    assert "token_flow" in data["summary"]["detectors_fired"]


def test_correlation_404s_for_an_unknown_id(client):
    assert client.get("/api/events/correlation/nope", headers=admin_headers()).status_code == 404


# --- analytics -------------------------------------------------------------


def test_overview_summarises_the_window(client):
    post_events(
        client,
        [
            make_event(event_id="o1", action="block", severity="high"),
            make_event(event_id="o2", action="allow"),
            make_event(event_id="o3", action="allow"),
        ],
    )
    data = client.get("/api/overview", headers=admin_headers()).json()
    assert data["total_events"] == 3
    assert data["by_action"]["block"] == 1
    assert data["block_rate"] == pytest.approx(1 / 3, abs=0.001)


def test_timeline_buckets_events(client):
    post_events(client, [make_event(event_id=f"t{i}", n=i) for i in range(5)])
    buckets = client.get("/api/timeline", params={"hours": 1}, headers=admin_headers()).json()["buckets"]
    assert sum(b["total"] for b in buckets) == 5


def test_detector_analytics_reports_hit_rates(client):
    findings = [
        {"detector": "pii", "detected": True, "score": 1.0, "severity": "medium", "action": "redact",
         "summary": "pii", "category": "sensitive_data", "spans": [], "elapsed_ms": 0.4},
        {"detector": "prompt_injection", "detected": False, "score": 0.0, "severity": "info",
         "action": "allow", "summary": "", "category": "prompt_injection", "spans": [], "elapsed_ms": 0.2},
    ]
    post_events(client, [make_event(event_id="d1", findings=findings),
                         make_event(event_id="d2", findings=findings)])
    stats = {d["detector"]: d for d in
             client.get("/api/analytics/detectors", headers=admin_headers()).json()["detectors"]}
    assert stats["pii"]["hit_rate"] == 1.0
    assert stats["prompt_injection"]["hit_rate"] == 0.0
    assert stats["pii"]["avg_latency_ms"] > 0


def test_policy_analytics_reports_which_rules_fire(client):
    post_events(
        client,
        [make_event(event_id="p1", policy_traces=[
            {"policy_id": "default", "policy_version": "1.0.0", "rule_id": "block-secrets",
             "matched": True, "action": "block", "elapsed_ms": 0.05, "note": ""}])],
    )
    rules = client.get("/api/analytics/policy", headers=admin_headers()).json()["rules"]
    assert rules[0]["rule_id"] == "block-secrets" and rules[0]["matches"] == 1


# --- fleet -----------------------------------------------------------------


def test_fleet_inventory_tracks_instances(client):
    client.post(
        "/v1/fleet/register",
        json={"instance_id": "inst_1", "application": "support-bot", "environment": "production",
              "sdk_version": "0.1.0", "detectors": ["pii", "secrets"], "monitor_only": False},
        headers=ingest_headers(),
    )
    fleet = client.get("/api/fleet", headers=admin_headers()).json()
    assert fleet["total"] == 1 and fleet["healthy"] == 1
    assert fleet["sdk_versions"]["0.1.0"] == 1


def test_heartbeat_updates_health(client):
    client.post("/v1/fleet/register",
                json={"instance_id": "inst_2", "application": "a"}, headers=ingest_headers())
    client.post("/v1/fleet/heartbeat",
                json={"instance_id": "inst_2", "health": {"sdk_version": "0.2.0", "detectors": ["pii"]}},
                headers=ingest_headers())
    instance = client.get("/api/fleet", headers=admin_headers()).json()["instances"][0]
    assert instance["sdk_version"] == "0.2.0"


# --- policy ----------------------------------------------------------------


def test_a_safe_default_policy_is_seeded_and_servable(client):
    response = client.get("/v1/policies/default", headers=ingest_headers())
    assert response.status_code == 200
    assert response.json()["policy"]["id"] == "keeper.safe-default"
    assert response.headers["ETag"]


def test_policy_fetch_revalidates_with_etag(client):
    first = client.get("/v1/policies/default", headers=ingest_headers())
    etag = first.headers["ETag"]
    second = client.get("/v1/policies/default", headers={**ingest_headers(), "If-None-Match": etag})
    assert second.status_code == 304
    assert not second.content


def test_publishing_a_policy_serves_it_to_the_fleet(client):
    policy = {
        "id": "acme.strict",
        "version": "2.0.0",
        "rules": [{"id": "block-pii", "when": {"detector_fired": "pii"}, "action": "block"}],
    }
    published = client.post("/api/policies", json={"bundle": "default", "policy": policy, "publish": True},
                            headers=admin_headers())
    assert published.status_code == 201
    served = client.get("/v1/policies/default", headers=ingest_headers()).json()
    assert served["policy"]["id"] == "acme.strict" and served["version"] == "2.0.0"


def test_invalid_policy_is_rejected_at_publish_time(client):
    bad = {"id": "x", "version": "1", "rules": [{"id": "r", "when": {"nonsense": True}, "action": "block"}]}
    response = client.post("/api/policies", json={"bundle": "default", "policy": bad}, headers=admin_headers())
    assert response.status_code == 422
    assert "invalid policy" in response.json()["detail"]


def test_republishing_a_version_with_different_content_is_refused(client):
    base = {"id": "acme", "version": "1.0.0", "rules": []}
    client.post("/api/policies", json={"bundle": "b1", "policy": base}, headers=admin_headers())
    changed = {"id": "acme", "version": "1.0.0",
               "rules": [{"id": "r", "when": {"detector_fired": "pii"}, "action": "block"}]}
    response = client.post("/api/policies", json={"bundle": "b1", "policy": changed}, headers=admin_headers())
    assert response.status_code == 409


def test_dry_run_reports_what_would_change(client):
    post_events(
        client,
        [make_event(event_id="dr1", action="allow",
                    findings=[{"detector": "pii", "detected": True, "score": 1.0, "severity": "medium",
                               "action": "redact", "summary": "pii", "category": "sensitive_data",
                               "spans": []}])],
    )
    candidate = {"id": "c", "version": "9.0.0",
                 "rules": [{"id": "block-pii", "when": {"detector_fired": "pii"}, "action": "block"}]}
    report = client.post("/api/policies/dry-run", json={"policy": candidate, "hours": 24},
                         headers=admin_headers()).json()
    assert report["changed"] == 1
    assert report["examples"][0]["to"] == "block"


# --- alerting --------------------------------------------------------------


def test_default_alert_rules_are_seeded(client):
    rules = client.get("/api/alert-rules", headers=admin_headers()).json()["rules"]
    assert {r["id"] for r in rules} >= {"rule_credential_leak", "rule_indirect_injection"}


def test_a_matching_event_fires_an_alert(client):
    post_events(
        client,
        [make_event(event_id="a1", action="block", severity="critical",
                    findings=[{"detector": "secrets", "detected": True, "score": 1.0, "severity": "critical",
                               "action": "block", "summary": "credential material detected",
                               "category": "credential_exposure", "spans": []}])],
    )
    alerts = client.get("/api/alerts", headers=admin_headers()).json()["alerts"]
    assert any(a["rule_id"] == "rule_credential_leak" for a in alerts)


def test_alert_cooldown_suppresses_a_flood(client):
    for i in range(5):
        post_events(
            client,
            [make_event(event_id=f"f{i}", action="block", severity="critical",
                        findings=[{"detector": "secrets", "detected": True, "score": 1.0,
                                   "severity": "critical", "action": "block", "summary": "leak",
                                   "category": "credential_exposure", "spans": []}])],
        )
    alerts = [a for a in client.get("/api/alerts", headers=admin_headers()).json()["alerts"]
              if a["rule_id"] == "rule_credential_leak"]
    assert len(alerts) == 1


def test_alerts_can_be_acknowledged(client):
    post_events(
        client,
        [make_event(event_id="ack1", action="block", severity="critical",
                    findings=[{"detector": "secrets", "detected": True, "score": 1.0, "severity": "critical",
                               "action": "block", "summary": "leak", "category": "credential_exposure",
                               "spans": []}])],
    )
    alert = client.get("/api/alerts", headers=admin_headers()).json()["alerts"][0]
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge", headers=admin_headers()).status_code == 200
    assert client.post(f"/api/alerts/{alert['id']}/acknowledge", headers=admin_headers()).status_code == 404


def test_custom_alert_rules_round_trip(client):
    rule = {"id": "rule_custom", "name": "Blocks in checkout", "kind": "match",
            "spec": {"application": "checkout", "action": ["block"]}, "channels": ["log"]}
    client.put("/api/alert-rules", json=rule, headers=admin_headers())
    assert any(r["id"] == "rule_custom" for r in
               client.get("/api/alert-rules", headers=admin_headers()).json()["rules"])
    assert client.delete("/api/alert-rules/rule_custom", headers=admin_headers()).status_code == 200


# --- operations ------------------------------------------------------------


def test_health_reports_counts_and_warnings(client):
    post_events(client, [make_event(event_id="h1")])
    health = client.get("/health", headers=admin_headers()).json()
    assert health["events_stored"] == 1
    assert health["database"] == "sqlite"


def test_metrics_are_prometheus_formatted(client):
    post_events(client, [make_event(event_id="m1")])
    body = client.get("/metrics").text
    assert "keeper_cp_events_ingested_total 1" in body
    assert "# TYPE keeper_cp_events_stored gauge" in body


def test_errors_do_not_leak_internals(client):
    """A security product must not hand a stack trace to a client."""
    response = client.get("/api/events/does-not-exist", headers=admin_headers())
    assert response.status_code == 404
    assert "Traceback" not in response.text


# --- compressed ingest ------------------------------------------------------
# The SDK gzips batches above a few kilobytes, which is most real batches. A
# suite that only ever posts one small event at a time never exercises that
# path, and the control plane returned 400 on every compressed batch until this
# was added.


def test_ingest_accepts_a_gzipped_batch(client):
    import gzip
    import json

    events = [make_event(n=i, event_id=f"gz{i}", prompt="x" * 200) for i in range(40)]
    body = json.dumps({"instance_id": "inst_1", "events": events}).encode()
    assert len(body) > 4096, "fixture must exceed the SDK's gzip threshold to be meaningful"

    response = client.post(
        "/v1/telemetry/events",
        content=gzip.compress(body),
        headers={**ingest_headers(), "Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    assert response.status_code == 200, response.text
    assert response.json()["accepted"] == 40
    assert client.get("/api/events", headers=admin_headers()).json()["total"] == 40


def test_ingest_still_accepts_an_uncompressed_batch(client):
    assert post_events(client, [make_event(event_id="plain")]).json()["accepted"] == 1


def test_malformed_gzip_is_rejected_cleanly(client):
    response = client.post(
        "/v1/telemetry/events",
        content=b"this is not gzip",
        headers={**ingest_headers(), "Content-Type": "application/json", "Content-Encoding": "gzip"},
    )
    assert response.status_code == 400
    assert "decompress" in response.json()["detail"]
