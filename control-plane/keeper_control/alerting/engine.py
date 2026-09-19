"""Alerting: rules, evaluation, and delivery.

Three rule kinds, which between them cover what security teams actually ask
for:

``match``
    Fire on any single event matching a filter ("any critical credential leak,
    immediately"). Evaluated on the ingest path, so latency is sub-second.

``threshold``
    Fire when a count over a window crosses a number ("more than 20 blocks from
    one principal in 5 minutes"). Evaluated on a timer.

``anomaly``
    Fire on findings from :mod:`keeper_control.anomaly.detectors`.

Every rule has a cooldown, because the failure mode of alerting is not missing
an alert — it is sending four hundred, after which people mute the channel and
you have negative security value.

Delivery is pluggable: :class:`Notifier` is three methods, and the built-ins
(webhook, Slack, log) are examples rather than a closed set. Delivery failures
never fail the alert — the alert is recorded in the database either way, and
the delivery result is attached so a failing channel is visible instead of
silent.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol

import httpx

from ..anomaly.detectors import AnomalyFinding
from ..store.repository import Repository, now_ms

log = logging.getLogger("keeper.alerting")

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Notifier(Protocol):
    name: str

    def send(self, alert: Mapping[str, Any]) -> None: ...


class LogNotifier:
    """Always present. An alert that reaches no channel still reaches the log."""

    name = "log"

    def send(self, alert: Mapping[str, Any]) -> None:
        log.warning("ALERT [%s] %s — %s", alert["severity"], alert["title"], alert.get("description", ""))


class WebhookNotifier:
    """Generic JSON POST. The integration point for PagerDuty, Opsgenie, or an
    internal bus, via whatever shim the org already has."""

    name = "webhook"

    def __init__(self, url: str, *, timeout_s: float = 5.0, headers: Mapping[str, str] | None = None) -> None:
        self.url = url
        self.timeout_s = timeout_s
        self.headers = dict(headers or {})

    def send(self, alert: Mapping[str, Any]) -> None:
        with httpx.Client(timeout=self.timeout_s) as client:
            response = client.post(self.url, json=dict(alert), headers=self.headers)
            response.raise_for_status()


class SlackNotifier:
    """Slack incoming webhook, formatted so the alert is readable in-channel."""

    name = "slack"

    def __init__(self, url: str, *, timeout_s: float = 5.0) -> None:
        self.url = url
        self.timeout_s = timeout_s

    def send(self, alert: Mapping[str, Any]) -> None:
        emoji = {"critical": ":rotating_light:", "high": ":warning:", "medium": ":eyes:"}.get(
            alert["severity"], ":information_source:"
        )
        context = alert.get("context") or {}
        fields = [
            {"type": "mrkdwn", "text": f"*{k}*\n{v}"}
            for k, v in list(context.get("entities", {}).items())[:6]
        ]
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn",
                                         "text": f"{emoji} *{alert['title']}*\n{alert.get('description', '')}"}},
        ]
        if fields:
            blocks.append({"type": "section", "fields": fields})
        examples = context.get("examples") or []
        if examples:
            blocks.append(
                {"type": "context", "elements": [
                    {"type": "mrkdwn", "text": f"Correlation IDs: `{'`, `'.join(examples[:3])}`"}
                ]}
            )
        with httpx.Client(timeout=self.timeout_s) as client:
            response = client.post(self.url, json={"text": alert["title"], "blocks": blocks})
            response.raise_for_status()


@dataclass(slots=True)
class RuleResult:
    fired: bool
    title: str = ""
    description: str = ""
    context: Mapping[str, Any] | None = None


class AlertEngine:
    """Evaluates rules and dispatches alerts."""

    def __init__(self, repo: Repository, notifiers: Sequence[Notifier] | None = None) -> None:
        self.repo = repo
        self.notifiers: dict[str, Notifier] = {n.name: n for n in (notifiers or [LogNotifier()])}
        if "log" not in self.notifiers:
            self.notifiers["log"] = LogNotifier()

    def add_notifier(self, notifier: Notifier) -> None:
        self.notifiers[notifier.name] = notifier

    # -- evaluation --------------------------------------------------------

    def on_events(self, events: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        """Evaluate ``match`` rules against a freshly ingested batch."""
        fired: list[dict[str, Any]] = []
        rules = [r for r in self.repo.list_alert_rules(enabled_only=True) if r["kind"] == "match"]
        if not rules:
            return fired
        for rule in rules:
            if self._in_cooldown(rule):
                continue
            for event in events:
                if not self._matches(rule["spec"], event):
                    continue
                fired.append(
                    self.fire(
                        rule,
                        title=rule["name"],
                        description=(
                            f"{event.get('action')} at {event.get('stage')} in "
                            f"{event.get('application')}: "
                            + "; ".join(
                                f.get("summary", "") for f in (event.get("findings") or []) if f.get("detected")
                            )
                        ),
                        context={
                            "event_id": event.get("event_id"),
                            "correlation_id": event.get("correlation_id"),
                            "entities": {
                                "application": event.get("application"),
                                "principal_id": event.get("principal_id"),
                                "stage": event.get("stage"),
                            },
                            "examples": [event.get("correlation_id")],
                        },
                    )
                )
                break  # one alert per rule per batch; the cooldown handles the rest
        return fired

    def evaluate_thresholds(self) -> list[dict[str, Any]]:
        """Evaluate ``threshold`` rules on a timer."""
        fired: list[dict[str, Any]] = []
        rules = [r for r in self.repo.list_alert_rules(enabled_only=True) if r["kind"] == "threshold"]
        for rule in rules:
            if self._in_cooldown(rule):
                continue
            spec = rule["spec"]
            window_s = int(spec.get("window_s", 300))
            since = now_ms() - window_s * 1000
            events = self.repo.recent_for_anomaly(since, limit=20_000)
            matched = [e for e in events if self._matches(spec.get("filter") or {}, e)]

            group_by = spec.get("group_by")
            threshold = int(spec.get("count", 10))
            if group_by:
                groups: dict[Any, list[Mapping[str, Any]]] = {}
                for event in matched:
                    groups.setdefault(event.get(group_by), []).append(event)
                for key, rows in groups.items():
                    if len(rows) >= threshold:
                        fired.append(
                            self.fire(
                                rule,
                                title=f"{rule['name']}: {key}",
                                description=(
                                    f"{len(rows)} matching events for {group_by}={key} in the last "
                                    f"{window_s}s (threshold {threshold})."
                                ),
                                context={
                                    "entities": {group_by: key, "count": len(rows)},
                                    "examples": [r["correlation_id"] for r in rows[:5]],
                                },
                            )
                        )
                        break  # cooldown applies per rule, not per group
            elif len(matched) >= threshold:
                fired.append(
                    self.fire(
                        rule,
                        title=rule["name"],
                        description=f"{len(matched)} matching events in the last {window_s}s (threshold {threshold}).",
                        context={
                            "entities": {"count": len(matched)},
                            "examples": [r["correlation_id"] for r in matched[:5]],
                        },
                    )
                )
        return fired

    def on_anomalies(self, findings: Sequence[AnomalyFinding]) -> list[dict[str, Any]]:
        """Turn anomaly findings into alerts, respecting per-rule cooldowns."""
        fired: list[dict[str, Any]] = []
        rules = [r for r in self.repo.list_alert_rules(enabled_only=True) if r["kind"] == "anomaly"]
        for finding in findings:
            for rule in rules:
                spec = rule["spec"]
                kinds = spec.get("kinds")
                if kinds and finding.kind not in kinds:
                    continue
                if SEVERITY_RANK.get(finding.severity, 0) < SEVERITY_RANK.get(spec.get("min_severity", "medium"), 2):
                    continue
                if self._in_cooldown(rule):
                    continue
                fired.append(
                    self.fire(
                        rule,
                        title=finding.title,
                        description=finding.description,
                        severity=finding.severity,
                        context={
                            "anomaly_kind": finding.kind,
                            "entities": dict(finding.entities),
                            "evidence": dict(finding.evidence),
                            "examples": list(finding.examples),
                        },
                    )
                )
                break
        return fired

    # -- firing ------------------------------------------------------------

    def fire(
        self,
        rule: Mapping[str, Any],
        *,
        title: str,
        description: str,
        severity: str | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        alert = self.repo.create_alert(
            {
                "rule_id": rule.get("id"),
                "title": title,
                "description": description,
                "severity": severity or rule.get("severity", "medium"),
                "context": context or {},
            }
        )
        self.repo.mark_rule_fired(rule["id"])
        alert["delivery"] = self.deliver(alert, rule.get("channels") or ["log"])
        return alert

    def deliver(self, alert: Mapping[str, Any], channels: Sequence[str]) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for channel in channels or ["log"]:
            notifier = self.notifiers.get(channel)
            if notifier is None:
                results.append({"channel": channel, "status": "unconfigured"})
                continue
            try:
                notifier.send(alert)
                results.append({"channel": channel, "status": "delivered"})
            except Exception as exc:
                log.error("alert delivery to %s failed: %s", channel, exc)
                results.append({"channel": channel, "status": "failed", "error": str(exc)[:300]})
        return results

    # -- helpers -----------------------------------------------------------

    @staticmethod
    def _in_cooldown(rule: Mapping[str, Any]) -> bool:
        last = rule.get("last_fired_ms")
        if not last:
            return False
        return (now_ms() - last) < int(rule.get("cooldown_s", 300)) * 1000

    @staticmethod
    def _matches(spec: Mapping[str, Any], event: Mapping[str, Any]) -> bool:
        """Filter an event against a rule spec.

        Supported keys: action, severity, min_severity, stage, application,
        environment, category, detector, principal_id, tenant. Every key given
        must match; list values mean "any of".
        """
        def any_of(value: Any, expected: Any) -> bool:
            wanted = expected if isinstance(expected, (list, tuple, set)) else [expected]
            return value in wanted

        for key, expected in spec.items():
            if key in ("window_s", "count", "group_by", "filter", "kinds", "min_severity"):
                continue
            if key == "category":
                if not set(event.get("categories") or []) & set(
                    expected if isinstance(expected, (list, tuple)) else [expected]
                ):
                    return False
            elif key == "detector":
                if not set(event.get("detectors_fired") or []) & set(
                    expected if isinstance(expected, (list, tuple)) else [expected]
                ):
                    return False
            elif not any_of(event.get(key), expected):
                return False

        min_severity = spec.get("min_severity")
        return not (
            min_severity
            and SEVERITY_RANK.get(event.get("severity", "info"), 0) < SEVERITY_RANK.get(min_severity, 0)
        )


def default_rules() -> list[dict[str, Any]]:
    """Rules seeded on first start.

    Chosen so a fresh deployment alerts on the things nobody would argue about,
    and nothing else. Anything noisier is left for the operator to add
    deliberately.
    """
    return [
        {
            "id": "rule_credential_leak",
            "name": "Credential material blocked",
            "description": "A live credential was about to reach a model provider, or appeared in a response.",
            "kind": "match",
            "severity": "critical",
            "spec": {"detector": ["secrets", "secret_leakage"], "action": ["block"]},
            "channels": ["log", "webhook", "slack"],
            "cooldown_s": 300,
        },
        {
            "id": "rule_indirect_injection",
            "name": "Indirect prompt injection blocked",
            "description": "Injected instructions were found in retrieved or tool-supplied content.",
            "kind": "match",
            "severity": "high",
            "spec": {"category": ["prompt_injection"], "stage": ["retrieval", "tool_result", "memory_write"]},
            "channels": ["log", "slack"],
            "cooldown_s": 600,
        },
        {
            "id": "rule_unsafe_tool_flow",
            "name": "Unauthorised tool execution blocked",
            "description": "Low-authority content attempted to drive a privileged tool call.",
            "kind": "match",
            "severity": "critical",
            "spec": {"category": ["unsafe_flow", "excessive_agency", "memory_provenance_laundering"], "action": ["block"]},
            "channels": ["log", "webhook", "slack"],
            "cooldown_s": 300,
        },
        {
            "id": "rule_injection_burst",
            "name": "Repeated injection attempts from one principal",
            "kind": "threshold",
            "severity": "high",
            "spec": {
                "window_s": 300,
                "count": 10,
                "group_by": "principal_id",
                "filter": {"action": ["block", "challenge"], "category": ["prompt_injection", "multi_turn_attack"]},
            },
            "channels": ["log", "slack"],
            "cooldown_s": 900,
        },
        {
            "id": "rule_anomalies",
            "name": "Cross-application anomaly",
            "kind": "anomaly",
            "severity": "high",
            "spec": {"min_severity": "high"},
            "channels": ["log", "slack"],
            "cooldown_s": 900,
        },
    ]
