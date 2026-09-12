/**
 * Alerts and alert rules.
 *
 * The delivery column is not decoration. The worst alerting failure is not a
 * missing rule — it is a rule that fires correctly into a webhook that has been
 * returning 500 for a fortnight, which nobody notices because the dashboard
 * shows the alert as having happened. So every alert records what happened to
 * each channel, and failures are shown in red next to the alert they belong to.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type AlertRule } from "../lib/api";
import {
  Card,
  Empty,
  ErrorBanner,
  Json,
  Loading,
  SeverityBadge,
  Tag,
  formatTime,
  timeAgo,
  useApi,
} from "../components/ui";

export default function Alerts() {
  const [openOnly, setOpenOnly] = useState(false);
  const [testing, setTesting] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);

  const alerts = useApi(() => api.alerts(openOnly), [openOnly], 15_000);
  const rules = useApi(() => api.alertRules(), []);

  const acknowledge = async (id: string) => {
    try {
      await api.acknowledge(id);
      alerts.reload();
    } catch (err) {
      setError(err);
    }
  };

  const toggleRule = async (rule: AlertRule) => {
    try {
      await api.saveAlertRule({ ...rule, enabled: !rule.enabled });
      rules.reload();
    } catch (err) {
      setError(err);
    }
  };

  const test = async (channels: string[]) => {
    setTesting(channels.join(","));
    setError(null);
    try {
      const result = await api.testAlert(channels);
      const failed = result.delivery.filter((d) => d.status !== "delivered");
      setError(
        failed.length
          ? new Error(`Delivery problems: ${failed.map((d) => `${d.channel}=${d.status}`).join(", ")}`)
          : null,
      );
      if (!failed.length) alerts.reload();
    } catch (err) {
      setError(err);
    } finally {
      setTesting(null);
    }
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Alerts</h1>
          <p>What fired, whether it reached anyone, and the rules that decide.</p>
        </div>
        <div className="row">
          <label className="row dim" style={{ fontSize: 13, gap: 5 }}>
            <input type="checkbox" checked={openOnly} onChange={(e) => setOpenOnly(e.target.checked)} />
            unacknowledged only
          </label>
          <button className="ghost" onClick={alerts.reload}>
            Refresh
          </button>
        </div>
      </div>

      <ErrorBanner error={error ?? alerts.error} />

      <div className="stack">
        <Card title="Recent alerts">
          {alerts.loading && !alerts.data ? (
            <Loading />
          ) : alerts.data?.alerts.length ? (
            <div className="stack">
              {alerts.data.alerts.map((alert) => {
                const failedDelivery = (alert.delivery ?? []).filter((d) => d.status !== "delivered");
                const examples: string[] = (alert.context?.examples ?? []).filter(Boolean);
                return (
                  <div
                    key={alert.id}
                    className="card"
                    style={{
                      background: "var(--surface-2)",
                      borderLeft: `3px solid var(--${alert.severity})`,
                    }}
                  >
                    <div className="row" style={{ justifyContent: "space-between" }}>
                      <div className="row">
                        <SeverityBadge severity={alert.severity} />
                        <strong>{alert.title}</strong>
                        {alert.acknowledged_ms ? (
                          <Tag tone="low">acknowledged by {alert.acknowledged_by}</Tag>
                        ) : null}
                      </div>
                      <div className="row">
                        <span className="faint nowrap" title={formatTime(alert.created_ms)}>
                          {timeAgo(alert.created_ms)}
                        </span>
                        {!alert.acknowledged_ms ? (
                          <button className="ghost" onClick={() => void acknowledge(alert.id)}>
                            Acknowledge
                          </button>
                        ) : null}
                      </div>
                    </div>

                    <p className="dim" style={{ margin: "6px 0" }}>
                      {alert.description}
                    </p>

                    <div className="row" style={{ gap: 6 }}>
                      {Object.entries(alert.context?.entities ?? {}).map(([key, value]) => (
                        <Tag key={key}>
                          {key}: {String(value)}
                        </Tag>
                      ))}
                      {(alert.delivery ?? []).map((delivery, i) => (
                        <Tag key={i} tone={delivery.status === "delivered" ? "low" : "critical"}>
                          {delivery.channel}: {delivery.status}
                        </Tag>
                      ))}
                    </div>

                    {failedDelivery.length ? (
                      <div className="banner error" style={{ marginTop: 8, marginBottom: 0 }}>
                        This alert did not reach {failedDelivery.map((d) => d.channel).join(", ")}:{" "}
                        {failedDelivery.map((d) => d.error ?? d.status).join("; ")}
                      </div>
                    ) : null}

                    {examples.length ? (
                      <div className="row" style={{ marginTop: 8, gap: 8 }}>
                        <span className="faint" style={{ fontSize: 12 }}>
                          Investigate:
                        </span>
                        {examples.slice(0, 5).map((id) => (
                          <Link key={id} className="mono" to={`/investigate/${id}`}>
                            {id.slice(0, 16)}…
                          </Link>
                        ))}
                      </div>
                    ) : null}
                  </div>
                );
              })}
            </div>
          ) : (
            <Empty>No alerts have fired.</Empty>
          )}
        </Card>

        <Card
          title="Alert rules"
          actions={
            <div className="row">
              <button className="ghost" disabled={testing !== null} onClick={() => void test(["log"])}>
                Test log
              </button>
              <button className="ghost" disabled={testing !== null} onClick={() => void test(["slack", "webhook"])}>
                Test slack + webhook
              </button>
              {testing ? <span className="spinner" /> : null}
            </div>
          }
        >
          {rules.loading && !rules.data ? (
            <Loading />
          ) : rules.data?.rules.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Kind</th>
                    <th>Severity</th>
                    <th>Channels</th>
                    <th>Cooldown</th>
                    <th>Last fired</th>
                    <th />
                  </tr>
                </thead>
                <tbody>
                  {rules.data.rules.map((rule) => (
                    <tr key={rule.id}>
                      <td>
                        <div>{rule.name}</div>
                        <div className="faint" style={{ fontSize: 12 }}>
                          {rule.description}
                        </div>
                        <details style={{ marginTop: 4 }}>
                          <summary className="dim" style={{ cursor: "pointer", fontSize: 11.5 }}>
                            Condition
                          </summary>
                          <Json value={rule.spec} />
                        </details>
                      </td>
                      <td>
                        <Tag>{rule.kind}</Tag>
                      </td>
                      <td>
                        <SeverityBadge severity={rule.severity} />
                      </td>
                      <td className="mono dim">{rule.channels.join(", ")}</td>
                      <td className="mono dim">{rule.cooldown_s}s</td>
                      <td className="nowrap dim">
                        {rule.last_fired_ms ? timeAgo(rule.last_fired_ms) : <span className="faint">never</span>}
                      </td>
                      <td className="right">
                        <button className="ghost" onClick={() => void toggleRule(rule)}>
                          {rule.enabled ? "Disable" : "Enable"}
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No alert rules configured.</Empty>
          )}
          <p className="faint" style={{ fontSize: 12, marginBottom: 0, marginTop: 10 }}>
            Cooldowns exist because the failure mode of alerting is not a missed alert — it is four
            hundred alerts, after which people mute the channel.
          </p>
        </Card>
      </div>
    </>
  );
}
