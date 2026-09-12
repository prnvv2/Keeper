/**
 * The "what is happening right now" page.
 *
 * Everything above the fold answers a question someone actually asks when they
 * open a security dashboard: how much AI traffic is there, how much of it is
 * being stopped, is the firewall itself healthy, and is anything on fire. The
 * detail lives one click away in Events and Investigate.
 */

import { Link } from "react-router-dom";
import { api } from "../lib/api";
import {
  ACTION_COLOR,
  BarRow,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  SeverityBadge,
  Stat,
  TimelineChart,
  formatTime,
  timeAgo,
  useApi,
} from "../components/ui";

const REFRESH_MS = 10_000;

export default function Overview() {
  const overview = useApi(() => api.overview(24), [], REFRESH_MS);
  const timeline = useApi(() => api.timeline(6, 2), [], REFRESH_MS);
  const anomalies = useApi(() => api.anomalies(30), [], 30_000);
  const health = useApi(() => api.health(), [], 30_000);

  if (overview.loading && !overview.data) return <Loading label="Loading live traffic" />;

  const data = overview.data;
  const warnings: string[] = (health.data?.warnings as string[]) ?? [];

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Live traffic</h1>
          <p>
            Every instrumented application, last 24 hours. Refreshing every {REFRESH_MS / 1000} seconds.
          </p>
        </div>
        <div className="row">
          {health.data ? (
            <span className={`badge ${health.data.status === "ok" ? "low" : "medium"}`}>
              control plane {String(health.data.status)}
            </span>
          ) : null}
          <button className="ghost" onClick={overview.reload}>
            Refresh
          </button>
        </div>
      </div>

      <ErrorBanner error={overview.error} />
      {warnings.map((warning) => (
        <div className="banner warn" key={warning}>
          {warning}
        </div>
      ))}

      {data ? (
        <>
          <div className="grid cols-4" style={{ marginBottom: 14 }}>
            <Stat label="Requests" value={data.total_events.toLocaleString()} sub="decisions recorded" />
            <Stat
              label="Blocked"
              value={data.blocked.toLocaleString()}
              sub={`${(data.block_rate * 100).toFixed(2)}% of traffic`}
              tone={data.blocked ? "var(--block)" : undefined}
            />
            <Stat
              label="Firewall overhead"
              value={`${data.avg_latency_ms.toFixed(1)} ms`}
              sub={`peak ${data.max_latency_ms.toFixed(0)} ms`}
            />
            <Stat label="Live SDK instances" value={data.active_instances} sub="reporting in" />
          </div>

          <div className="stack">
            <Card title="Traffic by decision — last 6 hours">
              {timeline.data ? <TimelineChart buckets={timeline.data.buckets as never} /> : <Loading />}
            </Card>

            <div className="grid cols-2">
              <Card title="Applications">
                {data.top_applications.length ? (
                  data.top_applications.slice(0, 8).map((app) => (
                    <BarRow
                      key={app.application}
                      label={
                        <Link to={`/events?application=${encodeURIComponent(app.application)}`}>
                          {app.application}
                        </Link>
                      }
                      value={app.events}
                      max={data.top_applications[0].events}
                    />
                  ))
                ) : (
                  <Empty>No applications have reported yet.</Empty>
                )}
              </Card>

              <Card title="Decisions">
                {Object.entries(data.by_action).length ? (
                  Object.entries(data.by_action)
                    .sort((a, b) => b[1]! - a[1]!)
                    .map(([action, count]) => (
                      <BarRow
                        key={action}
                        label={<span className={`badge ${action}`}>{action}</span>}
                        value={count!}
                        max={data.total_events}
                        color={ACTION_COLOR[action as keyof typeof ACTION_COLOR] ?? "var(--accent)"}
                        hint={`${count!.toLocaleString()} (${((count! / data.total_events) * 100).toFixed(1)}%)`}
                      />
                    ))
                ) : (
                  <Empty>Nothing recorded yet.</Empty>
                )}
              </Card>
            </div>

            <div className="grid cols-2">
              <Card title="Cross-application anomalies">
                {anomalies.data?.findings.length ? (
                  <div className="stack">
                    {anomalies.data.findings.slice(0, 5).map((finding, i) => (
                      <div key={i} style={{ borderLeft: "3px solid var(--border)", paddingLeft: 10 }}>
                        <div className="row">
                          <SeverityBadge severity={finding.severity} />
                          <strong>{finding.title}</strong>
                        </div>
                        <div className="dim" style={{ fontSize: 13 }}>
                          {finding.description}
                        </div>
                        {finding.examples.length ? (
                          <div className="row" style={{ marginTop: 4, gap: 6 }}>
                            {finding.examples.slice(0, 3).map((id) => (
                              <Link key={id} className="mono" to={`/investigate/${id}`}>
                                {id.slice(0, 14)}…
                              </Link>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    ))}
                  </div>
                ) : (
                  <Empty>
                    Nothing unusual across the fleet.
                    <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
                      Patterns here span applications — the kind no single SDK instance can see.
                    </div>
                  </Empty>
                )}
              </Card>

              <Card title="Most blocked principals">
                {data.top_offenders.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Principal</th>
                          <th>Application</th>
                          <th className="right">Blocked</th>
                        </tr>
                      </thead>
                      <tbody>
                        {data.top_offenders.map((row, i) => (
                          <tr key={i}>
                            <td className="mono">{row.principal_id ?? "anonymous"}</td>
                            <td>{row.application}</td>
                            <td className="right">
                              <Link
                                to={`/events?principal_id=${encodeURIComponent(row.principal_id ?? "")}&action=block`}
                              >
                                {row.blocked_events}
                              </Link>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty>Nothing has been blocked in this window.</Empty>
                )}
              </Card>
            </div>

            <Card title="Recent alerts" actions={<Link to="/alerts">All alerts →</Link>}>
              {data.recent_alerts.length ? (
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>Severity</th>
                        <th>Alert</th>
                        <th>When</th>
                        <th>Status</th>
                      </tr>
                    </thead>
                    <tbody>
                      {data.recent_alerts.map((alert) => (
                        <tr key={alert.id}>
                          <td>
                            <SeverityBadge severity={alert.severity} />
                          </td>
                          <td>
                            <div>{alert.title}</div>
                            <div className="faint" style={{ fontSize: 12 }}>
                              {alert.description}
                            </div>
                          </td>
                          <td className="nowrap dim" title={formatTime(alert.created_ms)}>
                            {timeAgo(alert.created_ms)}
                          </td>
                          <td>
                            {alert.acknowledged_ms ? (
                              <span className="badge low">acknowledged</span>
                            ) : (
                              <span className="badge medium">open</span>
                            )}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <Empty>No alerts have fired.</Empty>
              )}
            </Card>
          </div>
        </>
      ) : null}
    </>
  );
}
