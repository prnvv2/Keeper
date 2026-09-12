/**
 * Fleet inventory.
 *
 * The page that catches the quiet failures: an application still running a
 * months-old SDK, an instance that stopped reporting last Tuesday, a
 * production service left in monitor-only mode after a rollout, a policy
 * version that never propagated. None of those generate an alert on their own,
 * and all of them mean the security picture is less complete than it looks.
 */

import { api } from "../lib/api";
import {
  Card,
  Empty,
  ErrorBanner,
  Json,
  Loading,
  Stat,
  Tag,
  formatTime,
  timeAgo,
  useApi,
} from "../components/ui";

const EXPECTED_DETECTORS = ["secrets", "pii", "prompt_injection"];

export default function Fleet() {
  const fleet = useApi(() => api.fleet(), [], 15_000);

  if (fleet.loading && !fleet.data) return <Loading label="Loading fleet" />;

  const data = fleet.data;
  const versions = Object.entries(data?.sdk_versions ?? {}).sort((a, b) => b[1] - a[1]);
  const policies = Object.entries(data?.policy_versions ?? {}).sort((a, b) => b[1] - a[1]);

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Fleet</h1>
          <p>
            Every application running the SDK, which version, which policy, and whether it is still
            reporting.
          </p>
        </div>
        <button className="ghost" onClick={fleet.reload}>
          Refresh
        </button>
      </div>

      <ErrorBanner error={fleet.error} />

      {data ? (
        <>
          <div className="grid cols-4" style={{ marginBottom: 14 }}>
            <Stat label="Instances" value={data.total} />
            <Stat label="Healthy" value={data.healthy} tone="var(--allow)" sub="reported in last 5 min" />
            <Stat
              label="Stale"
              value={data.stale}
              tone={data.stale ? "var(--high)" : undefined}
              sub="no telemetry recently"
            />
            <Stat
              label="Monitor only"
              value={data.monitor_only.length}
              tone={data.monitor_only.length ? "var(--flag)" : undefined}
              sub="detecting but not blocking"
            />
          </div>

          <div className="grid cols-2" style={{ marginBottom: 14 }}>
            <Card title="SDK versions in production">
              {versions.length ? (
                <div className="row" style={{ gap: 8 }}>
                  {versions.map(([version, count], index) => (
                    <Tag key={version} tone={index === 0 ? "low" : "medium"}>
                      {version} × {count}
                    </Tag>
                  ))}
                </div>
              ) : (
                <Empty>No instances registered.</Empty>
              )}
              {versions.length > 1 ? (
                <p className="faint" style={{ fontSize: 12, marginBottom: 0, marginTop: 10 }}>
                  More than one SDK version is live. Instances on older versions may be missing detectors
                  or fixes shipped since.
                </p>
              ) : null}
            </Card>

            <Card title="Policy versions in force">
              {policies.length ? (
                <div className="row" style={{ gap: 8 }}>
                  {policies.map(([version, count], index) => (
                    <Tag key={version} tone={index === 0 ? "low" : "medium"}>
                      {version} × {count}
                    </Tag>
                  ))}
                </div>
              ) : (
                <Empty>No policy versions reported.</Empty>
              )}
              {policies.length > 1 ? (
                <p className="faint" style={{ fontSize: 12, marginBottom: 0, marginTop: 10 }}>
                  Policy propagates on each instance's next pull, so a spread here is expected briefly
                  after publishing — and a problem if it persists.
                </p>
              ) : null}
            </Card>
          </div>

          <Card title="Instances">
            {data.instances.length ? (
              <div className="table-wrap">
                <table>
                  <thead>
                    <tr>
                      <th>Status</th>
                      <th>Application</th>
                      <th>Environment</th>
                      <th>SDK</th>
                      <th>Policy</th>
                      <th>Coverage</th>
                      <th className="right">Events</th>
                      <th>Last seen</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.instances.map((instance) => {
                      const missing = EXPECTED_DETECTORS.filter((d) => !instance.detectors.includes(d));
                      return (
                        <tr key={instance.instance_id}>
                          <td>
                            <span className={`badge ${instance.status === "healthy" ? "low" : "high"}`}>
                              {instance.status}
                            </span>
                          </td>
                          <td>
                            <div>{instance.application}</div>
                            <div className="faint mono" style={{ fontSize: 11.5 }}>
                              {instance.instance_id.slice(0, 18)}…
                            </div>
                          </td>
                          <td className="dim">{instance.environment}</td>
                          <td className="mono dim">
                            {instance.sdk_version ?? "—"}
                            <div className="faint" style={{ fontSize: 11.5 }}>
                              {instance.language}
                            </div>
                          </td>
                          <td className="mono dim">
                            {instance.policy_id ? `${instance.policy_id}@${instance.policy_version}` : "—"}
                          </td>
                          <td>
                            {instance.monitor_only ? (
                              <Tag tone="flag">monitor only</Tag>
                            ) : missing.length ? (
                              <Tag tone="high">missing: {missing.join(", ")}</Tag>
                            ) : (
                              <Tag tone="low">{instance.detectors.length} detectors</Tag>
                            )}
                          </td>
                          <td className="right mono dim">{(instance.events_received ?? 0).toLocaleString()}</td>
                          <td className="nowrap dim" title={formatTime(instance.last_seen_ms)}>
                            {timeAgo(instance.last_seen_ms)}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <Empty>
                No SDK instances have registered.
                <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
                  Point an application at this control plane with <code>endpoint=</code> and it will
                  appear here on first request.
                </div>
              </Empty>
            )}
          </Card>

          {data.instances.some((i) => Object.keys(i.health ?? {}).length) ? (
            <Card title="Instance health detail">
              <details>
                <summary className="dim" style={{ cursor: "pointer" }}>
                  Raw health snapshots reported by each SDK
                </summary>
                <Json
                  value={Object.fromEntries(
                    data.instances.filter((i) => Object.keys(i.health ?? {}).length).map((i) => [i.instance_id, i.health]),
                  )}
                />
              </details>
            </Card>
          ) : null}
        </>
      ) : null}
    </>
  );
}
