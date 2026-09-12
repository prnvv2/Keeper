/**
 * Observability analytics: turning the audit trail into decisions.
 *
 * Three questions this page exists to answer, none of which a raw event list
 * answers well:
 *
 *  - Which detectors are earning the latency they cost? (hit rate vs. runtime)
 *  - Which policy rules actually fire, and which are dead weight?
 *  - What is happening across applications that no single instance can see?
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import {
  BarRow,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  SeverityBadge,
  Tag,
  useApi,
} from "../components/ui";

export default function Analytics() {
  const [hours, setHours] = useState(24);
  const detectors = useApi(() => api.detectorStats(hours), [hours]);
  const policy = useApi(() => api.policyStats(hours), [hours]);
  const anomalies = useApi(() => api.anomalies(Math.min(hours * 60, 1440)), [hours]);

  const maxRuns = Math.max(1, ...(detectors.data?.detectors.map((d) => d.runs) ?? [1]));
  const maxLatency = Math.max(0.001, ...(detectors.data?.detectors.map((d) => d.avg_latency_ms) ?? [1]));
  const maxMatches = Math.max(1, ...(policy.data?.rules.map((r) => r.matches) ?? [1]));

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Analytics</h1>
          <p>
            Detector effectiveness, policy behaviour, and cross-application patterns over the selected
            window.
          </p>
        </div>
        <select value={hours} onChange={(e) => setHours(Number(e.target.value))}>
          {[
            [1, "last hour"],
            [24, "last 24 hours"],
            [168, "last 7 days"],
            [720, "last 30 days"],
          ].map(([value, label]) => (
            <option key={value} value={value}>
              {label}
            </option>
          ))}
        </select>
      </div>

      <ErrorBanner error={detectors.error ?? policy.error} />

      <div className="stack">
        <Card title="Detector effectiveness">
          {detectors.loading && !detectors.data ? (
            <Loading />
          ) : detectors.data?.detectors.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Detector</th>
                    <th className="right">Runs</th>
                    <th className="right">Hits</th>
                    <th>Hit rate</th>
                    <th className="right">Avg latency</th>
                    <th className="right">Errors</th>
                    <th>Categories</th>
                  </tr>
                </thead>
                <tbody>
                  {detectors.data.detectors.map((detector) => (
                    <tr key={detector.detector}>
                      <td className="mono">
                        <Link to={`/events?detector=${encodeURIComponent(detector.detector)}&hours=${hours}`}>
                          {detector.detector}
                        </Link>
                      </td>
                      <td className="right mono dim">{detector.runs.toLocaleString()}</td>
                      <td className="right mono">{detector.hits.toLocaleString()}</td>
                      <td style={{ minWidth: 130 }}>
                        <div className="bar-track">
                          <div
                            className="bar-fill"
                            style={{
                              width: `${Math.max(2, detector.hit_rate * 100)}%`,
                              background: detector.hit_rate > 0.3 ? "var(--high)" : "var(--accent)",
                            }}
                          />
                        </div>
                        <span className="faint mono" style={{ fontSize: 11.5 }}>
                          {(detector.hit_rate * 100).toFixed(2)}%
                        </span>
                      </td>
                      <td className="right mono dim">{detector.avg_latency_ms.toFixed(3)} ms</td>
                      <td className="right mono" style={{ color: detector.errors ? "var(--block)" : undefined }}>
                        {detector.errors}
                      </td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {detector.categories.map((category) => (
                            <Tag key={category}>{category}</Tag>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No detector runs recorded in this window.</Empty>
          )}
        </Card>

        <div className="grid cols-2">
          <Card title="Where the latency goes">
            {detectors.data?.detectors.length ? (
              detectors.data.detectors
                .slice()
                .sort((a, b) => b.avg_latency_ms - a.avg_latency_ms)
                .slice(0, 10)
                .map((detector) => (
                  <BarRow
                    key={detector.detector}
                    label={<span className="mono">{detector.detector}</span>}
                    value={detector.avg_latency_ms}
                    max={maxLatency}
                    color="var(--redact)"
                    hint={`${detector.avg_latency_ms.toFixed(3)} ms`}
                  />
                ))
            ) : (
              <Empty>Nothing to show.</Empty>
            )}
          </Card>

          <Card title="Coverage — how often each detector ran">
            {detectors.data?.detectors.length ? (
              detectors.data.detectors
                .slice()
                .sort((a, b) => b.runs - a.runs)
                .slice(0, 10)
                .map((detector) => (
                  <BarRow
                    key={detector.detector}
                    label={<span className="mono">{detector.detector}</span>}
                    value={detector.runs}
                    max={maxRuns}
                    hint={detector.runs.toLocaleString()}
                  />
                ))
            ) : (
              <Empty>Nothing to show.</Empty>
            )}
          </Card>
        </div>

        <Card title="Policy rules that fired">
          {policy.loading && !policy.data ? (
            <Loading />
          ) : policy.data?.rules.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Policy</th>
                    <th className="right">Matches</th>
                    <th>Share</th>
                    <th>Actions</th>
                    <th className="right">Avg eval</th>
                  </tr>
                </thead>
                <tbody>
                  {policy.data.rules.map((rule, i) => (
                    <tr key={i}>
                      <td className="mono">{rule.rule_id ?? "(policy default)"}</td>
                      <td className="dim mono">{rule.policy_id}</td>
                      <td className="right mono">{rule.matches.toLocaleString()}</td>
                      <td style={{ minWidth: 120 }}>
                        <div className="bar-track">
                          <div
                            className="bar-fill"
                            style={{ width: `${(rule.matches / maxMatches) * 100}%`, background: "var(--accent)" }}
                          />
                        </div>
                      </td>
                      <td>
                        <div className="row" style={{ gap: 4 }}>
                          {Object.entries(rule.actions).map(([action, count]) => (
                            <span key={action} className={`badge ${action}`}>
                              {action} {count}
                            </span>
                          ))}
                        </div>
                      </td>
                      <td className="right mono dim">{rule.avg_eval_ms.toFixed(4)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>
              No policy rules matched in this window.
              <div className="faint" style={{ fontSize: 12, marginTop: 6 }}>
                A rule that never fires is either well-targeted or dead weight — check it against a
                dry-run before removing it.
              </div>
            </Empty>
          )}
        </Card>

        <Card title="Cross-application anomalies">
          {anomalies.loading && !anomalies.data ? (
            <Loading />
          ) : anomalies.data?.findings.length ? (
            <div className="stack">
              {anomalies.data.findings.map((finding, i) => (
                <div key={i} className="card" style={{ background: "var(--surface-2)" }}>
                  <div className="row">
                    <SeverityBadge severity={finding.severity} />
                    <strong>{finding.title}</strong>
                    <Tag>{finding.kind}</Tag>
                  </div>
                  <p className="dim" style={{ margin: "6px 0" }}>
                    {finding.description}
                  </p>
                  <div className="row" style={{ gap: 6 }}>
                    {Object.entries(finding.entities).map(([key, value]) => (
                      <Tag key={key}>
                        {key}: {String(value)}
                      </Tag>
                    ))}
                  </div>
                  {finding.examples.length ? (
                    <div className="row" style={{ marginTop: 8, gap: 8 }}>
                      <span className="faint" style={{ fontSize: 12 }}>
                        Investigate:
                      </span>
                      {finding.examples.slice(0, 5).map((id) => (
                        <Link key={id} className="mono" to={`/investigate/${id}`}>
                          {id.slice(0, 16)}…
                        </Link>
                      ))}
                    </div>
                  ) : null}
                </div>
              ))}
            </div>
          ) : (
            <Empty>No cross-application anomalies detected.</Empty>
          )}
        </Card>
      </div>
    </>
  );
}
