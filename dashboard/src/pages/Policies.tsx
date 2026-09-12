/**
 * Policy authoring, dry-run, and publication.
 *
 * The dry-run panel is the point of this page. Publishing a policy change
 * straight to a fleet enforcing it in production is how a security team causes
 * an outage; replaying the change against real recorded traffic first turns
 * "this looks fine" into "this would have changed 14 of the last 5,000
 * requests, here they are".
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type PolicyRecord } from "../lib/api";
import {
  ActionBadge,
  Card,
  Empty,
  ErrorBanner,
  Json,
  Loading,
  Tag,
  formatTime,
  useApi,
} from "../components/ui";

const STARTER = `{
  "id": "acme.default",
  "version": "1.0.0",
  "description": "What this policy is for, and who owns it.",
  "defaults": { "action": "allow" },
  "rules": [
    {
      "id": "block-credential-egress",
      "description": "Never let live credentials reach a model provider.",
      "when": { "detector_fired": ["secrets", "secret_leakage"] },
      "action": "block",
      "severity": "critical",
      "message": "This request contains credential material and was blocked."
    },
    {
      "id": "redact-pii",
      "when": { "detector_fired": "pii" },
      "action": "redact",
      "stop": false
    }
  ]
}`;

export default function Policies() {
  const [bundle, setBundle] = useState("default");
  const [draft, setDraft] = useState(STARTER);
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [report, setReport] = useState<Awaited<ReturnType<typeof api.dryRun>> | null>(null);

  const policies = useApi(() => api.policies(), []);

  const parsed = (): unknown => {
    try {
      return JSON.parse(draft);
    } catch (err) {
      throw new Error(`Draft is not valid JSON: ${(err as Error).message}`);
    }
  };

  const run = async (action: "dry-run" | "save" | "publish") => {
    setBusy(true);
    setError(null);
    setMessage(null);
    try {
      const policy = parsed();
      if (action === "dry-run") {
        setReport(await api.dryRun(policy, 24));
        setMessage("Dry run complete — nothing was published.");
      } else {
        const result = await api.publishPolicy(bundle, policy, action === "publish", note);
        setMessage(
          action === "publish"
            ? `Published ${result.policy.version} to bundle "${bundle}". Instances will pick it up on their next poll.`
            : `Saved ${result.policy.version} without publishing.`,
        );
        policies.reload();
      }
    } catch (err) {
      setError(err);
    } finally {
      setBusy(false);
    }
  };

  const load = (record: PolicyRecord) => {
    setDraft(JSON.stringify(record.document, null, 2));
    setBundle(record.bundle);
    setReport(null);
    setMessage(`Loaded ${record.bundle}@${record.version} into the editor.`);
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Policy</h1>
          <p>
            Author here, enforce everywhere. SDK instances pull the published bundle on an interval and
            cache it locally, so a change takes effect within one refresh period and survives this
            service being unreachable.
          </p>
        </div>
      </div>

      <div className="grid cols-2" style={{ alignItems: "start" }}>
        <div className="stack">
          <Card title="Editor">
            <div className="filters">
              <label className="dim" style={{ fontSize: 12 }}>
                bundle
              </label>
              <input type="text" value={bundle} onChange={(e) => setBundle(e.target.value)} style={{ width: 140 }} />
              <input
                type="text"
                placeholder="change note (optional)"
                value={note}
                onChange={(e) => setNote(e.target.value)}
                style={{ flex: 1 }}
              />
            </div>
            <textarea rows={24} value={draft} onChange={(e) => setDraft(e.target.value)} spellCheck={false} />
            <div className="row" style={{ marginTop: 10 }}>
              <button onClick={() => void run("dry-run")} disabled={busy}>
                Dry run against last 24h
              </button>
              <button onClick={() => void run("save")} disabled={busy}>
                Save unpublished
              </button>
              <button className="primary" onClick={() => void run("publish")} disabled={busy}>
                Publish to fleet
              </button>
              {busy ? <span className="spinner" /> : null}
            </div>
            <p className="faint" style={{ fontSize: 12, marginBottom: 0 }}>
              Versions are immutable: republishing a version with different content is refused, so an
              audit row recorded under <span className="mono">1.4.0</span> can always be explained by the
              exact bundle that produced it. Bump the version instead.
            </p>
          </Card>

          {message ? <div className="banner warn">{message}</div> : null}
          <ErrorBanner error={error} />

          {report ? (
            <Card title="Dry-run result">
              <div className="grid cols-3" style={{ marginBottom: 12 }}>
                <div className="stat">
                  <span className="label">Replayed</span>
                  <span className="value" style={{ fontSize: 20 }}>
                    {report.events_replayed.toLocaleString()}
                  </span>
                </div>
                <div className="stat">
                  <span className="label">Would change</span>
                  <span
                    className="value"
                    style={{ fontSize: 20, color: report.changed ? "var(--high)" : "var(--allow)" }}
                  >
                    {report.changed.toLocaleString()}
                  </span>
                </div>
                <div className="stat">
                  <span className="label">Policy</span>
                  <span className="value mono" style={{ fontSize: 15 }}>
                    {report.policy}
                  </span>
                </div>
              </div>

              <h3>Transitions</h3>
              <div className="row" style={{ gap: 8, marginBottom: 12 }}>
                {Object.entries(report.transitions).map(([transition, count]) => {
                  const [from, to] = transition.split("->");
                  return (
                    <span key={transition} className="row" style={{ gap: 4 }}>
                      <ActionBadge action={from as never} />
                      <span className="faint">→</span>
                      <ActionBadge action={to as never} />
                      <span className="mono dim">{count}</span>
                    </span>
                  );
                })}
              </div>

              {report.examples.length ? (
                <>
                  <h3>Affected requests</h3>
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>Correlation</th>
                          <th>From</th>
                          <th>To</th>
                          <th>Rules</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.examples.slice(0, 20).map((example) => (
                          <tr key={example.event_id}>
                            <td>
                              <Link className="mono" to={`/investigate/${example.correlation_id}`}>
                                {example.correlation_id.slice(0, 16)}…
                              </Link>
                            </td>
                            <td>
                              <ActionBadge action={example.from as never} />
                            </td>
                            <td>
                              <ActionBadge action={example.to as never} />
                            </td>
                            <td className="mono dim">{example.rules.filter(Boolean).join(", ")}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <Empty>This policy would not change any recorded decision.</Empty>
              )}
            </Card>
          ) : null}
        </div>

        <Card title="Versions">
          {policies.loading && !policies.data ? (
            <Loading />
          ) : policies.data?.policies.length ? (
            <div className="stack">
              {policies.data.policies.map((record) => (
                <div
                  key={`${record.bundle}-${record.version}-${record.created_ms}`}
                  className="card"
                  style={{ background: "var(--surface-2)" }}
                >
                  <div className="row" style={{ justifyContent: "space-between" }}>
                    <div className="row">
                      <strong className="mono">
                        {record.bundle}@{record.version}
                      </strong>
                      {record.published ? <Tag tone="low">published</Tag> : <Tag>draft</Tag>}
                    </div>
                    <button className="ghost" onClick={() => load(record)}>
                      Load
                    </button>
                  </div>
                  <div className="faint" style={{ fontSize: 12 }}>
                    {formatTime(record.created_ms)}
                    {record.created_by ? ` · ${record.created_by}` : ""}
                    {` · ${(record.document.rules ?? []).length} rules`}
                  </div>
                  {record.note ? (
                    <div className="dim" style={{ fontSize: 12.5, marginTop: 4 }}>
                      {record.note}
                    </div>
                  ) : null}
                  <details style={{ marginTop: 6 }}>
                    <summary className="dim" style={{ cursor: "pointer", fontSize: 12 }}>
                      Document
                    </summary>
                    <Json value={record.document} />
                  </details>
                </div>
              ))}
            </div>
          ) : (
            <Empty>No policies stored yet.</Empty>
          )}
        </Card>
      </div>
    </>
  );
}
