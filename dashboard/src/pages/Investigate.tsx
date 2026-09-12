/**
 * Correlation view: one request, every stage, in order.
 *
 * This is where a single flagged event becomes an incident narrative. An
 * investigator arrives with a correlation id — from an alert, a SIEM record, or
 * an error message a user quoted — and needs to see what the whole interaction
 * did: what came in, which documents were retrieved, which tools were attempted,
 * what came out, and where the firewall intervened.
 */

import { useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { api, type AuditEvent } from "../lib/api";
import {
  ACTION_COLOR,
  ActionBadge,
  Card,
  Empty,
  ErrorBanner,
  Loading,
  SeverityBadge,
  Tag,
  formatTime,
  useApi,
} from "../components/ui";
import { EventDrawer } from "./Events";

export default function Investigate() {
  const { correlationId } = useParams<{ correlationId: string }>();
  const navigate = useNavigate();
  const [query, setQuery] = useState(correlationId ?? "");
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const view = useApi(
    () => (correlationId ? api.correlation(correlationId) : Promise.resolve(null)),
    [correlationId],
  );

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Investigate</h1>
          <p>
            Reconstruct a single AI interaction end to end, from the correlation id the SDK returned to
            the caller.
          </p>
        </div>
      </div>

      <Card>
        <div className="filters" style={{ marginBottom: 0 }}>
          <input
            type="search"
            placeholder="Correlation id, e.g. req_3f19c0…"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && query.trim()) navigate(`/investigate/${query.trim()}`);
            }}
          />
          <button className="primary" disabled={!query.trim()} onClick={() => navigate(`/investigate/${query.trim()}`)}>
            Trace
          </button>
        </div>
      </Card>

      {correlationId ? (
        <div style={{ marginTop: 14 }}>
          <ErrorBanner error={view.error} />
          {view.loading ? (
            <Loading label="Reconstructing interaction" />
          ) : view.data ? (
            <div className="stack">
              <Card title="Summary">
                <div className="grid cols-4" style={{ gap: 12 }}>
                  <div className="stat">
                    <span className="label">Outcome</span>
                    <span className="value" style={{ fontSize: 18 }}>
                      <ActionBadge action={view.data.summary.outcome} />
                    </span>
                  </div>
                  <div className="stat">
                    <span className="label">Stages</span>
                    <span className="value" style={{ fontSize: 18 }}>
                      {view.data.events.length}
                    </span>
                    <span className="sub">{view.data.summary.stages.join(" → ")}</span>
                  </div>
                  <div className="stat">
                    <span className="label">Duration</span>
                    <span className="value" style={{ fontSize: 18 }}>
                      {view.data.summary.duration_ms} ms
                    </span>
                    <span className="sub">{formatTime(view.data.summary.started_ms)}</span>
                  </div>
                  <div className="stat">
                    <span className="label">Principal</span>
                    <span className="value mono" style={{ fontSize: 15 }}>
                      {view.data.summary.principal_id ?? "anonymous"}
                    </span>
                    <span className="sub">{view.data.summary.application}</span>
                  </div>
                </div>
                {view.data.summary.detectors_fired.length ? (
                  <div className="row" style={{ marginTop: 14, gap: 6 }}>
                    <span className="dim" style={{ fontSize: 12 }}>
                      Detectors fired:
                    </span>
                    {view.data.summary.detectors_fired.map((detector) => (
                      <Tag key={detector}>{detector}</Tag>
                    ))}
                  </div>
                ) : null}
                <dl className="kv" style={{ marginTop: 14 }}>
                  <dt>Policy</dt>
                  <dd className="mono">{view.data.summary.policy_version ?? "—"}</dd>
                  <dt>Model</dt>
                  <dd className="mono">{view.data.summary.model ?? "—"}</dd>
                  <dt>Session</dt>
                  <dd className="mono">{view.data.summary.session_id ?? "—"}</dd>
                  <dt>Trace</dt>
                  <dd className="mono">{view.data.summary.trace_id ?? "—"}</dd>
                </dl>
              </Card>

              <Card title="Timeline">
                <div className="stack" style={{ gap: 0 }}>
                  {view.data.events.map((event, index) => {
                    const fired = event.findings.filter((f) => f.detected);
                    const last = index === view.data!.events.length - 1;
                    const elapsed = event.timestamp_ms - view.data!.summary.started_ms;
                    return (
                      <div className="trace-step" key={event.event_id}>
                        <div className="trace-rail">
                          <span className="trace-dot" style={{ background: ACTION_COLOR[event.action] }} />
                          {!last ? <span className="trace-line" /> : null}
                        </div>
                        <div style={{ paddingBottom: last ? 0 : 18 }}>
                          <div
                            className="row clickable"
                            style={{ cursor: "pointer" }}
                            onClick={() => setSelected(event)}
                          >
                            <strong className="mono">{event.stage}</strong>
                            <ActionBadge action={event.action} />
                            {fired.length ? <SeverityBadge severity={event.severity} /> : null}
                            <span className="faint mono" style={{ marginLeft: "auto" }}>
                              +{elapsed} ms
                            </span>
                          </div>
                          {fired.length ? (
                            <ul style={{ margin: "6px 0 0", paddingLeft: 18 }}>
                              {fired.map((finding, i) => (
                                <li key={i} style={{ marginBottom: 2 }}>
                                  <span className="mono">{finding.detector}</span>{" "}
                                  <span className="dim">{finding.summary}</span>
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <div className="faint" style={{ fontSize: 12.5, marginTop: 3 }}>
                              no findings
                            </div>
                          )}
                          {event.tags?.tool ? (
                            <div className="row" style={{ marginTop: 6, gap: 5 }}>
                              <Tag>tool: {String(event.tags.tool)}</Tag>
                              {event.tags.trust ? <Tag>trust: {String(event.tags.trust)}</Tag> : null}
                            </div>
                          ) : null}
                          <button className="ghost" style={{ marginTop: 6 }} onClick={() => setSelected(event)}>
                            Details →
                          </button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </Card>
            </div>
          ) : (
            <Empty>No events found for that correlation id.</Empty>
          )}
        </div>
      ) : (
        <div style={{ marginTop: 14 }}>
          <Empty>
            Paste a correlation id to reconstruct the interaction.
            <div className="faint" style={{ fontSize: 12, marginTop: 8 }}>
              The SDK returns one on every response, and every blocked request quotes it to the caller.
            </div>
          </Empty>
        </div>
      )}

      {selected ? <EventDrawer event={selected} onClose={() => setSelected(null)} /> : null}
    </>
  );
}
