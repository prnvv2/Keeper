/**
 * Audit log search — the investigation surface.
 *
 * Filters live in the URL, so a search is a link. That matters more than it
 * sounds: half of incident response is one person pasting a view to another,
 * and a dashboard whose state exists only in component memory cannot be shared.
 */

import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { api, type AuditEvent } from "../lib/api";
import {
  ActionBadge,
  Card,
  Drawer,
  Empty,
  ErrorBanner,
  Json,
  Loading,
  Payload,
  SeverityBadge,
  Tag,
  formatTime,
  timeAgo,
  useApi,
} from "../components/ui";

const PAGE_SIZE = 50;

export default function Events() {
  const [params, setParams] = useSearchParams();
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const filters = {
    q: params.get("q") ?? "",
    application: params.get("application") ?? "",
    action: params.get("action") ?? "",
    min_severity: params.get("min_severity") ?? "",
    stage: params.get("stage") ?? "",
    detector: params.get("detector") ?? "",
    principal_id: params.get("principal_id") ?? "",
    hours: params.get("hours") ?? "24",
  };
  const offset = Number(params.get("offset") ?? 0);

  const page = useApi(
    () => api.events({ ...filters, limit: PAGE_SIZE, offset }),
    [JSON.stringify(filters), offset],
  );

  const update = (key: string, value: string) => {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    next.delete("offset");
    setParams(next);
  };

  const setOffset = (value: number) => {
    const next = new URLSearchParams(params);
    if (value > 0) next.set("offset", String(value));
    else next.delete("offset");
    setParams(next);
  };

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Audit log</h1>
          <p>
            Every decision the firewall has made across the fleet. Filters are in the URL — copy the
            address to share exactly this view.
          </p>
        </div>
      </div>

      <Card>
        <div className="filters">
          <input
            type="search"
            placeholder="Search prompts, responses, detectors, findings…"
            defaultValue={filters.q}
            onKeyDown={(e) => {
              if (e.key === "Enter") update("q", (e.target as HTMLInputElement).value);
            }}
          />
          <select value={filters.action} onChange={(e) => update("action", e.target.value)}>
            <option value="">any action</option>
            {["allow", "flag", "redact", "challenge", "block"].map((a) => (
              <option key={a} value={a}>
                {a}
              </option>
            ))}
          </select>
          <select value={filters.min_severity} onChange={(e) => update("min_severity", e.target.value)}>
            <option value="">any severity</option>
            {["low", "medium", "high", "critical"].map((s) => (
              <option key={s} value={s}>
                {s}+
              </option>
            ))}
          </select>
          <select value={filters.stage} onChange={(e) => update("stage", e.target.value)}>
            <option value="">any stage</option>
            {["input", "output", "stream", "tool_call", "tool_result", "retrieval", "memory_write", "memory_read", "access"].map(
              (s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ),
            )}
          </select>
          <select value={filters.hours} onChange={(e) => update("hours", e.target.value)}>
            {[
              ["1", "last hour"],
              ["24", "last 24h"],
              ["168", "last 7d"],
              ["720", "last 30d"],
            ].map(([value, label]) => (
              <option key={value} value={value}>
                {label}
              </option>
            ))}
          </select>
          <input
            type="text"
            placeholder="application"
            defaultValue={filters.application}
            onKeyDown={(e) => {
              if (e.key === "Enter") update("application", (e.target as HTMLInputElement).value);
            }}
            style={{ width: 150 }}
          />
          <input
            type="text"
            placeholder="detector"
            defaultValue={filters.detector}
            onKeyDown={(e) => {
              if (e.key === "Enter") update("detector", (e.target as HTMLInputElement).value);
            }}
            style={{ width: 140 }}
          />
          {[...params.keys()].length ? (
            <button className="ghost" onClick={() => setParams(new URLSearchParams())}>
              Clear
            </button>
          ) : null}
        </div>

        <ErrorBanner error={page.error} />

        {page.loading && !page.data ? (
          <Loading label="Searching" />
        ) : page.data && page.data.events.length ? (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Action</th>
                    <th>Stage</th>
                    <th>Application</th>
                    <th>Principal</th>
                    <th>Findings</th>
                    <th className="right">Latency</th>
                  </tr>
                </thead>
                <tbody>
                  {page.data.events.map((event) => (
                    <tr key={event.event_id} className="clickable" onClick={() => setSelected(event)}>
                      <td className="nowrap dim" title={formatTime(event.timestamp_ms)}>
                        {timeAgo(event.timestamp_ms)}
                      </td>
                      <td>
                        <ActionBadge action={event.action} />
                      </td>
                      <td className="mono dim">{event.stage}</td>
                      <td>{event.application}</td>
                      <td className="mono dim">{event.principal_id ?? "anonymous"}</td>
                      <td>
                        {event.findings.filter((f) => f.detected).length ? (
                          <div className="row" style={{ gap: 5 }}>
                            {event.findings
                              .filter((f) => f.detected)
                              .slice(0, 3)
                              .map((f, i) => (
                                <span key={i} className={`badge ${f.severity}`} title={f.summary}>
                                  {f.detector}
                                </span>
                              ))}
                          </div>
                        ) : (
                          <span className="faint">clean</span>
                        )}
                      </td>
                      <td className="right mono dim">{event.latency_ms.toFixed(1)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="row" style={{ justifyContent: "space-between", marginTop: 12 }}>
              <span className="dim">
                {offset + 1}–{Math.min(offset + PAGE_SIZE, page.data.total)} of{" "}
                {page.data.total.toLocaleString()}
              </span>
              <div className="row">
                <button disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}>
                  Previous
                </button>
                <button
                  disabled={offset + PAGE_SIZE >= page.data.total}
                  onClick={() => setOffset(offset + PAGE_SIZE)}
                >
                  Next
                </button>
              </div>
            </div>
          </>
        ) : (
          <Empty>No events match these filters.</Empty>
        )}
      </Card>

      {selected ? <EventDrawer event={selected} onClose={() => setSelected(null)} /> : null}
    </>
  );
}

/** Full detail for one decision: who, what, which detector, which rule. */
export function EventDrawer({ event, onClose }: { event: AuditEvent; onClose: () => void }) {
  const fired = event.findings.filter((f) => f.detected);
  const matched = event.policy_traces.filter((t) => t.matched);

  return (
    <Drawer onClose={onClose}>
      <div className="drawer-head">
        <div>
          <div className="row" style={{ marginBottom: 6 }}>
            <ActionBadge action={event.action} />
            <SeverityBadge severity={event.severity} />
            <Tag>{event.stage}</Tag>
          </div>
          <h2>{fired[0]?.summary ?? `${event.action} at ${event.stage}`}</h2>
          <div className="faint mono" style={{ fontSize: 12, marginTop: 4 }}>
            {event.event_id}
          </div>
        </div>
        <button className="ghost" onClick={onClose}>
          Close
        </button>
      </div>

      <div className="stack">
        <Card title="Context">
          <dl className="kv">
            <dt>Time</dt>
            <dd>{formatTime(event.timestamp_ms)}</dd>
            <dt>Correlation</dt>
            <dd>
              <Link className="mono" to={`/investigate/${event.correlation_id}`}>
                {event.correlation_id}
              </Link>
            </dd>
            <dt>Application</dt>
            <dd>
              {event.application} <span className="faint">({event.environment})</span>
            </dd>
            <dt>Principal</dt>
            <dd className="mono">
              {event.principal_id ?? "anonymous"}
              {event.principal_roles.length ? (
                <span className="faint"> — {event.principal_roles.join(", ")}</span>
              ) : null}
            </dd>
            {event.tenant ? (
              <>
                <dt>Tenant</dt>
                <dd className="mono">{event.tenant}</dd>
              </>
            ) : null}
            {event.session_id ? (
              <>
                <dt>Session</dt>
                <dd className="mono">{event.session_id}</dd>
              </>
            ) : null}
            <dt>Model</dt>
            <dd className="mono">
              {event.model ?? "—"} <span className="faint">{event.provider ?? ""}</span>
            </dd>
            <dt>Policy</dt>
            <dd className="mono">{event.policy_version ?? "—"}</dd>
            <dt>SDK</dt>
            <dd className="mono">
              {event.sdk_version ?? "—"} <span className="faint">{event.instance_id ?? ""}</span>
            </dd>
            {event.trace_id ? (
              <>
                <dt>Trace</dt>
                <dd className="mono">{event.trace_id}</dd>
              </>
            ) : null}
            <dt>Latency</dt>
            <dd>
              {event.latency_ms.toFixed(2)} ms
              {event.tokens_in || event.tokens_out ? (
                <span className="faint">
                  {" "}
                  — {event.tokens_in ?? 0} in / {event.tokens_out ?? 0} out tokens
                </span>
              ) : null}
            </dd>
          </dl>
        </Card>

        {fired.length ? (
          <Card title={`Detectors that fired (${fired.length})`}>
            <div className="stack">
              {fired.map((finding, i) => (
                <div key={i} style={{ borderLeft: `3px solid var(--${finding.severity})`, paddingLeft: 10 }}>
                  <div className="row">
                    <strong className="mono">{finding.detector}</strong>
                    <SeverityBadge severity={finding.severity} />
                    <ActionBadge action={finding.action} />
                    <span className="faint mono">score {finding.score.toFixed(2)}</span>
                    <span className="faint mono">{finding.elapsed_ms.toFixed(2)} ms</span>
                  </div>
                  <div style={{ margin: "4px 0 6px" }}>{finding.summary}</div>
                  {finding.spans.length ? (
                    <div className="row" style={{ gap: 5, marginBottom: 6 }}>
                      {finding.spans.slice(0, 8).map((span, j) => (
                        <Tag key={j}>
                          {span.label} @{span.start}–{span.end}
                        </Tag>
                      ))}
                    </div>
                  ) : null}
                  {Object.keys(finding.evidence).length ? (
                    <details>
                      <summary className="dim" style={{ cursor: "pointer", fontSize: 12 }}>
                        Evidence
                      </summary>
                      <Json value={finding.evidence} />
                    </details>
                  ) : null}
                </div>
              ))}
            </div>
          </Card>
        ) : null}

        {matched.length ? (
          <Card title="Policy decision">
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Rule</th>
                    <th>Action</th>
                    <th className="right">Eval</th>
                  </tr>
                </thead>
                <tbody>
                  {matched.map((trace, i) => (
                    <tr key={i}>
                      <td>
                        <div className="mono">{trace.rule_id ?? "(policy default)"}</div>
                        <div className="faint" style={{ fontSize: 12 }}>
                          {trace.policy_id}@{trace.policy_version} {trace.note}
                        </div>
                      </td>
                      <td>
                        <ActionBadge action={trace.action} />
                      </td>
                      <td className="right mono dim">{trace.elapsed_ms.toFixed(3)} ms</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        ) : null}

        <Card title="Payload">
          {event.redacted_fields.length ? (
            <div className="row" style={{ marginBottom: 8, gap: 5 }}>
              <span className="dim" style={{ fontSize: 12 }}>
                Redacted before storage:
              </span>
              {event.redacted_fields.map((field) => (
                <Tag key={field} tone="redact">
                  {field}
                </Tag>
              ))}
            </div>
          ) : null}
          <div className="stack">
            <div>
              <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>
                Prompt
              </div>
              <Payload text={event.prompt} />
            </div>
            {event.response !== null || event.stage === "output" ? (
              <div>
                <div className="dim" style={{ fontSize: 12, marginBottom: 4 }}>
                  Response
                </div>
                <Payload text={event.response} />
              </div>
            ) : null}
          </div>
        </Card>

        {Object.keys(event.tags ?? {}).length ? (
          <Card title="Tags">
            <Json value={event.tags} />
          </Card>
        ) : null}
      </div>
    </Drawer>
  );
}
