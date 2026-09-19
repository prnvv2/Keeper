/**
 * Risk & OWASP: the view a CISO asks for.
 *
 * Detectors describe what they saw; this page describes exposure in the terms
 * security programmes report against — a 5x5 likelihood x impact matrix and
 * the OWASP Top 10 lists for LLM applications (2025), agentic applications
 * (2026) and MCP (2025). Coverage comes from the SDK's own taxonomy through the
 * control plane, so it cannot drift from what the firewall actually enforces.
 */

import { useState } from "react";
import { Link } from "react-router-dom";
import { api, type RiskBand, type ThreatRow } from "../lib/api";
import { ActionBadge, BarRow, Card, Empty, ErrorBanner, Loading, Stat, timeAgo, useApi } from "../components/ui";

const BAND_COLOR: Record<RiskBand, string> = {
  none: "var(--info)",
  low: "var(--low)",
  medium: "var(--medium)",
  high: "var(--high)",
  critical: "var(--critical)",
};

const bandFor = (score: number): RiskBand =>
  score <= 0 ? "none" : score <= 4 ? "low" : score <= 9 ? "medium" : score <= 16 ? "high" : "critical";

const FRAMEWORK_LABEL: Record<string, string> = {
  "owasp-llm-2025": "OWASP Top 10 for LLM Applications 2025",
  "owasp-agentic-2026": "OWASP Top 10 for Agentic Applications 2026",
  "owasp-mcp-2025": "OWASP MCP Top 10 2025",
};

const STATUS_COLOR: Record<ThreatRow["status"], string> = {
  covered: "var(--allow)",
  partial: "var(--flag)",
  observed: "var(--info)",
  disabled: "var(--text-faint)",
  out_of_scope: "var(--border)",
};

function Heatmap({ matrix, hours }: { matrix: number[][]; hours: number }) {
  const max = Math.max(1, ...matrix.flat());
  return (
    <div>
      <div className="heatmap" role="table" aria-label="Likelihood by impact">
        {[5, 4, 3, 2, 1].map((likelihood) => (
          <div key={likelihood} style={{ display: "contents" }} role="row">
            <div className="axis" role="rowheader">
              L{likelihood}
            </div>
            {[1, 2, 3, 4, 5].map((impact) => {
              const count = matrix[likelihood - 1]?.[impact - 1] ?? 0;
              const score = likelihood * impact;
              const color = BAND_COLOR[bandFor(score)];
              const strength = count ? 18 + Math.round((count / max) * 62) : 6;
              return (
                <Link
                  key={impact}
                  to={`/events?min_risk=${score}&hours=${hours}`}
                  className={`cell${count ? "" : " empty-cell"}`}
                  role="cell"
                  title={`likelihood ${likelihood} × impact ${impact} = ${score} (${bandFor(score)}): ${count} events`}
                  style={{ background: `color-mix(in srgb, ${color} ${strength}%, var(--surface))` }}
                >
                  <span>{count ? count.toLocaleString() : "·"}</span>
                  <span className="score">{score}</span>
                </Link>
              );
            })}
          </div>
        ))}
        <div />
        {[1, 2, 3, 4, 5].map((impact) => (
          <div key={impact} className="axis">
            I{impact}
          </div>
        ))}
      </div>
      <p className="faint" style={{ fontSize: 12, marginBottom: 0 }}>
        Likelihood is detector confidence (with corroboration); impact is the threat's severity raised to the
        sink's risk tier and the application's criticality. Residual risk after redaction. Click a cell to
        see those events.
      </p>
    </div>
  );
}

export default function Risk() {
  const [hours, setHours] = useState(24);
  const [framework, setFramework] = useState<string>("all");
  const risk = useApi(() => api.riskStats(hours), [hours]);
  const catalog = useApi(() => api.threats(Math.max(hours, 1)), [hours]);

  const bands = risk.data?.by_band ?? {};
  const totalRisky = (bands.low ?? 0) + (bands.medium ?? 0) + (bands.high ?? 0) + (bands.critical ?? 0);
  const rows = (catalog.data?.threats ?? []).filter((t) => framework === "all" || t.framework === framework);
  const hitsByThreat = new Map((risk.data?.threats ?? []).map((t) => [t.threat, t]));
  const maxHits = Math.max(1, ...(risk.data?.threats ?? []).map((t) => t.events));
  const grouped = rows.reduce<Record<string, ThreatRow[]>>((acc, row) => {
    (acc[row.framework] ??= []).push(row);
    return acc;
  }, {});
  const covered = (catalog.data?.threats ?? []).filter((t) => t.status === "covered").length;
  const partial = (catalog.data?.threats ?? []).filter((t) => t.status === "partial").length;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Risk &amp; OWASP</h1>
          <p>Every decision placed on a likelihood × impact matrix and named in OWASP LLM, Agentic and MCP terms.</p>
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

      <ErrorBanner error={risk.error ?? catalog.error} />

      <div className="grid cols-4" style={{ marginBottom: 16 }}>
        <Stat label="Critical risk" value={(bands.critical ?? 0).toLocaleString()} tone="var(--critical)" sub="score 17–25" />
        <Stat label="High risk" value={(bands.high ?? 0).toLocaleString()} tone="var(--high)" sub="score 10–16" />
        <Stat label="Risk-bearing events" value={totalRisky.toLocaleString()} sub={`medium ${bands.medium ?? 0} · low ${bands.low ?? 0}`} />
        <Stat
          label="OWASP coverage"
          value={`${covered} / ${catalog.data?.threats.length ?? 30}`}
          sub={`${partial} partial`}
        />
      </div>

      <div className="grid cols-2" style={{ marginBottom: 16 }}>
        <Card title="Risk matrix">
          {risk.loading && !risk.data ? <Loading /> : <Heatmap matrix={risk.data?.matrix ?? []} hours={hours} />}
        </Card>

        <Card title="Most frequent threats">
          {risk.data?.threats.length ? (
            risk.data.threats.slice(0, 10).map((t) => (
              <BarRow
                key={t.threat}
                label={
                  <Link className="mono" to={`/events?threat=${t.threat}&hours=${hours}`}>
                    {t.threat}
                  </Link>
                }
                value={t.events}
                max={maxHits}
                color="var(--accent)"
                hint={`${t.events.toLocaleString()} · ${t.blocked.toLocaleString()} blocked`}
              />
            ))
          ) : (
            <Empty>No threats detected in this window.</Empty>
          )}
        </Card>
      </div>

      <div className="stack">
        <Card title="Riskiest recent decisions">
          {risk.data?.top_events.length ? (
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>When</th>
                    <th>Risk</th>
                    <th>Action</th>
                    <th>Stage</th>
                    <th>Application</th>
                    <th>Principal</th>
                    <th>Threats</th>
                  </tr>
                </thead>
                <tbody>
                  {risk.data.top_events.map((e) => (
                    <tr key={e.event_id}>
                      <td className="nowrap dim">{timeAgo(e.timestamp_ms)}</td>
                      <td className="nowrap">
                        <span className={`badge ${e.risk_band}`}>{e.risk_score}</span>{" "}
                        <span className="faint mono">
                          L{e.risk_likelihood}×I{e.risk_impact}
                        </span>
                      </td>
                      <td>
                        <ActionBadge action={e.action} />
                      </td>
                      <td className="mono dim">{e.stage}</td>
                      <td>
                        <Link to={`/investigate/${e.correlation_id}`}>{e.application}</Link>
                      </td>
                      <td className="mono dim">{e.principal_id ?? "anonymous"}</td>
                      <td className="mono dim">{(e.threats ?? []).join(" ")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <Empty>No risk-bearing decisions in this window.</Empty>
          )}
        </Card>

        <Card
          title="OWASP coverage"
          actions={
            <select value={framework} onChange={(e) => setFramework(e.target.value)}>
              <option value="all">all frameworks</option>
              {Object.entries(FRAMEWORK_LABEL).map(([id, label]) => (
                <option key={id} value={id}>
                  {label}
                </option>
              ))}
            </select>
          }
        >
          {catalog.loading && !catalog.data ? (
            <Loading />
          ) : (
            Object.entries(grouped).map(([fw, threats]) => (
              <div key={fw} style={{ marginBottom: 18 }}>
                <h3 style={{ margin: "4px 0 8px", fontSize: 13 }}>{FRAMEWORK_LABEL[fw] ?? fw}</h3>
                <div className="table-wrap">
                  <table>
                    <thead>
                      <tr>
                        <th>ID</th>
                        <th>Threat</th>
                        <th>Coverage</th>
                        <th>Enforced by</th>
                        <th>ATLAS</th>
                        <th className="right">Hits</th>
                      </tr>
                    </thead>
                    <tbody>
                      {threats.map((t) => {
                        const hit = hitsByThreat.get(t.id);
                        return (
                          <tr key={t.id} title={t.note || t.summary}>
                            <td className="mono">
                              <Link to={`/events?threat=${t.id}&hours=${hours}`}>{t.id}</Link>
                            </td>
                            <td>
                              {t.title}
                              <div className="faint" style={{ fontSize: 12 }}>
                                {t.summary}
                              </div>
                            </td>
                            <td className="nowrap">
                              <span className="coverage-dot" style={{ background: STATUS_COLOR[t.status] }} />
                              {t.status.replace("_", " ")}
                            </td>
                            <td className="mono dim" style={{ fontSize: 12 }}>
                              {[...t.detectors, ...t.controls].join(", ") || "—"}
                            </td>
                            <td className="mono faint" style={{ fontSize: 12 }}>
                              {t.atlas.join(" ") || "—"}
                            </td>
                            <td className="right mono">{(hit?.events ?? t.hits).toLocaleString()}</td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            ))
          )}
        </Card>
      </div>
    </>
  );
}
