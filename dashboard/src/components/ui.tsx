/**
 * Shared presentation primitives.
 *
 * Charts are hand-drawn SVG rather than a charting library. Three reasons that
 * actually matter here: the dashboard ships as part of a security product, so
 * every dependency is one more thing to audit and patch; the two chart shapes
 * we need are a stacked bar timeline and a horizontal bar, which are about
 * forty lines each; and inline SVG inherits the theme's CSS variables, so
 * light/dark works without a second theme definition.
 */

import { useEffect, useState, type ReactNode } from "react";
import type { Action, Severity } from "../lib/api";

export const ACTION_COLOR: Record<Action, string> = {
  allow: "var(--allow)",
  flag: "var(--flag)",
  redact: "var(--redact)",
  challenge: "var(--challenge)",
  block: "var(--block)",
};

export const ACTION_ORDER: Action[] = ["allow", "flag", "redact", "challenge", "block"];

export function ActionBadge({ action }: { action: Action }) {
  return (
    <span className={`badge ${action}`}>
      <span className="dot" />
      {action}
    </span>
  );
}

export function SeverityBadge({ severity }: { severity: Severity }) {
  return <span className={`badge ${severity}`}>{severity}</span>;
}

export function Tag({ children, tone = "neutral" }: { children: ReactNode; tone?: string }) {
  return <span className={`badge ${tone}`}>{children}</span>;
}

export function Stat({
  label,
  value,
  sub,
  tone,
}: {
  label: string;
  value: ReactNode;
  sub?: ReactNode;
  tone?: string;
}) {
  return (
    <div className="card stat">
      <span className="label">{label}</span>
      <span className="value" style={tone ? { color: tone } : undefined}>
        {value}
      </span>
      {sub ? <span className="sub">{sub}</span> : null}
    </div>
  );
}

export function Card({ title, children, actions }: { title?: string; children: ReactNode; actions?: ReactNode }) {
  return (
    <section className="card">
      {title || actions ? (
        <div className="row" style={{ justifyContent: "space-between", marginBottom: 12 }}>
          {title ? <h2 style={{ margin: 0 }}>{title}</h2> : <span />}
          {actions}
        </div>
      ) : null}
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="empty">
      <span className="spinner" /> <span style={{ marginLeft: 8 }}>{label}…</span>
    </div>
  );
}

export function ErrorBanner({ error }: { error: unknown }) {
  if (!error) return null;
  const message = error instanceof Error ? error.message : String(error);
  return <div className="banner error">{message}</div>;
}

/** Stacked bar chart over time, coloured by action. */
export function TimelineChart({
  buckets,
  height = 150,
}: {
  buckets: { bucket_ms: number; total: number } & Partial<Record<Action, number>>[];
  height?: number;
}) {
  const data = buckets as unknown as ({ bucket_ms: number; total: number } & Partial<Record<Action, number>>)[];
  if (!data.length) return <Empty>No traffic in this window.</Empty>;

  const width = 1000;
  const max = Math.max(...data.map((b) => b.total), 1);
  const gap = data.length > 120 ? 0 : 1;
  const barWidth = Math.max(1, width / data.length - gap);

  return (
    <>
      <svg className="chart" viewBox={`0 0 ${width} ${height}`} preserveAspectRatio="none" role="img"
           aria-label="AI traffic over time by firewall action">
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={width} y1={height * f} y2={height * f} stroke="var(--border)" strokeWidth={1} />
        ))}
        {data.map((bucket, i) => {
          let offset = 0;
          const x = i * (barWidth + gap);
          return (
            <g key={bucket.bucket_ms}>
              {ACTION_ORDER.map((action) => {
                const count = bucket[action] ?? 0;
                if (!count) return null;
                const h = (count / max) * (height - 4);
                const y = height - offset - h;
                offset += h;
                return (
                  <rect key={action} x={x} y={y} width={barWidth} height={h} fill={ACTION_COLOR[action]} opacity={0.88}>
                    <title>
                      {new Date(bucket.bucket_ms).toLocaleTimeString()} — {count} {action}
                    </title>
                  </rect>
                );
              })}
            </g>
          );
        })}
      </svg>
      <div className="chart-legend">
        {ACTION_ORDER.map((action) => (
          <span key={action}>
            <span className="swatch" style={{ background: ACTION_COLOR[action] }} />
            {action}
          </span>
        ))}
        <span style={{ marginLeft: "auto" }}>
          {new Date(data[0].bucket_ms).toLocaleTimeString()} →{" "}
          {new Date(data[data.length - 1].bucket_ms).toLocaleTimeString()}
        </span>
      </div>
    </>
  );
}

/** Horizontal bar, for ranked lists (detector hit rates, top applications). */
export function BarRow({
  label,
  value,
  max,
  color = "var(--accent)",
  hint,
}: {
  label: ReactNode;
  value: number;
  max: number;
  color?: string;
  hint?: ReactNode;
}) {
  const pct = max > 0 ? Math.max(2, (value / max) * 100) : 0;
  return (
    <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: "2px 10px", marginBottom: 10 }}>
      <div className="row" style={{ gap: 6 }}>
        {label}
      </div>
      <span className="mono dim nowrap">{hint ?? value.toLocaleString()}</span>
      <div className="bar-track" style={{ gridColumn: "1 / -1" }}>
        <div className="bar-fill" style={{ width: `${pct}%`, background: color }} />
      </div>
    </div>
  );
}

export function Drawer({ onClose, children }: { onClose: () => void; children: ReactNode }) {
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = "";
    };
  }, [onClose]);

  return (
    <>
      <div className="drawer-backdrop" onClick={onClose} />
      <aside className="drawer" role="dialog" aria-modal="true">
        {children}
      </aside>
    </>
  );
}

export function Json({ value }: { value: unknown }) {
  return <pre className="json">{JSON.stringify(value, null, 2)}</pre>;
}

/**
 * Render a payload with `[REDACTED:label]` markers highlighted.
 *
 * Making redaction visible rather than invisible matters: an investigator
 * needs to know the difference between "the prompt had no card number" and
 * "the card number was stripped before storage".
 */
export function Payload({ text }: { text: string | null }) {
  if (!text) return <span className="faint">not recorded (redaction mode)</span>;
  const parts = text.split(/(\[REDACTED:[^\]]+\])/g);
  return (
    <div className="payload">
      {parts.map((part, i) =>
        part.startsWith("[REDACTED:") ? (
          <span key={i} className="redaction">
            {part}
          </span>
        ) : (
          <span key={i}>{part}</span>
        ),
      )}
    </div>
  );
}

export function timeAgo(ms: number): string {
  const seconds = Math.max(0, (Date.now() - ms) / 1000);
  if (seconds < 60) return `${Math.floor(seconds)}s ago`;
  if (seconds < 3600) return `${Math.floor(seconds / 60)}m ago`;
  if (seconds < 86400) return `${Math.floor(seconds / 3600)}h ago`;
  return `${Math.floor(seconds / 86400)}d ago`;
}

export function formatTime(ms: number): string {
  return new Date(ms).toLocaleString(undefined, {
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
}

/** Small data-fetching hook: loading, error, refetch, optional polling. */
export function useApi<T>(
  fetcher: () => Promise<T>,
  deps: unknown[] = [],
  pollMs = 0,
): { data: T | null; error: unknown; loading: boolean; reload: () => void } {
  const [data, setData] = useState<T | null>(null);
  const [error, setError] = useState<unknown>(null);
  const [loading, setLoading] = useState(true);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let cancelled = false;
    const run = async (showSpinner: boolean) => {
      if (showSpinner) setLoading(true);
      try {
        const result = await fetcher();
        if (!cancelled) {
          setData(result);
          setError(null);
        }
      } catch (err) {
        if (!cancelled) setError(err);
      } finally {
        if (!cancelled) setLoading(false);
      }
    };
    void run(true);
    if (pollMs > 0) {
      // Poll without the spinner so a live view does not flicker every tick.
      const timer = setInterval(() => void run(false), pollMs);
      return () => {
        cancelled = true;
        clearInterval(timer);
      };
    }
    return () => {
      cancelled = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [...deps, nonce, pollMs]);

  return { data, error, loading, reload: () => setNonce((n) => n + 1) };
}
