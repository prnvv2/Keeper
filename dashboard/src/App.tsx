/**
 * Shell: navigation, the admin-key gate, and routing.
 *
 * The key gate is a placeholder for real identity, and says so rather than
 * pretending otherwise. A production deployment should put SSO in front of the
 * control plane (docs/deployment.md) and turn dashboard auth off here, rather
 * than treating a shared bearer token as an access-control story.
 */

import { useState } from "react";
import { NavLink, Route, Routes } from "react-router-dom";
import { ApiError, api, getKey, setKey } from "./lib/api";
import { useApi } from "./components/ui";
import Alerts from "./pages/Alerts";
import Analytics from "./pages/Analytics";
import Events from "./pages/Events";
import Fleet from "./pages/Fleet";
import Investigate from "./pages/Investigate";
import Overview from "./pages/Overview";
import Policies from "./pages/Policies";

const NAV = [
  { to: "/", label: "Live traffic", end: true },
  { to: "/events", label: "Audit log" },
  { to: "/investigate", label: "Investigate" },
  { to: "/analytics", label: "Analytics" },
  { to: "/fleet", label: "Fleet" },
  { to: "/policies", label: "Policy" },
  { to: "/alerts", label: "Alerts" },
];

function Mark() {
  return (
    <svg className="brand-mark" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M12 2.5 3.8 6v6.2c0 5 3.5 8.6 8.2 9.9 4.7-1.3 8.2-4.9 8.2-9.9V6L12 2.5Z"
        stroke="var(--accent)"
        strokeWidth="1.8"
        strokeLinejoin="round"
      />
      <path d="M8.6 12.2l2.5 2.5 4.4-4.9" stroke="var(--accent)" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function KeyGate({ onAuthenticated }: { onAuthenticated: () => void }) {
  const [value, setValue] = useState(getKey());
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setKey(value.trim());
    try {
      await api.health();
      onAuthenticated();
    } catch (err) {
      setKey("");
      setError(err instanceof ApiError && err.isAuth ? "That key was rejected." : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="login">
      <form className="card" onSubmit={submit}>
        <div className="brand" style={{ padding: "0 0 14px" }}>
          <Mark />
          Keeper
        </div>
        <p className="dim" style={{ marginTop: 0 }}>
          Enter an admin API key to view the audit trail. This grants read access to every recorded AI
          interaction across the fleet.
        </p>
        <input
          type="password"
          autoFocus
          placeholder="admin API key"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          style={{ width: "100%", marginBottom: 10 }}
        />
        {error ? <div className="banner error">{error}</div> : null}
        <button className="primary" type="submit" disabled={busy || !value.trim()} style={{ width: "100%" }}>
          {busy ? "Checking…" : "Continue"}
        </button>
        <p className="faint" style={{ fontSize: 12, marginBottom: 0, marginTop: 12 }}>
          Keys are kept in sessionStorage and cleared when the tab closes. For production, front the
          control plane with SSO and disable dashboard key auth.
        </p>
      </form>
    </div>
  );
}

export default function App() {
  const [nonce, setNonce] = useState(0);
  const health = useApi(() => api.health(), [nonce]);

  if (health.error instanceof ApiError && health.error.isAuth) {
    return <KeyGate onAuthenticated={() => setNonce((n) => n + 1)} />;
  }

  return (
    <div className="app">
      <nav className="sidebar">
        <div className="brand">
          <Mark />
          Keeper
        </div>
        {NAV.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) => `nav-link${isActive ? " active" : ""}`}
          >
            {item.label}
          </NavLink>
        ))}
        <div className="sidebar-footer">
          <div>control plane v{String(health.data?.version ?? "—")}</div>
          <div>{String(health.data?.environment ?? "")}</div>
          <div className="mono">{Number(health.data?.events_stored ?? 0).toLocaleString()} events stored</div>
          <button
            className="ghost"
            style={{ marginTop: 8, paddingLeft: 0 }}
            onClick={() => {
              setKey("");
              setNonce((n) => n + 1);
            }}
          >
            Sign out
          </button>
        </div>
      </nav>

      <main className="main">
        <Routes>
          <Route path="/" element={<Overview />} />
          <Route path="/events" element={<Events />} />
          <Route path="/investigate" element={<Investigate />} />
          <Route path="/investigate/:correlationId" element={<Investigate />} />
          <Route path="/analytics" element={<Analytics />} />
          <Route path="/fleet" element={<Fleet />} />
          <Route path="/policies" element={<Policies />} />
          <Route path="/alerts" element={<Alerts />} />
          <Route path="*" element={<div className="empty">Page not found.</div>} />
        </Routes>
      </main>
    </div>
  );
}
