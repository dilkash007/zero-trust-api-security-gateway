import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getSecurityEvents } from "../services/api";

export default function Threats() {
  const { user, logout } = useAuth();
  const [events, setEvents] = useState([]);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  const fetchEvents = async () => {
    setLoading(true);
    setForbidden(false);
    try {
      const params = { limit: 50 };
      if (severityFilter) params.severity = severityFilter;
      if (typeFilter) params.event_type = typeFilter;

      const res = await getSecurityEvents(params);
      setEvents(res.data || []);
    } catch (err) {
      if (err.response?.status === 403) {
        setForbidden(true);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchEvents();
  }, [severityFilter, typeFilter]);

  const getSeverityBadge = (severity) => {
    if (severity === "HIGH") {
      return (
        <span
          style={{
            padding: "3px 8px",
            borderRadius: "4px",
            fontSize: "11px",
            fontWeight: 700,
            fontFamily: "var(--font-mono)",
            backgroundColor: "rgba(239, 68, 68, 0.2)",
            color: "var(--danger)",
            border: "1px solid rgba(239, 68, 68, 0.4)",
          }}
        >
          HIGH
        </span>
      );
    }
    if (severity === "MEDIUM") {
      return (
        <span
          style={{
            padding: "3px 8px",
            borderRadius: "4px",
            fontSize: "11px",
            fontWeight: 700,
            fontFamily: "var(--font-mono)",
            backgroundColor: "rgba(245, 158, 11, 0.2)",
            color: "var(--warning)",
            border: "1px solid rgba(245, 158, 11, 0.4)",
          }}
        >
          MEDIUM
        </span>
      );
    }
    return (
      <span
        style={{
          padding: "3px 8px",
          borderRadius: "4px",
          fontSize: "11px",
          fontWeight: 600,
          fontFamily: "var(--font-mono)",
          backgroundColor: "rgba(59, 130, 246, 0.15)",
          color: "var(--accent)",
          border: "1px solid rgba(59, 130, 246, 0.3)",
        }}
      >
        INFO
      </span>
    );
  };

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">Security Events Audit</span>
          <span className="topbar-badge">INCIDENT LOGS</span>
        </div>
        <div className="topbar-right">
          {user && (
            <div className="user-greeting">
              <span className="user-welcome">Welcome, {user.name}</span>
              <span className="user-role-badge">Role: {user.role}</span>
            </div>
          )}
          <button id="logout-btn" className="btn-logout" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="content-area">
        <div className="header-banner">
          <h1 className="page-title">Security Events & Audit Stream</h1>
          <p className="page-subtitle">
            Zero-Trust API Security Engine — Step 4: Security Events Telemetry (`security_events`)
          </p>
        </div>

        {forbidden ? (
          <div
            style={{
              padding: "24px",
              backgroundColor: "var(--surface)",
              border: "1px solid var(--border)",
              borderRadius: "8px",
              color: "var(--text)",
            }}
          >
            <div style={{ display: "flex", alignItems: "center", gap: "10px", marginBottom: "8px" }}>
              <span className="dot dot-disconnected"></span>
              <h2 style={{ fontSize: "16px", margin: 0, color: "var(--danger)" }}>
                Administrative Access Required
              </h2>
            </div>
            <p style={{ fontSize: "13px", color: "var(--muted)", lineHeight: 1.6 }}>
              Security audit event records are restricted to users with the <strong>ADMIN</strong> role.
              Your current identity has role <code>{user?.role}</code>. Log in as an administrator to inspect security events.
            </p>
          </div>
        ) : (
          <section className="info-panel">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px", flexWrap: "wrap", gap: "12px" }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <h2 className="info-title" style={{ margin: 0 }}>
                  <span>Security Events Stream ({events.length} records)</span>
                </h2>
                <button
                  id="btn-refresh-events"
                  className="btn-refresh"
                  onClick={fetchEvents}
                  disabled={loading}
                >
                  {loading ? "Refreshing..." : "Refresh Events"}
                </button>
              </div>

              {/* Filters */}
              <div style={{ display: "flex", gap: "12px", alignItems: "center" }}>
                <div>
                  <span style={{ fontSize: "11px", color: "var(--muted)", marginRight: "6px" }}>Severity:</span>
                  <select
                    value={severityFilter}
                    onChange={(e) => setSeverityFilter(e.target.value)}
                    style={{
                      backgroundColor: "var(--surface-secondary)",
                      color: "var(--text)",
                      border: "1px solid var(--border)",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "11px",
                    }}
                  >
                    <option value="">All Severities</option>
                    <option value="INFO">INFO</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="HIGH">HIGH</option>
                  </select>
                </div>

                <div>
                  <span style={{ fontSize: "11px", color: "var(--muted)", marginRight: "6px" }}>Event Type:</span>
                  <select
                    value={typeFilter}
                    onChange={(e) => setTypeFilter(e.target.value)}
                    style={{
                      backgroundColor: "var(--surface-secondary)",
                      color: "var(--text)",
                      border: "1px solid var(--border)",
                      borderRadius: "4px",
                      padding: "4px 8px",
                      fontSize: "11px",
                    }}
                  >
                    <option value="">All Types</option>
                    <option value="AUTHENTICATION_FAILURE">AUTHENTICATION_FAILURE</option>
                    <option value="AUTHORIZATION_FAILURE">AUTHORIZATION_FAILURE</option>
                    <option value="SENSITIVE_ENDPOINT_ACCESS">SENSITIVE_ENDPOINT_ACCESS</option>
                    <option value="REQUEST_COMPLETED">REQUEST_COMPLETED</option>
                  </select>
                </div>
              </div>
            </div>

            {loading ? (
              <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
                Loading security events from PostgreSQL...
              </div>
            ) : events.length === 0 ? (
              <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
                No security events match the current filter criteria.
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
                  <thead>
                    <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)", textTransform: "uppercase", fontSize: "11px" }}>
                      <th style={{ padding: "10px" }}>Event ID</th>
                      <th style={{ padding: "10px" }}>Severity</th>
                      <th style={{ padding: "10px" }}>Event Type</th>
                      <th style={{ padding: "10px" }}>Endpoint</th>
                      <th style={{ padding: "10px" }}>User ID</th>
                      <th style={{ padding: "10px" }}>Timestamp</th>
                      <th style={{ padding: "10px" }}>Message</th>
                    </tr>
                  </thead>
                  <tbody>
                    {events.map((ev) => {
                      const timeStr = ev.timestamp
                        ? ev.timestamp.includes("T")
                          ? new Date(ev.timestamp).toLocaleTimeString()
                          : ev.timestamp
                        : "N/A";

                      return (
                        <tr
                          key={ev.event_id}
                          style={{
                            borderBottom: "1px solid rgba(255,255,255,0.05)",
                            backgroundColor:
                              ev.severity === "HIGH"
                                ? "rgba(239, 68, 68, 0.04)"
                                : ev.severity === "MEDIUM"
                                ? "rgba(245, 158, 11, 0.03)"
                                : "transparent",
                          }}
                        >
                          <td style={{ padding: "10px", fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                            {ev.event_id ? `${ev.event_id.substring(0, 13)}...` : "N/A"}
                          </td>
                          <td style={{ padding: "10px" }}>{getSeverityBadge(ev.severity)}</td>
                          <td style={{ padding: "10px", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                            {ev.event_type}
                          </td>
                          <td style={{ padding: "10px", fontFamily: "var(--font-mono)" }}>
                            {ev.endpoint}
                          </td>
                          <td style={{ padding: "10px", fontFamily: "var(--font-mono)" }}>
                            {ev.user_id !== null ? `User #${ev.user_id}` : "Unauthenticated"}
                          </td>
                          <td style={{ padding: "10px", color: "var(--muted)", fontFamily: "var(--font-mono)", fontSize: "11px" }}>
                            {timeStr}
                          </td>
                          <td style={{ padding: "10px" }}>{ev.message}</td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </section>
        )}
      </main>
    </div>
  );
}
