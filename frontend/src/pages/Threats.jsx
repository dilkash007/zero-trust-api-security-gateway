import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { getAnomalies } from "../services/api";

export default function Threats() {
  const { user, logout } = useAuth();
  const [anomalies, setAnomalies] = useState([]);
  const [loading, setLoading] = useState(true);
  const [forbidden, setForbidden] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [expandedEventId, setExpandedEventId] = useState(null);

  const fetchAnomalies = async () => {
    setLoading(true);
    setForbidden(false);
    try {
      const params = { limit: 100 };
      if (severityFilter) params.severity = severityFilter;
      if (typeFilter) params.type = typeFilter;

      const res = await getAnomalies(params);
      setAnomalies(res.data || []);
    } catch (err) {
      if (err.response?.status === 403) {
        setForbidden(true);
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchAnomalies();
  }, [severityFilter, typeFilter]);

  // Real counters derived directly from backend anomaly data
  const highCount = anomalies.filter((a) => a.severity === "HIGH").length;
  const mediumCount = anomalies.filter((a) => a.severity === "MEDIUM").length;
  const lowCount = anomalies.filter((a) => a.severity === "LOW" || a.severity === "INFO").length;

  const getSeverityBadge = (severity) => {
    switch (severity) {
      case "HIGH":
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
      case "MEDIUM":
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
      case "LOW":
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
            LOW
          </span>
        );
      default:
        return (
          <span
            style={{
              padding: "3px 8px",
              borderRadius: "4px",
              fontSize: "11px",
              fontWeight: 600,
              fontFamily: "var(--font-mono)",
              backgroundColor: "rgba(148, 163, 184, 0.15)",
              color: "var(--muted)",
            }}
          >
            {severity || "INFO"}
          </span>
        );
    }
  };

  const getTypeBadge = (type) => {
    let color = "var(--text)";
    let bg = "var(--surface-secondary)";

    if (type === "API_ABUSE" || type === "CREDENTIAL_ATTACK") {
      color = "var(--danger)";
      bg = "rgba(239, 68, 68, 0.1)";
    } else if (type === "PRIVILEGE_MISUSE") {
      color = "#f97316";
      bg = "rgba(249, 115, 22, 0.1)";
    } else if (type === "UNKNOWN_DEVICE" || type === "LOCATION_ANOMALY") {
      color = "var(--warning)";
      bg = "rgba(245, 158, 11, 0.1)";
    } else if (type === "UNUSUAL_TIME") {
      color = "var(--accent)";
      bg = "rgba(59, 130, 246, 0.1)";
    }

    return (
      <span
        style={{
          padding: "3px 8px",
          borderRadius: "4px",
          fontSize: "11px",
          fontFamily: "var(--font-mono)",
          fontWeight: 600,
          color,
          backgroundColor: bg,
          border: `1px solid ${color}33`,
          whiteSpace: "nowrap",
        }}
      >
        {type}
      </span>
    );
  };

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">Threat Intelligence & Anomalies</span>
          <span className="topbar-badge">STEP 6 DETECTION</span>
        </div>
        <div className="topbar-right">
          {user && (
            <div className="user-greeting">
              <span className="user-welcome">Active: {user.name}</span>
              <span className="user-role-badge">Role: {user.role}</span>
            </div>
          )}
          <button
            id="btn-refresh-anomalies"
            className="btn-refresh"
            onClick={fetchAnomalies}
            disabled={loading}
          >
            {loading ? "Checking..." : "Refresh Anomalies"}
          </button>
          <button id="logout-btn" className="btn-logout" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="content-area">
        <div className="header-banner">
          <h1 className="page-title">Rule-Based Behavioral Anomaly Console</h1>
          <p className="page-subtitle">
            Zero-Trust Rule Engine evaluates real-time API requests against baseline telemetry to identify suspicious behaviors with explainable evidence.
          </p>
        </div>

        {/* Real Counters Grid */}
        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
            gap: "14px",
            marginBottom: "20px",
          }}
        >
          <div className="soc-card" style={{ padding: "16px" }}>
            <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
              Total Detected Anomalies
            </div>
            <div
              id="total-anomalies-count"
              style={{
                fontSize: "24px",
                fontWeight: 700,
                color: "var(--text)",
                fontFamily: "var(--font-mono)",
                marginTop: "4px",
              }}
            >
              {anomalies.length}
            </div>
            <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
              Stored in <code>security_events</code>
            </div>
          </div>

          <div className="soc-card" style={{ padding: "16px" }}>
            <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
              High Severity
            </div>
            <div
              id="high-severity-count"
              style={{
                fontSize: "24px",
                fontWeight: 700,
                color: "var(--danger)",
                fontFamily: "var(--font-mono)",
                marginTop: "4px",
              }}
            >
              {highCount}
            </div>
            <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
              API Abuse, Credential Surge, Privilege Misuse
            </div>
          </div>

          <div className="soc-card" style={{ padding: "16px" }}>
            <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
              Medium Severity
            </div>
            <div
              id="medium-severity-count"
              style={{
                fontSize: "24px",
                fontWeight: 700,
                color: "var(--warning)",
                fontFamily: "var(--font-mono)",
                marginTop: "4px",
              }}
            >
              {mediumCount}
            </div>
            <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
              Unknown Device, IP/Location Change
            </div>
          </div>

          <div className="soc-card" style={{ padding: "16px" }}>
            <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
              Low Severity
            </div>
            <div
              id="low-severity-count"
              style={{
                fontSize: "24px",
                fontWeight: 700,
                color: "var(--accent)",
                fontFamily: "var(--font-mono)",
                marginTop: "4px",
              }}
            >
              {lowCount}
            </div>
            <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
              Unusual Time of Access
            </div>
          </div>
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
              The anomaly intelligence stream is restricted to users with the <strong>ADMIN</strong> role.
              Your current identity has role <code>{user?.role}</code>. Log in as an administrator to inspect detections.
            </p>
          </div>
        ) : (
          <section className="info-panel">
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "16px",
                flexWrap: "wrap",
                gap: "12px",
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "12px" }}>
                <h2 className="info-title" style={{ margin: 0 }}>
                  <span>Detected Anomaly Events Matrix</span>
                </h2>
              </div>

              {/* Filters */}
              <div style={{ display: "flex", gap: "12px", alignItems: "center", flexWrap: "wrap" }}>
                <div>
                  <span style={{ fontSize: "11px", color: "var(--muted)", marginRight: "6px" }}>
                    Severity:
                  </span>
                  <select
                    id="filter-severity"
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
                    <option value="HIGH">HIGH</option>
                    <option value="MEDIUM">MEDIUM</option>
                    <option value="LOW">LOW</option>
                  </select>
                </div>

                <div>
                  <span style={{ fontSize: "11px", color: "var(--muted)", marginRight: "6px" }}>
                    Anomaly Type:
                  </span>
                  <select
                    id="filter-type"
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
                    <option value="">All Anomaly Types</option>
                    <option value="API_ABUSE">API_ABUSE</option>
                    <option value="CREDENTIAL_ATTACK">CREDENTIAL_ATTACK</option>
                    <option value="UNKNOWN_DEVICE">UNKNOWN_DEVICE</option>
                    <option value="LOCATION_ANOMALY">LOCATION_ANOMALY</option>
                    <option value="PRIVILEGE_MISUSE">PRIVILEGE_MISUSE</option>
                    <option value="UNUSUAL_TIME">UNUSUAL_TIME</option>
                  </select>
                </div>
              </div>
            </div>

            {loading ? (
              <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
                Loading detected anomalies from PostgreSQL security_events...
              </div>
            ) : anomalies.length === 0 ? (
              <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
                No anomalies detected matching the current filter criteria.
              </div>
            ) : (
              <div style={{ overflowX: "auto" }}>
                <table
                  id="anomalies-table"
                  style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}
                >
                  <thead>
                    <tr
                      style={{
                        borderBottom: "1px solid var(--border)",
                        backgroundColor: "var(--surface-secondary)",
                        color: "var(--muted)",
                        textTransform: "uppercase",
                        fontSize: "11px",
                      }}
                    >
                      <th style={{ padding: "10px 12px" }}>Anomaly Type</th>
                      <th style={{ padding: "10px 12px" }}>Severity</th>
                      <th style={{ padding: "10px 12px" }}>User Principal</th>
                      <th style={{ padding: "10px 12px" }}>Endpoint</th>
                      <th style={{ padding: "10px 12px" }}>Detection Reason (Why Suspicious?)</th>
                      <th style={{ padding: "10px 12px" }}>Timestamp</th>
                      <th style={{ padding: "10px 12px" }}>Evidence</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anomalies.map((a) => {
                      const isExpanded = expandedEventId === a.event_id;
                      const timeStr = a.timestamp
                        ? new Date(a.timestamp).toLocaleString()
                        : "N/A";

                      return (
                        <React.Fragment key={a.event_id}>
                          <tr
                            style={{
                              borderBottom: "1px solid rgba(255,255,255,0.05)",
                              backgroundColor:
                                a.severity === "HIGH"
                                  ? "rgba(239, 68, 68, 0.04)"
                                  : a.severity === "MEDIUM"
                                  ? "rgba(245, 158, 11, 0.03)"
                                  : "transparent",
                            }}
                          >
                            <td style={{ padding: "10px 12px" }}>{getTypeBadge(a.type)}</td>
                            <td style={{ padding: "10px 12px" }}>{getSeverityBadge(a.severity)}</td>
                            <td style={{ padding: "10px 12px" }}>
                              <div style={{ fontWeight: 600, color: "var(--text)" }}>
                                {a.username || `User #${a.user_id}`}
                              </div>
                              <div
                                style={{
                                  fontSize: "10px",
                                  color: "var(--muted)",
                                  fontFamily: "var(--font-mono)",
                                }}
                              >
                                UID: {a.user_id || "None"}
                              </div>
                            </td>
                            <td style={{ padding: "10px 12px", fontFamily: "var(--font-mono)" }}>
                              {a.endpoint}
                            </td>
                            <td style={{ padding: "10px 12px", color: "var(--text)", maxWidth: "300px" }}>
                              {a.reason}
                            </td>
                            <td
                              style={{
                                padding: "10px 12px",
                                color: "var(--muted)",
                                fontFamily: "var(--font-mono)",
                                fontSize: "11px",
                                whiteSpace: "nowrap",
                              }}
                            >
                              {timeStr}
                            </td>
                            <td style={{ padding: "10px 12px" }}>
                              <button
                                className="btn-refresh"
                                style={{ fontSize: "10px", padding: "2px 8px" }}
                                onClick={() => setExpandedEventId(isExpanded ? null : a.event_id)}
                              >
                                {isExpanded ? "Hide" : "Inspect"}
                              </button>
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr style={{ backgroundColor: "var(--surface-secondary)" }}>
                              <td colSpan="7" style={{ padding: "12px 16px" }}>
                                <div style={{ fontSize: "11px", fontFamily: "var(--font-mono)" }}>
                                  <div style={{ color: "var(--accent)", marginBottom: "4px" }}>
                                    Request ID: <strong>{a.request_id}</strong> | Event ID: <strong>{a.event_id}</strong>
                                  </div>
                                  <div style={{ color: "var(--muted)", marginBottom: "4px" }}>
                                    Detection Evidence Payload:
                                  </div>
                                  <pre
                                    style={{
                                      backgroundColor: "var(--bg)",
                                      padding: "8px 12px",
                                      borderRadius: "4px",
                                      overflowX: "auto",
                                      border: "1px solid var(--border)",
                                      color: "var(--text)",
                                    }}
                                  >
                                    {JSON.stringify(a.evidence, null, 2)}
                                  </pre>
                                </div>
                              </td>
                            </tr>
                          )}
                        </React.Fragment>
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
