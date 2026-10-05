import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  getBehaviorProfiles,
  getMyBehaviorProfile,
  getBehaviorFeatures,
  rebuildBaselines,
} from "../services/api";

export default function Behavior() {
  const { user, logout } = useAuth();
  const isAdmin = user?.role === "ADMIN";

  const [profiles, setProfiles] = useState([]);
  const [featureSnapshot, setFeatureSnapshot] = useState(null);
  const [loading, setLoading] = useState(true);
  const [rebuilding, setRebuilding] = useState(false);
  const [rebuildMsg, setRebuildMsg] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);

  const fetchBehaviorData = async () => {
    setLoading(true);
    setErrorMsg(null);
    try {
      // 1. Fetch live feature snapshot for current user
      const snapshotRes = await getBehaviorFeatures();
      setFeatureSnapshot(snapshotRes.data || null);

      // 2. Fetch profiles: if ADMIN fetch all, otherwise fetch own profile
      if (isAdmin) {
        const profilesRes = await getBehaviorProfiles();
        setProfiles(profilesRes.data || []);
      } else {
        const myRes = await getMyBehaviorProfile();
        setProfiles(myRes.data ? [myRes.data] : []);
      }
    } catch (err) {
      console.error("Failed to load behavior intelligence:", err);
      setErrorMsg(
        err.response?.data?.error?.message ||
          "Failed to load behavioral profiles. Please check backend connection."
      );
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchBehaviorData();
  }, [isAdmin]);

  const handleRebuildBaselines = async () => {
    setRebuilding(true);
    setRebuildMsg(null);
    setErrorMsg(null);
    try {
      const res = await rebuildBaselines();
      setRebuildMsg(
        `✓ ${res.message} — ${res.profiles_updated} profiles recalculated from request telemetry.`
      );
      await fetchBehaviorData();
    } catch (err) {
      setErrorMsg(
        err.response?.data?.error?.message ||
          "Failed to rebuild behavior baselines."
      );
    } finally {
      setRebuilding(false);
    }
  };

  const getStatusBadge = (status) => {
    switch (status) {
      case "ESTABLISHED":
        return {
          label: "ESTABLISHED (50+ reqs)",
          bg: "rgba(16, 185, 129, 0.15)",
          color: "var(--success)",
          border: "1px solid rgba(16, 185, 129, 0.3)",
        };
      case "LEARNING":
        return {
          label: "LEARNING (10–49 reqs)",
          bg: "rgba(245, 158, 11, 0.15)",
          color: "var(--warning)",
          border: "1px solid rgba(245, 158, 11, 0.3)",
        };
      default:
        return {
          label: "INSUFFICIENT DATA (<10 reqs)",
          bg: "rgba(148, 163, 184, 0.15)",
          color: "var(--muted)",
          border: "1px solid rgba(148, 163, 184, 0.3)",
        };
    }
  };

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">Behavioral Intelligence & Baselines</span>
          <span className="topbar-badge">STEP 5 ENGINE</span>
        </div>
        <div className="topbar-right">
          {user && (
            <div className="user-greeting">
              <span className="user-welcome">Active: {user.name}</span>
              <span className="user-role-badge">Role: {user.role}</span>
            </div>
          )}
          {isAdmin && (
            <button
              id="rebuild-baselines-btn"
              className="btn-refresh"
              onClick={handleRebuildBaselines}
              disabled={loading || rebuilding}
              style={{
                backgroundColor: "rgba(59, 130, 246, 0.15)",
                borderColor: "rgba(59, 130, 246, 0.4)",
                color: "var(--accent)",
                fontWeight: 600,
              }}
            >
              {rebuilding ? "Rebuilding Profiles..." : "Rebuild Baselines"}
            </button>
          )}
          <button
            id="refresh-behavior-btn"
            className="btn-refresh"
            onClick={fetchBehaviorData}
            disabled={loading || rebuilding}
          >
            {loading ? "Refreshing..." : "Refresh"}
          </button>
          <button id="logout-btn" className="btn-logout" onClick={logout}>
            Logout
          </button>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="content-area">
        <div className="header-banner">
          <h1 className="page-title">User Behavior Baseline & Feature Engine</h1>
          <p className="page-subtitle">
            Extracts behavioral telemetry from PostgreSQL request logs (7-day window) and models baseline profiles for Step 6 anomaly detection.
          </p>
        </div>

        {rebuildMsg && (
          <div
            id="rebuild-success-banner"
            style={{
              padding: "10px 14px",
              borderRadius: "6px",
              backgroundColor: "rgba(16, 185, 129, 0.1)",
              border: "1px solid rgba(16, 185, 129, 0.3)",
              color: "var(--success)",
              fontSize: "12px",
              marginBottom: "16px",
              fontFamily: "var(--font-mono)",
            }}
          >
            {rebuildMsg}
          </div>
        )}

        {errorMsg && (
          <div
            id="behavior-error-banner"
            style={{
              padding: "10px 14px",
              borderRadius: "6px",
              backgroundColor: "rgba(239, 68, 68, 0.1)",
              border: "1px solid rgba(239, 68, 68, 0.3)",
              color: "var(--danger)",
              fontSize: "12px",
              marginBottom: "16px",
            }}
          >
            {errorMsg}
          </div>
        )}

        {/* Feature Snapshot Grid */}
        <section className="info-panel" style={{ marginBottom: "20px" }}>
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "8px",
            }}
          >
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>Live Behavioral Feature Snapshot</span>
              <span
                style={{
                  fontSize: "11px",
                  padding: "2px 8px",
                  borderRadius: "4px",
                  backgroundColor: "rgba(59, 130, 246, 0.15)",
                  color: "var(--accent)",
                  fontFamily: "var(--font-mono)",
                }}
              >
                /api/behavior/features
              </span>
            </h2>
            <span style={{ fontSize: "12px", color: "var(--muted)" }}>
              Authenticated Principal: <strong>{user?.email}</strong>
            </span>
          </div>

          <p style={{ fontSize: "12px", color: "var(--muted)", margin: "4px 0 14px 0" }}>
            Real-time telemetry extracted from historical request logs. Used by Step 6 ML and statistical scoring to evaluate deviation from baseline.
          </p>

          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
              gap: "12px",
            }}
          >
            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Requests / Minute
              </div>
              <div
                id="feature-rpm"
                style={{
                  fontSize: "22px",
                  fontWeight: 700,
                  color: "var(--text)",
                  fontFamily: "var(--font-mono)",
                  marginTop: "4px",
                }}
              >
                {featureSnapshot ? featureSnapshot.requests_per_minute : "—"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                Active burst velocity
              </div>
            </div>

            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Unique Endpoints
              </div>
              <div
                id="feature-endpoints"
                style={{
                  fontSize: "22px",
                  fontWeight: 700,
                  color: "var(--accent)",
                  fontFamily: "var(--font-mono)",
                  marginTop: "4px",
                }}
              >
                {featureSnapshot ? featureSnapshot.unique_endpoints : "—"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                Distinct paths accessed
              </div>
            </div>

            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Failed Requests (4xx/5xx)
              </div>
              <div
                id="feature-failed"
                style={{
                  fontSize: "22px",
                  fontWeight: 700,
                  color:
                    featureSnapshot && featureSnapshot.failed_requests > 0
                      ? "var(--danger)"
                      : "var(--success)",
                  fontFamily: "var(--font-mono)",
                  marginTop: "4px",
                }}
              >
                {featureSnapshot ? featureSnapshot.failed_requests : "—"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                Error count in window
              </div>
            </div>

            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Sensitive Endpoints
              </div>
              <div
                id="feature-sensitive"
                style={{
                  fontSize: "22px",
                  fontWeight: 700,
                  color: "var(--warning)",
                  fontFamily: "var(--font-mono)",
                  marginTop: "4px",
                }}
              >
                {featureSnapshot ? featureSnapshot.sensitive_endpoint_access : "—"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                High-privilege routes
              </div>
            </div>

            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Device / IP Delta
              </div>
              <div
                style={{
                  display: "flex",
                  gap: "8px",
                  marginTop: "6px",
                  fontSize: "12px",
                  fontFamily: "var(--font-mono)",
                }}
              >
                <span
                  style={{
                    padding: "3px 6px",
                    borderRadius: "4px",
                    backgroundColor:
                      featureSnapshot?.device_change
                        ? "rgba(239, 68, 68, 0.2)"
                        : "rgba(16, 185, 129, 0.1)",
                    color: featureSnapshot?.device_change
                      ? "var(--danger)"
                      : "var(--success)",
                  }}
                >
                  Dev: {featureSnapshot?.device_change ? "CHANGED" : "STABLE"}
                </span>
                <span
                  style={{
                    padding: "3px 6px",
                    borderRadius: "4px",
                    backgroundColor:
                      featureSnapshot?.location_change
                        ? "rgba(239, 68, 68, 0.2)"
                        : "rgba(16, 185, 129, 0.1)",
                    color: featureSnapshot?.location_change
                      ? "var(--danger)"
                      : "var(--success)",
                  }}
                >
                  IP: {featureSnapshot?.location_change ? "CHANGED" : "STABLE"}
                </span>
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                User-Agent & Client IP check
              </div>
            </div>

            <div className="soc-card" style={{ padding: "14px" }}>
              <div style={{ fontSize: "11px", color: "var(--muted)", textTransform: "uppercase" }}>
                Current Usage Hour
              </div>
              <div
                id="feature-hour"
                style={{
                  fontSize: "22px",
                  fontWeight: 700,
                  color: "var(--text)",
                  fontFamily: "var(--font-mono)",
                  marginTop: "4px",
                }}
              >
                {featureSnapshot ? `${featureSnapshot.current_hour}:00 UTC` : "—"}
              </div>
              <div style={{ fontSize: "11px", color: "var(--muted)", marginTop: "4px" }}>
                Avg Latency: {featureSnapshot?.average_response_time || 0} ms
              </div>
            </div>
          </div>
        </section>

        {/* Behavior Profiles Table */}
        <section className="info-panel">
          <div
            style={{
              display: "flex",
              justifyContent: "space-between",
              alignItems: "center",
              marginBottom: "14px",
            }}
          >
            <div>
              <h2 className="info-title" style={{ margin: 0 }}>
                <span>Behavioral Profiles Matrix</span>
                <span className="topbar-badge" style={{ marginLeft: "8px" }}>
                  {isAdmin ? "ALL IDENTITIES (ADMIN VIEW)" : "MY PROFILE"}
                </span>
              </h2>
              <p style={{ fontSize: "12px", color: "var(--muted)", marginTop: "4px" }}>
                Persisted in PostgreSQL table <code>behavior_profiles</code>. Minimum maturity threshold: 0–9 reqs (INSUFFICIENT DATA), 10–49 reqs (LEARNING), 50+ reqs (ESTABLISHED).
              </p>
            </div>
            <div style={{ fontSize: "12px", color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
              Total Profiles: <strong>{profiles.length}</strong>
            </div>
          </div>

          <div style={{ overflowX: "auto" }}>
            <table
              id="behavior-profiles-table"
              style={{
                width: "100%",
                borderCollapse: "collapse",
                fontSize: "12px",
                textAlign: "left",
              }}
            >
              <thead>
                <tr
                  style={{
                    backgroundColor: "var(--surface-secondary)",
                    borderBottom: "1px solid var(--border)",
                    color: "var(--muted)",
                    fontSize: "11px",
                    textTransform: "uppercase",
                    letterSpacing: "0.05em",
                  }}
                >
                  <th style={{ padding: "10px 12px" }}>User Principal</th>
                  <th style={{ padding: "10px 12px" }}>Baseline Status</th>
                  <th style={{ padding: "10px 12px" }}>Req / Min</th>
                  <th style={{ padding: "10px 12px" }}>Known Devices</th>
                  <th style={{ padding: "10px 12px" }}>Known IPs</th>
                  <th style={{ padding: "10px 12px" }}>Sensitive Access</th>
                  <th style={{ padding: "10px 12px" }}>Normal Hours (UTC)</th>
                  <th style={{ padding: "10px 12px" }}>Sample Count</th>
                  <th style={{ padding: "10px 12px" }}>Avg Latency</th>
                  <th style={{ padding: "10px 12px" }}>Last Updated</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr>
                    <td colSpan="10" style={{ padding: "24px", textAlign: "center", color: "var(--muted)" }}>
                      Loading behavioral baseline profiles from PostgreSQL...
                    </td>
                  </tr>
                ) : profiles.length === 0 ? (
                  <tr>
                    <td colSpan="10" style={{ padding: "24px", textAlign: "center", color: "var(--muted)" }}>
                      No behavior profiles calculated yet. Click "Rebuild Baselines" to aggregate historical logs.
                    </td>
                  </tr>
                ) : (
                  profiles.map((p) => {
                    const statusInfo = getStatusBadge(p.baseline_status);
                    return (
                      <tr
                        key={p.user_id}
                        style={{
                          borderBottom: "1px solid var(--border)",
                          transition: "background-color 0.15s ease",
                        }}
                        onMouseEnter={(e) =>
                          (e.currentTarget.style.backgroundColor = "var(--surface-secondary)")
                        }
                        onMouseLeave={(e) =>
                          (e.currentTarget.style.backgroundColor = "transparent")
                        }
                      >
                        <td style={{ padding: "10px 12px" }}>
                          <div style={{ fontWeight: 600, color: "var(--text)" }}>
                            {p.username || `User #${p.user_id}`}
                          </div>
                          <div
                            style={{
                              fontSize: "10px",
                              color: "var(--muted)",
                              fontFamily: "var(--font-mono)",
                            }}
                          >
                            UID: {p.user_id}
                          </div>
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          <span
                            style={{
                              fontSize: "10px",
                              fontWeight: 700,
                              fontFamily: "var(--font-mono)",
                              padding: "3px 8px",
                              borderRadius: "4px",
                              backgroundColor: statusInfo.bg,
                              color: statusInfo.color,
                              border: statusInfo.border,
                              display: "inline-block",
                              whiteSpace: "nowrap",
                            }}
                          >
                            {p.baseline_status}
                          </span>
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            color: "var(--text)",
                          }}
                        >
                          {p.avg_requests_per_minute}
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            color: "var(--text)",
                          }}
                        >
                          {p.known_devices}
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            color: "var(--text)",
                          }}
                        >
                          {p.known_ips}
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            color: p.avg_sensitive_access > 0 ? "var(--warning)" : "var(--muted)",
                          }}
                        >
                          {p.avg_sensitive_access}
                        </td>
                        <td style={{ padding: "10px 12px" }}>
                          {p.normal_hours && p.normal_hours.length > 0 ? (
                            <div style={{ display: "flex", flexWrap: "wrap", gap: "4px" }}>
                              {p.normal_hours.map((hr) => (
                                <span
                                  key={hr}
                                  style={{
                                    fontSize: "10px",
                                    fontFamily: "var(--font-mono)",
                                    padding: "1px 5px",
                                    borderRadius: "3px",
                                    backgroundColor: "var(--surface-secondary)",
                                    border: "1px solid var(--border)",
                                    color: "var(--text)",
                                  }}
                                >
                                  {hr}:00
                                </span>
                              ))}
                            </div>
                          ) : (
                            <span style={{ color: "var(--muted)", fontSize: "11px" }}>None</span>
                          )}
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            fontWeight: 600,
                            color: "var(--accent)",
                          }}
                        >
                          {p.sample_count} reqs
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontFamily: "var(--font-mono)",
                            color: "var(--text)",
                          }}
                        >
                          {p.avg_response_time} ms
                        </td>
                        <td
                          style={{
                            padding: "10px 12px",
                            fontSize: "11px",
                            color: "var(--muted)",
                            whiteSpace: "nowrap",
                          }}
                        >
                          {p.updated_at
                            ? new Date(p.updated_at).toLocaleString()
                            : "Never"}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </section>
      </main>
    </div>
  );
}
