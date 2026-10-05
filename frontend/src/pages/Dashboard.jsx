import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import { checkHealth, checkDatabaseHealth, testProtectedApi } from "../services/api";

export default function Dashboard() {
  const { user, logout } = useAuth();

  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [backendHealth, setBackendHealth] = useState(null);
  const [databaseHealth, setDatabaseHealth] = useState(null);
  const [backendError, setBackendError] = useState(null);
  const [databaseError, setDatabaseError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);
  const [protectedTestMsg, setProtectedTestMsg] = useState(null);

  const fetchHealthData = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    let bData = null;
    let bErr = null;
    let dData = null;
    let dErr = null;

    try {
      bData = await checkHealth();
    } catch {
      bErr = "Backend unavailable";
    }

    try {
      dData = await checkDatabaseHealth();
    } catch {
      dErr = "Database unavailable";
    }

    setBackendHealth(bData);
    setBackendError(bErr);
    setDatabaseHealth(dData);
    setDatabaseError(dErr);
    setLastChecked(new Date().toLocaleTimeString());
    setLoading(false);
    setRefreshing(false);
  };

  const handleTestProtected = async () => {
    try {
      const res = await testProtectedApi();
      setProtectedTestMsg(`Success: ${res.message} (Role: ${res.role})`);
    } catch (err) {
      if (err.response?.status === 401) {
        setProtectedTestMsg("Error 401: Unauthorized (Invalid or expired token)");
      } else {
        setProtectedTestMsg("Protected call failed");
      }
    }
  };

  useEffect(() => {
    fetchHealthData();
  }, []);

  const isBackendConnected = Boolean(backendHealth && backendHealth.status === "ok");
  const isDatabaseConnected = Boolean(databaseHealth && databaseHealth.database === "connected");
  const isSystemOperational = isBackendConnected && isDatabaseConnected;

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">Overview</span>
          <span className="topbar-badge">SOC MONITOR</span>
        </div>
        <div className="topbar-right">
          {user && (
            <div className="user-greeting" id="user-greeting">
              <span className="user-welcome">Welcome, {user.name}</span>
              <span className="user-role-badge">Role: {user.role}</span>
            </div>
          )}
          <span className="info-value" style={{ fontSize: "11px", color: "var(--muted)" }}>
            {lastChecked ? `Check: ${lastChecked}` : "Checking..."}
          </span>
          <button
            id="refresh-health-btn"
            className="btn-refresh"
            onClick={() => fetchHealthData(true)}
            disabled={loading || refreshing}
          >
            {refreshing ? "Checking..." : "Refresh Status"}
          </button>
          <button
            id="logout-btn"
            className="btn-logout"
            onClick={logout}
            title="Sign out of current session"
          >
            Logout
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="content-area">
        <div className="header-banner">
          <h1 className="page-title">SOC Operations & Telemetry Status</h1>
          <p className="page-subtitle">
            Zero-Trust API Security Engine — Step 2: Authentication & Identity Active
          </p>
        </div>

        {/* Status Cards Grid */}
        <div className="cards-grid">
          {/* Card 1: System Status */}
          <div className="soc-card" id="card-system-status">
            <div className="card-header">
              <span className="card-title">System Status</span>
              <span className="topbar-badge">CORE</span>
            </div>
            <div>
              {loading ? (
                <div className="status-indicator">
                  <span className="dot dot-loading"></span>
                  <span className="text-warning">Initializing Diagnostic...</span>
                </div>
              ) : isSystemOperational ? (
                <div className="status-indicator">
                  <span className="dot dot-connected"></span>
                  <span className="text-success">Operational</span>
                </div>
              ) : (
                <div className="status-indicator">
                  <span className="dot dot-disconnected"></span>
                  <span className="text-danger">Degraded Service</span>
                </div>
              )}
            </div>
            <div className="card-footer">
              <span>SECURITY SCOPE</span>
              <span>{isSystemOperational ? "IDENTITY & TELEMETRY READY" : "ATTENTION REQUIRED"}</span>
            </div>
          </div>

          {/* Card 2: Backend Connection */}
          <div className="soc-card" id="card-backend-connection">
            <div className="card-header">
              <span className="card-title">Backend Connection</span>
              <span className="topbar-badge">FASTAPI</span>
            </div>
            <div>
              {loading ? (
                <div className="status-indicator">
                  <span className="dot dot-loading"></span>
                  <span className="text-warning">Checking /health...</span>
                </div>
              ) : isBackendConnected ? (
                <div className="status-indicator">
                  <span className="dot dot-connected"></span>
                  <span className="text-success">Backend Connected</span>
                </div>
              ) : (
                <div className="status-indicator">
                  <span className="dot dot-disconnected"></span>
                  <span className="text-danger">
                    {backendError || "Backend unavailable"}
                  </span>
                </div>
              )}
            </div>
            <div className="card-footer">
              <span>ENDPOINT: /health</span>
              <span>{isBackendConnected ? `v${backendHealth.version}` : "OFFLINE"}</span>
            </div>
          </div>

          {/* Card 3: Database Connection */}
          <div className="soc-card" id="card-database-connection">
            <div className="card-header">
              <span className="card-title">Database Connection</span>
              <span className="topbar-badge">POSTGRESQL</span>
            </div>
            <div>
              {loading ? (
                <div className="status-indicator">
                  <span className="dot dot-loading"></span>
                  <span className="text-warning">Checking /health/database...</span>
                </div>
              ) : isDatabaseConnected ? (
                <div className="status-indicator">
                  <span className="dot dot-connected"></span>
                  <span className="text-success">PostgreSQL Connected</span>
                </div>
              ) : (
                <div className="status-indicator">
                  <span className="dot dot-disconnected"></span>
                  <span className="text-danger">
                    {databaseError || "Database unavailable"}
                  </span>
                </div>
              )}
            </div>
            <div className="card-footer">
              <span>TARGET DB</span>
              <span>{isDatabaseConnected ? "zero_trust_db" : "UNREACHABLE"}</span>
            </div>
          </div>

          {/* Card 4: Identity & Session Status */}
          <div className="soc-card" id="card-identity-session">
            <div className="card-header">
              <span className="card-title">Identity & Session</span>
              <span className="topbar-badge">JWT</span>
            </div>
            <div>
              <div className="status-indicator">
                <span className="dot dot-connected"></span>
                <span className="text-success">Authenticated</span>
              </div>
            </div>
            <div className="card-footer">
              <span>ROLE</span>
              <span style={{ color: "var(--accent)", fontWeight: 600 }}>{user?.role || "USER"}</span>
            </div>
          </div>
        </div>

        {/* Authenticated Identity & Protected Endpoint Verification */}
        <section className="info-panel" id="panel-identity-info" style={{ marginBottom: "20px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "12px" }}>
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>Authenticated Principal Profile</span>
            </h2>
            <button
              id="test-protected-btn"
              className="btn-refresh"
              onClick={handleTestProtected}
              style={{ fontSize: "11px" }}
            >
              Verify /api/test/protected
            </button>
          </div>
          {protectedTestMsg && (
            <div
              id="protected-test-result"
              style={{
                fontSize: "12px",
                padding: "8px 12px",
                borderRadius: "4px",
                backgroundColor: "var(--surface-secondary)",
                border: "1px solid var(--border)",
                color: protectedTestMsg.startsWith("Success") ? "var(--success)" : "var(--danger)",
                marginBottom: "12px",
                fontFamily: "var(--font-mono)"
              }}
            >
              {protectedTestMsg}
            </div>
          )}
          <div className="info-grid">
            <div className="info-item">
              <div className="info-label">Identity Name</div>
              <div className="info-value">{user?.name}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Email Address</div>
              <div className="info-value">{user?.email}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Assigned Role</div>
              <div className="info-value">{user?.role}</div>
            </div>
            <div className="info-item">
              <div className="info-label">Account Status</div>
              <div className="info-value" style={{ color: "var(--success)" }}>Active</div>
            </div>
          </div>
        </section>

        {/* Project Information Panel */}
        <section className="info-panel" id="panel-project-info">
          <h2 className="info-title">
            <span>Security Engine Blueprint</span>
          </h2>
          <p style={{ fontSize: "13px", color: "var(--muted)", lineHeight: 1.6 }}>
            Step 2 identity layer established. All subsequent requests in upcoming steps
            (telemetry logging, behavioral baselining, and policy enforcement) are linked to
            authenticated user principals.
          </p>

          <div className="info-grid">
            <div className="info-item">
              <div className="info-label">Application</div>
              <div className="info-value">Zero-Trust API Security Engine</div>
            </div>
            <div className="info-item">
              <div className="info-label">Current Release</div>
              <div className="info-value">v0.1.0 (Step 2 - Identity Layer)</div>
            </div>
            <div className="info-item">
              <div className="info-label">Identity Store</div>
              <div className="info-value">PostgreSQL users (Bcrypt Hashes)</div>
            </div>
            <div className="info-item">
              <div className="info-label">Auth Protocol</div>
              <div className="info-value">JWT Bearer (HS256)</div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
