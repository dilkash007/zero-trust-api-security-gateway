import React, { useEffect, useState } from "react";
import { checkHealth, checkDatabaseHealth } from "../services/api";

export default function Dashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [backendHealth, setBackendHealth] = useState(null);
  const [databaseHealth, setDatabaseHealth] = useState(null);
  const [backendError, setBackendError] = useState(null);
  const [databaseError, setDatabaseError] = useState(null);
  const [lastChecked, setLastChecked] = useState(null);

  const fetchHealthData = async (isManualRefresh = false) => {
    if (isManualRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    // Reset error & data states for fresh evaluation
    let bData = null;
    let bErr = null;
    let dData = null;
    let dErr = null;

    try {
      bData = await checkHealth();
    } catch (err) {
      bErr = "Backend unavailable";
    }

    try {
      dData = await checkDatabaseHealth();
    } catch (err) {
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
          <span className="info-value" style={{ fontSize: "11px", color: "var(--muted)" }}>
            {lastChecked ? `Last Check: ${lastChecked}` : "Checking..."}
          </span>
          <button
            id="refresh-health-btn"
            className="btn-refresh"
            onClick={() => fetchHealthData(true)}
            disabled={loading || refreshing}
          >
            {refreshing ? "Checking..." : "Refresh Status"}
          </button>
        </div>
      </header>

      {/* Main Content */}
      <main className="content-area">
        <div className="header-banner">
          <h1 className="page-title">SOC Operations & Telemetry Status</h1>
          <p className="page-subtitle">
            Zero-Trust API Security Engine — Step 1: Foundation & PostgreSQL Verification
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
              <span>{isSystemOperational ? "READY FOR TELEMETRY" : "ATTENTION REQUIRED"}</span>
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
        </div>

        {/* Project Information Panel */}
        <section className="info-panel" id="panel-project-info">
          <h2 className="info-title">
            <span>Security Engine Blueprint</span>
          </h2>
          <p style={{ fontSize: "13px", color: "var(--muted)", lineHeight: 1.6 }}>
            Foundation deployment verification for the Zero-Trust API Security & Behavioral Anomaly Engine.
            All telemetry, behavioral profiling, and policy enforcement modules will build atop this verified base.
          </p>

          <div className="info-grid">
            <div className="info-item">
              <div className="info-label">Application</div>
              <div className="info-value">Zero-Trust API Security Engine</div>
            </div>
            <div className="info-item">
              <div className="info-label">Current Release</div>
              <div className="info-value">v0.1.0 (Step 1 Foundation)</div>
            </div>
            <div className="info-item">
              <div className="info-label">Backend Architecture</div>
              <div className="info-value">FastAPI + SQLAlchemy 2.x</div>
            </div>
            <div className="info-item">
              <div className="info-label">Storage Engine</div>
              <div className="info-value">PostgreSQL (psycopg2-binary)</div>
            </div>
            <div className="info-item">
              <div className="info-label">Frontend Platform</div>
              <div className="info-value">React + Vite + Axios</div>
            </div>
            <div className="info-item">
              <div className="info-label">Security Model</div>
              <div className="info-value">Zero-Trust Continuous Verification</div>
            </div>
          </div>
        </section>
      </main>
    </div>
  );
}
