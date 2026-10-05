import React, { useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  getProfile,
  getOrders,
  getPayment,
  getUsers,
  getAdminUsers,
  getAdminTransactions,
} from "../services/api";

export default function ApiTraffic() {
  const { user, logout } = useAuth();
  const [trafficLogs, setTrafficLogs] = useState([]);
  const [loadingEndpoint, setLoadingEndpoint] = useState(null);

  const executeApiCall = async (endpointName, apiFn, method = "GET", isSensitive = false) => {
    setLoadingEndpoint(endpointName);

    let status = 0;
    let requestId = "N/A";
    let message = "";
    let userRole = user?.role || "USER";
    let userName = user?.name || "Anonymous";

    try {
      const response = await apiFn();
      status = response.status;
      requestId =
        response.headers["x-request-id"] ||
        response.data?.security_context?.request_id ||
        "generated-id";
      message = response.data?.data?.message || "Data retrieved successfully";
      if (response.data?.security_context?.role) {
        userRole = response.data.security_context.role;
      }
    } catch (err) {
      if (err.response) {
        status = err.response.status;
        requestId =
          err.response.headers["x-request-id"] ||
          err.response.data?.error?.request_id ||
          "denied-id";

        if (status === 401) {
          message = "Authentication required";
        } else if (status === 403) {
          message = "You do not have permission to access this resource.";
        } else if (status === 500) {
          message = "Internal server error";
        } else {
          message = err.response.data?.error?.message || "Request failed";
        }
      } else {
        status = 0;
        message = "Backend unavailable";
      }
    }

    const logEntry = {
      id: Date.now() + Math.random(),
      requestId,
      endpoint: endpointName,
      method,
      status,
      user: userName,
      role: userRole,
      sensitive: isSensitive ? "YES" : "NO",
      message,
      timestamp: new Date().toLocaleTimeString(),
    };

    setTrafficLogs((prev) => [logEntry, ...prev]);
    setLoadingEndpoint(null);
  };

  const clearLogs = () => {
    setTrafficLogs([]);
  };

  const runAllTests = async () => {
    await executeApiCall("/api/profile", getProfile, "GET", false);
    await executeApiCall("/api/orders", getOrders, "GET", false);
    await executeApiCall("/api/payment", getPayment, "GET", true);
    await executeApiCall("/api/users", getUsers, "GET", true);
    await executeApiCall("/api/admin/users", getAdminUsers, "GET", true);
    await executeApiCall("/api/admin/transactions", getAdminTransactions, "GET", true);
  };

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">API Traffic Inspection</span>
          <span className="topbar-badge">GATEWAY TELEMETRY</span>
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
          <h1 className="page-title">Live API Traffic & Gateway Interception</h1>
          <p className="page-subtitle">
            Zero-Trust API Security Engine — Step 3: Centralized Inspection, Request IDs & Role Authorization
          </p>
        </div>

        {/* API Action Control Panel */}
        <section className="info-panel" style={{ marginBottom: "24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>Protected API Test Triggers</span>
            </h2>
            <div style={{ display: "flex", gap: "10px" }}>
              <button
                id="btn-run-all"
                className="btn-refresh"
                onClick={runAllTests}
                disabled={Boolean(loadingEndpoint)}
                style={{ backgroundColor: "var(--accent)", color: "#fff", borderColor: "var(--accent)" }}
              >
                Run All Endpoints
              </button>
              <button
                id="btn-clear-logs"
                className="btn-refresh"
                onClick={clearLogs}
                disabled={trafficLogs.length === 0}
              >
                Clear Results
              </button>
            </div>
          </div>

          <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: "12px" }}>
            <button
              id="btn-call-profile"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/profile", getProfile, "GET", false)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center" }}
            >
              {loadingEndpoint === "/api/profile" ? "Calling..." : "GET /api/profile (Normal)"}
            </button>

            <button
              id="btn-call-orders"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/orders", getOrders, "GET", false)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center" }}
            >
              {loadingEndpoint === "/api/orders" ? "Calling..." : "GET /api/orders (Normal)"}
            </button>

            <button
              id="btn-call-payment"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/payment", getPayment, "GET", true)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center", borderColor: "rgba(245, 158, 11, 0.4)" }}
            >
              {loadingEndpoint === "/api/payment" ? "Calling..." : "GET /api/payment (Sensitive)"}
            </button>

            <button
              id="btn-call-users"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/users", getUsers, "GET", true)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center", borderColor: "rgba(239, 68, 68, 0.4)" }}
            >
              {loadingEndpoint === "/api/users" ? "Calling..." : "GET /api/users (Admin)"}
            </button>

            <button
              id="btn-call-admin-users"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/admin/users", getAdminUsers, "GET", true)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center", borderColor: "rgba(239, 68, 68, 0.4)" }}
            >
              {loadingEndpoint === "/api/admin/users" ? "Calling..." : "GET /api/admin/users (Admin)"}
            </button>

            <button
              id="btn-call-admin-tx"
              className="btn-refresh"
              onClick={() => executeApiCall("/api/admin/transactions", getAdminTransactions, "GET", true)}
              disabled={Boolean(loadingEndpoint)}
              style={{ justifyContent: "center", borderColor: "rgba(239, 68, 68, 0.4)" }}
            >
              {loadingEndpoint === "/api/admin/transactions" ? "Calling..." : "GET /api/admin/transactions (Admin)"}
            </button>
          </div>
        </section>

        {/* Live Traffic Table */}
        <section className="info-panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px" }}>
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>Gateway Interception Stream ({trafficLogs.length} events)</span>
            </h2>
            <span style={{ fontSize: "11px", color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
              REQUEST IDs EXTRACTED FROM X-Request-ID
            </span>
          </div>

          {trafficLogs.length === 0 ? (
            <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
              No API traffic recorded in this session. Click any endpoint button above to trigger live Zero-Trust gateway inspection.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)", textTransform: "uppercase", fontSize: "11px" }}>
                    <th style={{ padding: "10px" }}>Request ID</th>
                    <th style={{ padding: "10px" }}>Endpoint</th>
                    <th style={{ padding: "10px" }}>Method</th>
                    <th style={{ padding: "10px" }}>Status</th>
                    <th style={{ padding: "10px" }}>User</th>
                    <th style={{ padding: "10px" }}>Role</th>
                    <th style={{ padding: "10px" }}>Sensitive</th>
                    <th style={{ padding: "10px" }}>Gateway Message</th>
                  </tr>
                </thead>
                <tbody>
                  {trafficLogs.map((log) => {
                    const isSuccess = log.status >= 200 && log.status < 300;
                    const isForbidden = log.status === 403;
                    const isUnauthorized = log.status === 401;

                    let statusClass = "text-success";
                    if (isForbidden) statusClass = "text-danger";
                    else if (isUnauthorized) statusClass = "text-warning";
                    else if (!isSuccess) statusClass = "text-danger";

                    return (
                      <tr
                        key={log.id}
                        style={{
                          borderBottom: "1px solid rgba(255,255,255,0.05)",
                          backgroundColor: isForbidden ? "rgba(239, 68, 68, 0.03)" : "transparent",
                        }}
                      >
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                          {log.requestId.length > 13 ? `${log.requestId.substring(0, 13)}...` : log.requestId}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                          {log.endpoint}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)" }}>
                          {log.method}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", fontWeight: 700 }} className={statusClass}>
                          {log.status === 0 ? "ERR" : `${log.status} ${isSuccess ? "OK" : isForbidden ? "FORBIDDEN" : isUnauthorized ? "UNAUTHORIZED" : ""}`}
                        </td>
                        <td style={{ padding: "10px" }}>{log.user}</td>
                        <td style={{ padding: "10px" }}>
                          <span
                            style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "10px",
                              fontFamily: "var(--font-mono)",
                              backgroundColor: log.role === "ADMIN" ? "rgba(239, 68, 68, 0.15)" : "rgba(59, 130, 246, 0.15)",
                              color: log.role === "ADMIN" ? "var(--danger)" : "var(--accent)",
                            }}
                          >
                            {log.role}
                          </span>
                        </td>
                        <td style={{ padding: "10px" }}>
                          <span
                            style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "10px",
                              fontWeight: 600,
                              fontFamily: "var(--font-mono)",
                              backgroundColor: log.sensitive === "YES" ? "rgba(245, 158, 11, 0.15)" : "rgba(148, 163, 184, 0.1)",
                              color: log.sensitive === "YES" ? "var(--warning)" : "var(--muted)",
                            }}
                          >
                            {log.sensitive}
                          </span>
                        </td>
                        <td style={{ padding: "10px", color: isForbidden ? "#fca5a5" : "var(--text)" }}>
                          {log.message}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </main>
    </div>
  );
}
