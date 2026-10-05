import React, { useEffect, useState } from "react";
import { useAuth } from "../context/AuthContext";
import {
  getApiRequests,
  getProfile,
  getOrders,
  getPayment,
  getUsers,
  getAdminUsers,
  getAdminTransactions,
} from "../services/api";

export default function ApiTraffic() {
  const { user, logout } = useAuth();
  const [dbLogs, setDbLogs] = useState([]);
  const [sessionLogs, setSessionLogs] = useState([]);
  const [loadingEndpoint, setLoadingEndpoint] = useState(null);
  const [fetchingDb, setFetchingDb] = useState(false);
  const [dbAccessForbidden, setDbAccessForbidden] = useState(false);
  const [filterSensitive, setFilterSensitive] = useState("");

  const fetchDatabaseLogs = async () => {
    setFetchingDb(true);
    setDbAccessForbidden(false);
    try {
      const params = { limit: 50 };
      if (filterSensitive === "true") params.is_sensitive = true;
      if (filterSensitive === "false") params.is_sensitive = false;

      const res = await getApiRequests(params);
      setDbLogs(res.data || []);
    } catch (err) {
      if (err.response?.status === 403) {
        setDbAccessForbidden(true);
      }
    } finally {
      setFetchingDb(false);
    }
  };

  useEffect(() => {
    fetchDatabaseLogs();
  }, [filterSensitive]);

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
        "N/A";
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
          "N/A";

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
      request_id: requestId,
      endpoint: endpointName,
      method,
      status_code: status,
      username: userName,
      role: userRole,
      is_sensitive: isSensitive,
      message,
      timestamp: new Date().toLocaleTimeString(),
      response_time_ms: 0,
    };

    setSessionLogs((prev) => [logEntry, ...prev]);
    setLoadingEndpoint(null);

    // Refresh database records if user is admin
    if (user?.role === "ADMIN") {
      fetchDatabaseLogs();
    }
  };

  const runAllTests = async () => {
    await executeApiCall("/api/profile", getProfile, "GET", false);
    await executeApiCall("/api/orders", getOrders, "GET", false);
    await executeApiCall("/api/payment", getPayment, "GET", true);
    await executeApiCall("/api/users", getUsers, "GET", true);
    await executeApiCall("/api/admin/users", getAdminUsers, "GET", true);
    await executeApiCall("/api/admin/transactions", getAdminTransactions, "GET", true);
  };

  // Determine display rows: use database logs if available (for Admin), or session logs (for User)
  const displayLogs = dbLogs.length > 0 ? dbLogs : sessionLogs;

  return (
    <div className="main-wrapper">
      {/* Top Navbar */}
      <header className="topbar">
        <div className="topbar-left">
          <span className="topbar-title">API Traffic Inspection</span>
          <span className="topbar-badge">POSTGRES TELEMETRY</span>
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
          <h1 className="page-title">Live API Traffic & Persistent Telemetry</h1>
          <p className="page-subtitle">
            Zero-Trust API Security Engine — Step 4: PostgreSQL Request Telemetry (`api_request_logs`)
          </p>
        </div>

        {/* API Action Control Panel */}
        <section className="info-panel" style={{ marginBottom: "24px" }}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "16px" }}>
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>Protected API Triggers</span>
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
              {user?.role === "ADMIN" && (
                <button
                  id="btn-refresh-db"
                  className="btn-refresh"
                  onClick={fetchDatabaseLogs}
                  disabled={fetchingDb}
                >
                  {fetchingDb ? "Syncing..." : "Sync Database Logs"}
                </button>
              )}
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

        {dbAccessForbidden && (
          <div
            style={{
              padding: "12px 16px",
              backgroundColor: "rgba(59, 130, 246, 0.1)",
              border: "1px solid rgba(59, 130, 246, 0.3)",
              borderRadius: "6px",
              marginBottom: "16px",
              fontSize: "12px",
              color: "var(--text)",
            }}
          >
            <strong>Note:</strong> Logged in as standard USER. Showing current session traffic. Historical database logs (`/api/requests`) require ADMIN role.
          </div>
        )}

        {/* Live Traffic Table */}
        <section className="info-panel">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "14px", flexWrap: "wrap", gap: "10px" }}>
            <h2 className="info-title" style={{ margin: 0 }}>
              <span>
                {dbLogs.length > 0 ? "PostgreSQL Audit Logs (`api_request_logs`)" : "Gateway Traffic Stream"} ({displayLogs.length} records)
              </span>
            </h2>
            <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ fontSize: "11px", color: "var(--muted)" }}>Filter Sensitive:</span>
              <select
                value={filterSensitive}
                onChange={(e) => setFilterSensitive(e.target.value)}
                style={{
                  backgroundColor: "var(--surface-secondary)",
                  color: "var(--text)",
                  border: "1px solid var(--border)",
                  borderRadius: "4px",
                  padding: "4px 8px",
                  fontSize: "11px",
                }}
              >
                <option value="">All Endpoints</option>
                <option value="true">Sensitive Only</option>
                <option value="false">Normal Only</option>
              </select>
            </div>
          </div>

          {displayLogs.length === 0 ? (
            <div style={{ padding: "36px", textAlign: "center", color: "var(--muted)", fontSize: "13px" }}>
              No request logs recorded yet. Trigger one of the API endpoints above.
            </div>
          ) : (
            <div style={{ overflowX: "auto" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "12px", textAlign: "left" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--border)", color: "var(--muted)", textTransform: "uppercase", fontSize: "11px" }}>
                    <th style={{ padding: "10px" }}>Request ID</th>
                    <th style={{ padding: "10px" }}>User</th>
                    <th style={{ padding: "10px" }}>Role</th>
                    <th style={{ padding: "10px" }}>Method</th>
                    <th style={{ padding: "10px" }}>Endpoint</th>
                    <th style={{ padding: "10px" }}>Status</th>
                    <th style={{ padding: "10px" }}>Latency</th>
                    <th style={{ padding: "10px" }}>Sensitive</th>
                    <th style={{ padding: "10px" }}>Timestamp</th>
                  </tr>
                </thead>
                <tbody>
                  {displayLogs.map((log, index) => {
                    const status = log.status_code;
                    const isSuccess = status >= 200 && status < 300;
                    const isForbidden = status === 403;
                    const isUnauthorized = status === 401;

                    let statusClass = "text-success";
                    if (isForbidden) statusClass = "text-danger";
                    else if (isUnauthorized) statusClass = "text-warning";
                    else if (!isSuccess) statusClass = "text-danger";

                    const timeStr = log.timestamp
                      ? log.timestamp.includes("T")
                        ? new Date(log.timestamp).toLocaleTimeString()
                        : log.timestamp
                      : "Now";

                    return (
                      <tr
                        key={log.request_id || index}
                        style={{
                          borderBottom: "1px solid rgba(255,255,255,0.05)",
                          backgroundColor: isForbidden ? "rgba(239, 68, 68, 0.03)" : "transparent",
                        }}
                      >
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", color: "var(--accent)" }}>
                          {log.request_id ? `${log.request_id.substring(0, 13)}...` : "N/A"}
                        </td>
                        <td style={{ padding: "10px" }}>{log.username || "Anonymous"}</td>
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
                            {log.role || "NONE"}
                          </span>
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)" }}>
                          {log.method}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                          {log.endpoint}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)", fontWeight: 700 }} className={statusClass}>
                          {status} {isSuccess ? "OK" : isForbidden ? "FORBIDDEN" : isUnauthorized ? "UNAUTHORIZED" : ""}
                        </td>
                        <td style={{ padding: "10px", fontFamily: "var(--font-mono)" }}>
                          {log.response_time_ms ? `${log.response_time_ms} ms` : "< 1 ms"}
                        </td>
                        <td style={{ padding: "10px" }}>
                          <span
                            style={{
                              padding: "2px 6px",
                              borderRadius: "4px",
                              fontSize: "10px",
                              fontWeight: 600,
                              fontFamily: "var(--font-mono)",
                              backgroundColor: log.is_sensitive ? "rgba(245, 158, 11, 0.15)" : "rgba(148, 163, 184, 0.1)",
                              color: log.is_sensitive ? "var(--warning)" : "var(--muted)",
                            }}
                          >
                            {log.is_sensitive ? "YES" : "NO"}
                          </span>
                        </td>
                        <td style={{ padding: "10px", fontSize: "11px", color: "var(--muted)", fontFamily: "var(--font-mono)" }}>
                          {timeStr}
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
