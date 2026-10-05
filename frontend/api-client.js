/**
 * Zero-Trust API Security Gateway - Shared API Client & Telemetry Helper
 * 
 * Central communication layer between SOC frontend pages and the FastAPI backend.
 * Provides authentic JWT injection, error handling, session management, and real-time WebSockets.
 */

const API_BASE = window.location.protocol.startsWith("http")
  ? `http://${window.location.hostname || "127.0.0.1"}:8000`
  : "http://127.0.0.1:8000";

const isHttps = window.location.protocol === "https:";
const wsProtocol = isHttps ? "wss:" : "ws:";
const WS_BASE = window.location.port === "5173" || isHttps
  ? `${wsProtocol}//${window.location.host}`
  : `ws://${window.location.hostname || "127.0.0.1"}:8000`;

const Auth = {
  getToken() {
    return localStorage.getItem("zt_token") || "";
  },
  setToken(token) {
    if (token) localStorage.setItem("zt_token", token);
    else localStorage.removeItem("zt_token");
  },
  getUser() {
    try {
      const u = localStorage.getItem("zt_user");
      return u ? JSON.parse(u) : null;
    } catch (e) {
      return null;
    }
  },
  setUser(user) {
    if (user) localStorage.setItem("zt_user", JSON.stringify(user));
    else localStorage.removeItem("zt_user");
  },
  logout() {
    localStorage.removeItem("zt_token");
    localStorage.removeItem("zt_user");
    window.location.href = "zerotrust.html";
  },
  requireAuth() {
    const token = this.getToken();
    if (!token) {
      window.location.href = "zerotrust.html";
      return false;
    }
    return true;
  }
};

// Helper to determine candidate URLs dynamically
function getCandidateUrls(endpoint) {
  if (endpoint.startsWith("http://") || endpoint.startsWith("https://")) {
    if (endpoint.includes("localhost:8000")) {
      return [endpoint, endpoint.replace("localhost:8000", "127.0.0.1:8000")];
    }
    return [endpoint];
  }
  const cleanEp = endpoint.startsWith("/") ? endpoint : `/${endpoint}`;
  const host = window.location.hostname || "127.0.0.1";
  
  const urls = [];
  // Candidate 1: Same origin relative path (Vite proxy - completely immune to CORS)
  if (window.location.protocol.startsWith("http")) {
    urls.push(cleanEp);
  }
  // Candidate 2: Direct 127.0.0.1:8000 (IPv4 avoids macOS ::1 ECONNREFUSED)
  urls.push(`http://127.0.0.1:8000${cleanEp}`);
  // Candidate 3: Direct localhost:8000
  urls.push(`http://localhost:8000${cleanEp}`);
  if (host !== "127.0.0.1" && host !== "localhost") {
    urls.push(`http://${host}:8000${cleanEp}`);
  }
  return [...new Set(urls)];
}

// API Fetch Helper
const API = {
  async request(endpoint, options = {}) {
    const candidateUrls = getCandidateUrls(endpoint);
    const token = Auth.getToken();

    const headers = {
      "Content-Type": "application/json",
      ...(options.headers || {})
    };

    if (token) {
      headers["Authorization"] = `Bearer ${token}`;
    }

    let lastError = null;

    for (const url of candidateUrls) {
      try {
        const response = await fetch(url, { ...options, headers });
        
        // Handle Unauthorized (except login and public proxy testing endpoints)
        if (response.status === 401 && !endpoint.includes("/auth/login") && !endpoint.includes("/api/proxy")) {
          console.warn("Session expired or unauthorized. Redirecting to login...");
          Auth.logout();
          return null;
        }

        const data = await response.json().catch(() => ({}));
        let errorMsg = null;
        if (!response.ok) {
          if (typeof data.detail === "string") {
            errorMsg = data.detail;
          } else if (Array.isArray(data.detail)) {
            errorMsg = data.detail.map(d => d.msg || JSON.stringify(d)).join("; ");
          } else if (data.message) {
            errorMsg = data.message;
          } else {
            errorMsg = `HTTP ${response.status}`;
          }
        }

        return {
          ok: response.ok,
          status: response.status,
          data,
          error: errorMsg
        };
      } catch (err) {
        lastError = err;
        console.warn(`[API Client] Attempt failed on ${url}: ${err.message}. Trying next candidate...`);
      }
    }

    console.error(`[API Client] All candidates failed for ${endpoint}:`, lastError);
    return { ok: false, status: 0, error: lastError ? lastError.message : "Failed to fetch", data: null };
  },

  get(endpoint, params = {}) {
    let url = endpoint;
    const searchParams = new URLSearchParams();
    for (const [k, v] of Object.entries(params)) {
      if (v !== undefined && v !== null && v !== "") {
        searchParams.append(k, v);
      }
    }
    const qs = searchParams.toString();
    if (qs) url += `?${qs}`;
    return this.request(url, { method: "GET" });
  },

  post(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "POST",
      body: JSON.stringify(body)
    });
  },

  put(endpoint, body = {}) {
    return this.request(endpoint, {
      method: "PUT",
      body: JSON.stringify(body)
    });
  },

  delete(endpoint) {
    return this.request(endpoint, { method: "DELETE" });
  }
};

// Real-time WebSocket connection
function initWebSocket(onMessageCallback) {
  const token = Auth.getToken();
  if (!token) return null;

  try {
    const wsUrl = `${WS_BASE}/ws/security?token=${encodeURIComponent(token)}`;
    const ws = new WebSocket(wsUrl);

    ws.onopen = () => {
      console.log("[WS] Connected to Zero-Trust telemetry stream");
    };

    ws.onmessage = (event) => {
      try {
        const payload = JSON.parse(event.data);
        if (onMessageCallback) onMessageCallback(payload);
      } catch (e) {
        console.error("[WS] Message parsing error:", e);
      }
    };

    ws.onerror = (err) => {
      console.warn("[WS] Telemetry stream error:", err);
    };

    ws.onclose = () => {
      console.log("[WS] Telemetry stream closed. Reconnecting in 5s...");
      setTimeout(() => initWebSocket(onMessageCallback), 5000);
    };

    return ws;
  } catch (err) {
    console.warn("[WS] Could not start WebSocket:", err);
    return null;
  }
}

// Global UI Initialization (User Profile in header, Logout handler, Sync clocks)
document.addEventListener("DOMContentLoaded", () => {
  // Sync logged in user profile in header
  const user = Auth.getUser();
  if (user) {
    document.querySelectorAll(".user-name").forEach(el => el.textContent = user.name || "Operator");
    document.querySelectorAll(".user-email").forEach(el => el.textContent = user.email || "admin@example.com");
    document.querySelectorAll(".user-avatar-circle").forEach(el => {
      const initial = (user.name || user.email || "A").charAt(0).toUpperCase();
      el.textContent = initial;
    });
  }

  // Hook logout button
  document.querySelectorAll(".btn-logout").forEach(btn => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      Auth.logout();
    });
  });
});
