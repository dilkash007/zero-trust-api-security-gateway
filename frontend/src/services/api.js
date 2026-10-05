import axios from "axios";

// Centralized Axios API client configured for the FastAPI backend
const api = axios.create({
  baseURL: "http://localhost:8000",
  timeout: 5000,
  headers: {
    "Content-Type": "application/json",
  },
});

// Request Interceptor: Automatically attach Bearer token if available
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem("zero_trust_token");
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => Promise.reject(error)
);

// Response Interceptor: Handle 401 Unauthorized globally
api.interceptors.response.use(
  (response) => response,
  (error) => {
    const status = error?.response?.status;
    const isLoginEndpoint = error?.config?.url?.includes("/api/auth/login");

    if (status === 401 && !isLoginEndpoint) {
      localStorage.removeItem("zero_trust_token");
      localStorage.removeItem("zero_trust_user");
      window.dispatchEvent(new Event("zero_trust_logout"));
    }
    return Promise.reject(error);
  }
);

/**
 * Health check APIs (Step 1)
 */
export const checkHealth = async () => {
  const response = await api.get("/health");
  return response.data;
};

export const checkDatabaseHealth = async () => {
  const response = await api.get("/health/database");
  return response.data;
};

/**
 * Authentication APIs (Step 2)
 */
export const loginApi = async (email, password) => {
  const response = await api.post("/api/auth/login", { email, password });
  return response.data;
};

export const registerApi = async (name, email, password) => {
  const response = await api.post("/api/auth/register", { name, email, password });
  return response.data;
};

export const getMeApi = async () => {
  const response = await api.get("/api/auth/me");
  return response.data;
};

export const testProtectedApi = async () => {
  const response = await api.get("/api/test/protected");
  return response.data;
};

/**
 * Protected Demo APIs (Step 3 Gateway)
 * Returns the Axios response to allow extracting X-Request-ID and status codes.
 */
export const getProfile = async () => {
  return await api.get("/api/profile");
};

export const getOrders = async () => {
  return await api.get("/api/orders");
};

export const getPayment = async () => {
  return await api.get("/api/payment");
};

export const getUsers = async () => {
  return await api.get("/api/users");
};

export const getAdminUsers = async () => {
  return await api.get("/api/admin/users");
};

export const getAdminTransactions = async () => {
  return await api.get("/api/admin/transactions");
};

export default api;
