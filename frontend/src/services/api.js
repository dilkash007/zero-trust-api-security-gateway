import axios from "axios";

// Centralized Axios API client configured for the FastAPI backend
const api = axios.create({
  baseURL: "http://localhost:8000",
  timeout: 5000,
  headers: {
    "Content-Type": "application/json",
  },
});

/**
 * Checks general backend service health.
 * Endpoint: GET /health
 */
export const checkHealth = async () => {
  const response = await api.get("/health");
  return response.data;
};

/**
 * Verifies live PostgreSQL database connectivity.
 * Endpoint: GET /health/database
 */
export const checkDatabaseHealth = async () => {
  const response = await api.get("/health/database");
  return response.data;
};

export default api;
