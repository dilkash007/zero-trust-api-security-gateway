import React, { useState } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Login() {
  const { login, isAuthenticated } = useAuth();
  const navigate = useNavigate();

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [errorMessage, setErrorMessage] = useState("");

  // If already logged in, redirect directly to dashboard
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const handleSubmit = async (e) => {
    e.preventDefault();
    setErrorMessage("");

    if (!email.trim() || !password) {
      setErrorMessage("Please enter both email and password.");
      return;
    }

    setSubmitting(true);
    try {
      await login(email.trim(), password);
      navigate("/dashboard", { replace: true });
    } catch (err) {
      if (!err.response) {
        setErrorMessage("Backend unavailable");
      } else if (err.response.status === 401) {
        setErrorMessage("Invalid email or password");
      } else if (err.response.status === 403) {
        setErrorMessage("User account is inactive");
      } else {
        setErrorMessage("Authentication failed. Please verify credentials.");
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <div className="login-header">
          <div className="brand-badge">
            <span className="shield-icon"></span>
            <span>Zero-Trust Gateway Identity</span>
          </div>
          <h1 className="login-title">ZERO-TRUST SECURITY CENTER</h1>
          <p className="login-subtitle">Identity Verification & Access Control</p>
        </div>

        {errorMessage && (
          <div className="login-error-banner" id="login-error">
            <span className="dot dot-disconnected"></span>
            <span>{errorMessage}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="login-form">
          <div className="form-group">
            <label htmlFor="login-email" className="form-label">
              Email Address
            </label>
            <input
              id="login-email"
              type="email"
              className="form-input"
              placeholder="user@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              disabled={submitting}
              autoComplete="username"
              required
            />
          </div>

          <div className="form-group">
            <label htmlFor="login-password" className="form-label">
              Password
            </label>
            <input
              id="login-password"
              type="password"
              className="form-input"
              placeholder="••••••••"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              disabled={submitting}
              autoComplete="current-password"
              required
            />
          </div>

          <button
            id="login-submit-btn"
            type="submit"
            className="btn-signin"
            disabled={submitting}
          >
            {submitting ? "Authenticating..." : "Sign In"}
          </button>
        </form>

        <div className="login-footer">
          <span>Continuous Zero-Trust Verification</span>
          <span>Role: Standard & Admin</span>
        </div>
      </div>
    </div>
  );
}
