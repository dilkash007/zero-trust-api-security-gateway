import React from "react";
import { NavLink } from "react-router-dom";

export default function Sidebar() {
  const navItems = [
    { label: "Overview", path: "/dashboard", active: true, tag: "ACTIVE" },
    { label: "API Traffic", path: "/traffic", active: true, tag: "ACTIVE" },
    { label: "Threats & Anomalies", path: "/threats", active: true, tag: "STEP 6" },
    { label: "Behavior Baselines", path: "/behavior", active: true, tag: "ACTIVE" },
    { label: "Security Policies", path: "#policies", active: false, tag: "STEP 7" },
  ];

  return (
    <aside className="sidebar">
      <div className="sidebar-header">
        <div className="brand-badge">
          <span className="shield-icon"></span>
          <span>Zero-Trust Architecture</span>
        </div>
        <div className="sidebar-title">ZERO-TRUST SECURITY CENTER</div>
        <div className="sidebar-subtitle">Behavioral Anomaly Engine v0.1.0</div>
      </div>

      <nav className="sidebar-nav">
        {navItems.map((item) => {
          if (item.active) {
            return (
              <NavLink
                key={item.label}
                to={item.path}
                className={({ isActive }) =>
                  `nav-item ${isActive ? "active" : ""}`
                }
              >
                <span>{item.label}</span>
                <span className="nav-tag">{item.tag}</span>
              </NavLink>
            );
          }
          return (
            <div
              key={item.label}
              className="nav-item"
              style={{ cursor: "not-allowed", opacity: 0.65 }}
              title="Coming in later project steps"
            >
              <span>{item.label}</span>
              <span className="nav-tag">{item.tag}</span>
            </div>
          );
        })}
      </nav>

      <div className="sidebar-footer">
        <div>CORE STACK: FastAPI + Postgres</div>
        <div>DETECTION ENGINE: Step 6 (Active)</div>
      </div>
    </aside>
  );
}
