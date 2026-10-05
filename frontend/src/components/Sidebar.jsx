import React from "react";
import { NavLink } from "react-router-dom";

export default function Sidebar() {
  const navItems = [
    { label: "Overview", path: "/dashboard", active: true, tag: "ACTIVE" },
    { label: "API Traffic", path: "/traffic", active: true, tag: "ACTIVE" },
    { label: "Threats", path: "#threats", active: false, tag: "STEP 4" },
    { label: "Attack Simulator", path: "#simulator", active: false, tag: "STEP 5" },
    { label: "Policies", path: "#policies", active: false, tag: "STEP 6" },
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
        <div>GATEWAY: Step 3 (Active)</div>
      </div>
    </aside>
  );
}
