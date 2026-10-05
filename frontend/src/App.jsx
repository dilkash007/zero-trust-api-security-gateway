import React from "react";
import { Routes, Route, Navigate } from "react-router-dom";
import { AuthProvider, useAuth } from "./context/AuthContext";
import ProtectedRoute from "./components/ProtectedRoute";
import Sidebar from "./components/Sidebar";
import Dashboard from "./pages/Dashboard";
import Login from "./pages/Login";
import ApiTraffic from "./pages/ApiTraffic";
import Threats from "./pages/Threats";
import Behavior from "./pages/Behavior";

function HomeRedirect() {
  const { isAuthenticated, loading } = useAuth();
  if (loading) return null;
  return <Navigate to={isAuthenticated ? "/dashboard" : "/login"} replace />;
}

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/" element={<HomeRedirect />} />
        <Route path="/login" element={<Login />} />
        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <div className="app-container">
                <Sidebar />
                <Dashboard />
              </div>
            </ProtectedRoute>
          }
        />
        <Route
          path="/traffic"
          element={
            <ProtectedRoute>
              <div className="app-container">
                <Sidebar />
                <ApiTraffic />
              </div>
            </ProtectedRoute>
          }
        />
        <Route
          path="/threats"
          element={
            <ProtectedRoute>
              <div className="app-container">
                <Sidebar />
                <Threats />
              </div>
            </ProtectedRoute>
          }
        />
        <Route
          path="/behavior"
          element={
            <ProtectedRoute>
              <div className="app-container">
                <Sidebar />
                <Behavior />
              </div>
            </ProtectedRoute>
          }
        />
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </AuthProvider>
  );
}
