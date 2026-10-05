import React, { createContext, useContext, useEffect, useState } from "react";
import { getMeApi, loginApi } from "../services/api";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => localStorage.getItem("zero_trust_token"));
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  // Initialize auth state by validating existing token against backend /api/auth/me
  useEffect(() => {
    let isMounted = true;

    const initializeAuth = async () => {
      const storedToken = localStorage.getItem("zero_trust_token");
      if (storedToken) {
        try {
          const userData = await getMeApi();
          if (isMounted) {
            setUser(userData);
            setToken(storedToken);
          }
        } catch {
          if (isMounted) {
            localStorage.removeItem("zero_trust_token");
            setToken(null);
            setUser(null);
          }
        }
      } else {
        if (isMounted) {
          setToken(null);
          setUser(null);
        }
      }
      if (isMounted) {
        setLoading(false);
      }
    };

    initializeAuth();

    // Listen to global 401 interceptor logout event
    const handleGlobalLogout = () => {
      setToken(null);
      setUser(null);
      localStorage.removeItem("zero_trust_token");
    };

    window.addEventListener("zero_trust_logout", handleGlobalLogout);
    return () => {
      isMounted = false;
      window.removeEventListener("zero_trust_logout", handleGlobalLogout);
    };
  }, []);

  const login = async (email, password) => {
    const data = await loginApi(email, password);
    localStorage.setItem("zero_trust_token", data.access_token);
    setToken(data.access_token);
    setUser(data.user);
    return data;
  };

  const logout = () => {
    localStorage.removeItem("zero_trust_token");
    setToken(null);
    setUser(null);
  };

  const value = {
    user,
    token,
    login,
    logout,
    loading,
    isAuthenticated: Boolean(token && user),
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
