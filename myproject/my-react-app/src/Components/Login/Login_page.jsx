import { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import "./Login.css";

import React from 'react'

export default function Login_page() {
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    const storedUser = localStorage.getItem("username");
    if (storedUser) navigate("/dashpage");
  }, [navigate]);

  const handleSubmit = (e) => {
    e.preventDefault();
    setLoading(true);
    setError("");

    const USERS = [
      { username: "admin", password: "admin", role: "admin" },
      { username: "user1", password: "1234", role: "user" },
    ];

    const user = USERS.find(
      (u) => u.username === username && u.password === password
    );

    if (!user) {
      setError("Invalid username or password");
      setLoading(false);
      return;
    }

    localStorage.setItem("username", user.username);
    localStorage.setItem("role", user.role);

    setLoading(false);
    navigate("/dashboardpage");
  };

  return (
    <div className="login-container">
      <div className="login-card">
        <h2>AI-IDS/IPS System</h2>
        <form onSubmit={handleSubmit}>
          <input
            placeholder="Username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
          <input
            type="password"
            placeholder="Password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          {error && <p className="error">{error}</p>}
          <button type="submit" disabled={loading}>
            {loading ? "Signing in..." : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );

}
