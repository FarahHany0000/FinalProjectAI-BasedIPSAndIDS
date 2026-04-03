import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

export default function Sidebar({ dashboardMode = false, activeTab = "overview", onTabChange = () => {} }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/');
  };

  return (
    <div className="sidebar">
      <h2>AI Intrusion Detection Prevention System</h2>
      <nav>
        <ul className="sidebar-menu">
          <li>
            <NavLink to="/dashboardpage"
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
              Dashboard
            </NavLink>
          </li>
          <li>
            <NavLink to="/host"
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
              Hosts
            </NavLink>
          </li>
          <li>
            <NavLink to="/alert"
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
              Alerts
            </NavLink>
          </li>
          <li>
            <NavLink to="/agents"
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
              Agents
            </NavLink>
          </li>
          <li>
            <NavLink to="/network"
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
              Network
            </NavLink>
          </li>
        </ul>
      </nav>

      {dashboardMode && (
        <div className="sidebar-control-center">
          <h3>Control Center</h3>
          <button
            className={`sidebar-control-btn ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => onTabChange("overview")}
          >
            Overview
          </button>
          <button
            className={`sidebar-control-btn ${activeTab === "prevention" ? "active" : ""}`}
            onClick={() => onTabChange("prevention")}
          >
            Prevention Settings
          </button>
          <button
            className={`sidebar-control-btn ${activeTab === "ai" ? "active" : ""}`}
            onClick={() => onTabChange("ai")}
          >
            AI Decisions
          </button>
        </div>
      )}

      <button className="logout-btn" onClick={handleLogout}>
        Logout
      </button>
    </div>
  );
}
