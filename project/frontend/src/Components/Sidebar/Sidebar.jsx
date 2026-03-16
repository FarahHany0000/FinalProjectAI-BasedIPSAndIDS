import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

export default function Sidebar() {
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
      <button className="logout-btn" onClick={handleLogout}>
        Logout
      </button>
    </div>
  );
}
