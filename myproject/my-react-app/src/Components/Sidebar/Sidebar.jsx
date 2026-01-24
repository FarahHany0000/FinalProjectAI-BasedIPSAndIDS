import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';

export default function Sidebar() {
  const navigate = useNavigate();
  const handleLogout = () => {
    localStorage.removeItem('access_token'); 
    localStorage.removeItem('role');         
    navigate('/');                       
  };

  return (
    <div className="sidebar">
      <h2>AI Intrusion Detection Prevention System</h2>
      <nav>
        <ul className="sidebar-menu">
          <li>
            <NavLink 
              to="/dashboard" 
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}
            >
              Review
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/alert" 
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}
            >
              Alerts
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/host" 
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}
            >
              Host
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/scanner" 
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}
            >
              Scanner
            </NavLink>
          </li>
          <li>
            <NavLink 
              to="/updatepage" 
              className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}
            >
              Update Model
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
