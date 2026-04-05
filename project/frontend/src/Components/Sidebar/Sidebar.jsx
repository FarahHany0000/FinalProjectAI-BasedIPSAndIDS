import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Monitor, Globe, Settings, LogOut, ShieldCheck } from 'lucide-react';

export default function Sidebar({ prevention }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/');
  };

  const menuItems = [
    { to: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/devices', label: 'Devices', icon: Monitor },
    { to: '/network', label: 'Network', icon: Globe },
    { to: '/controls', label: 'Controls', icon: Settings },
  ];

  return (
    <div className="sidebar">
      <div className="sidebar-brand">
        <ShieldCheck size={28} color="#3b82f6" />
        <h2>IDS / IPS</h2>
      </div>
      <p className="sidebar-subtitle">AI-Based Intrusion Detection & Prevention</p>

      <nav>
        <ul className="sidebar-menu">
          {menuItems.map(({ to, label, icon: Icon }) => (
            <li key={to}>
              <NavLink to={to}
                className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
                <Icon size={18} style={{ marginRight: 10, verticalAlign: 'middle' }} />
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* System Status */}
      {prevention && (
        <div className="sidebar-controls">
          <div className="sidebar-section-title">System Status</div>
          <div className="sidebar-status-item">
            <span className={prevention.enabled ? "active-dot" : "inactive-dot"} />
            Network IPS: {prevention.enabled ? "Active" : "Off"}
          </div>
          {prevention.blocked_ips?.length > 0 && (
            <div className="sidebar-status-item" style={{ color: "#ef4444", fontSize: "0.8rem" }}>
              {prevention.blocked_ips.length} IP{prevention.blocked_ips.length > 1 ? "s" : ""} blocked
            </div>
          )}
        </div>
      )}

      <button className="logout-btn" onClick={handleLogout}>
        <LogOut size={16} style={{ marginRight: 6, verticalAlign: 'middle' }} />
        Logout
      </button>
    </div>
  );
}
