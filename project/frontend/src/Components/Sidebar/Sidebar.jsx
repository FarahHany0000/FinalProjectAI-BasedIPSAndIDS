import React from 'react';
import { NavLink, useNavigate } from 'react-router-dom';
import { LayoutDashboard, Monitor, Bell, Users, Shield, Settings, LogOut } from 'lucide-react';

export default function Sidebar({ activePage, prevention }) {
  const navigate = useNavigate();

  const handleLogout = () => {
    localStorage.removeItem('access_token');
    navigate('/');
  };

  const menuItems = [
    { to: '/dashboardpage', label: 'Dashboard', icon: LayoutDashboard },
    { to: '/host', label: 'Hosts', icon: Monitor },
    { to: '/alert', label: 'Alerts', icon: Bell },
    { to: '/agents', label: 'Agents', icon: Users },
    { to: '/network', label: 'Network', icon: Shield },
    { to: '/controls', label: 'Controls', icon: Settings },
  ];

  return (
    <div className="sidebar">
      <h2>AI Intrusion Detection Prevention System</h2>
      <nav>
        <ul className="sidebar-menu">
          {menuItems.map(({ to, label, icon: Icon }) => (
            <li key={to}>
              <NavLink to={to}
                className={({ isActive }) => isActive ? "menu-link active" : "menu-link"}>
                <Icon size={16} style={{ marginRight: 8, verticalAlign: 'middle' }} />
                {label}
              </NavLink>
            </li>
          ))}
        </ul>
      </nav>

      {/* IPS Status (visible on network and controls pages) */}
      {(activePage === 'network' || activePage === 'controls') && prevention && (
        <div className="sidebar-controls">
          <div className="sidebar-section-title">IPS Status</div>
          {prevention.enabled ? (
            <div className="sidebar-ips-status">
              <span className="active-dot" /> IPS Active
              {prevention.blocked_ips.length > 0 && (
                <span className="blocked-count">{prevention.blocked_ips.length} blocked</span>
              )}
            </div>
          ) : (
            <div className="sidebar-ips-status" style={{ color: '#6b7280' }}>
              IPS Disabled
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
