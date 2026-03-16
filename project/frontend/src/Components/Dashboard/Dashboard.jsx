import React, { useState, useEffect } from "react";
import Sidebar from "../Sidebar/Sidebar";
import { useNavigate } from "react-router-dom";
import API_BASE from "../../config";
import socket from "../../socket";

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [alerts, setAlerts] = useState([]);

  const fetchData = async () => {
    try {
      const [statsRes, hostsRes, alertsRes] = await Promise.all([
        fetch(`${API_BASE}/api/dashboard/stats`),
        fetch(`${API_BASE}/api/hosts`),
        fetch(`${API_BASE}/api/alerts`),
      ]);
      setStats(await statsRes.json());
      setHosts(await hostsRes.json());
      setAlerts(await alertsRes.json());
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 5000);

    socket.on("host_update", (host) => {
      setHosts(prev => {
        const idx = prev.findIndex(h => h.agent_id === host.agent_id);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = host;
          return updated;
        }
        return [...prev, host];
      });
    });

    socket.on("new_alert", (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 100));
      // Refresh stats on new alert
      fetch(`${API_BASE}/api/dashboard/stats`).then(r => r.json()).then(setStats).catch(() => {});
    });

    return () => {
      clearInterval(interval);
      socket.off("host_update");
      socket.off("new_alert");
    };
  }, []);

  return (
    <div className="dashboard-container">
      <Sidebar />
      <div className="dashboard-content">

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="currentColor" viewBox="0 0 16 16">
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>
          <h1>Dashboard</h1>
        </div>

        {/* Stats Cards */}
        <div className="stats-grid">
          <div className="stat-card">
            <h4>Total Hosts</h4>
            <p>{stats?.total_hosts ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Online Hosts</h4>
            <p className="host-online">{stats?.online_hosts ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Offline Hosts</h4>
            <p className="host-offline">{stats?.offline_hosts ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Total Alerts</h4>
            <p className="severity-high">{stats?.total_alerts ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Alerts (1h)</h4>
            <p className="severity-medium">{stats?.recent_alerts_1h ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Registered Agents</h4>
            <p>{stats?.registered_agents ?? 0}</p>
          </div>
          <div className="stat-card">
            <h4>Online Agents</h4>
            <p className="host-online">{stats?.online_agents ?? 0}</p>
          </div>
        </div>

        {/* Hosts Table */}
        <div className="panel">
          <h3>Hosts Overview</h3>
          <table>
            <thead>
              <tr>
                <th>Host Name</th>
                <th>IP Address</th>
                <th>Status</th>
                <th>Last Seen</th>
                <th>Action</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {hosts.length > 0 ? hosts.map((host, idx) => (
                <tr key={idx} className={host.action && host.action !== "No Action" ? "attack-row" : ""}>
                  <td><strong>{host.host_name}</strong></td>
                  <td>{host.ip}</td>
                  <td>
                    <span className={`status-badge ${host.status === "Online" ? "online" : "offline"}`}>
                      {host.status === "Online" ? "● Online" : "○ Offline"}
                    </span>
                  </td>
                  <td>{host.last_seen ? new Date(host.last_seen).toLocaleTimeString() : "N/A"}</td>
                  <td>
                    <span className={host.action && host.action !== "No Action" ? "prevention-active" : "prevention-none"}>
                      {host.action && host.action !== "No Action" ? host.action : "Secure"}
                    </span>
                  </td>
                  <td>
                    <button className="view-logs-btn" onClick={() => navigate(`/host/${host.host_name}`)}>
                      View Logs
                    </button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="6" className="empty-logs">No hosts detected yet. Start the host agent to begin monitoring.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Recent Alerts Table — no severity column */}
        <div className="panel">
          <h3>Recent Alerts</h3>
          <table>
            <thead>
              <tr>
                <th>Host Name</th>
                <th>Threat</th>
                <th>Action Taken</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length > 0 ? alerts.slice(0, 10).map((alert, idx) => (
                <tr key={idx}>
                  <td>{alert.host_name}</td>
                  <td style={{ color: "#ef4444", fontWeight: "bold" }}>{alert.threat}</td>
                  <td style={{ color: "#f97316", fontWeight: "bold" }}>{alert.action}</td>
                  <td>{alert.time ? new Date(alert.time).toLocaleString() : "N/A"}</td>
                </tr>
              )) : (
                <tr><td colSpan="4" className="empty-logs">No alerts detected. System is secure.</td></tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Model Status */}
        <div className="panel" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "1.2rem" }}>
            {stats?.model_loaded ? "🟢" : "🔴"}
          </span>
          <span>
            AI Model: <strong>{stats?.model_loaded ? "XGBoost — Loaded & Active" : "Not Loaded"}</strong>
          </span>
        </div>

      </div>
    </div>
  );
}
