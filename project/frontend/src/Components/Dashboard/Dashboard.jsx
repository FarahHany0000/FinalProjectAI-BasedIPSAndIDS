import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { LayoutDashboard, Shield, Monitor } from "lucide-react";

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
    const interval = setInterval(fetchData, 15000);

    socket.on("host_update", fetchData);
    socket.on("new_alert", (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 50));
      fetchData();
    });

    return () => {
      clearInterval(interval);
      socket.off("host_update");
      socket.off("new_alert");
    };
  }, []);

  const isOnline = (lastSeen) => {
    if (!lastSeen) return false;
    return (new Date() - new Date(lastSeen)) / 1000 < 30;
  };

  const onlineHosts = hosts.filter(h => isOnline(h.last_seen));
  const totalAlerts = stats?.total_alerts || 0;

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons"><LayoutDashboard size={36} /></div>
          <h1>Dashboard</h1>
        </div>
        <p className="page-description">System overview — real-time monitoring of all connected devices.</p>

        {/* Stats Cards */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(2, 1fr)" }}>
          <div className="stat-card">
            <h4><Monitor size={16} style={{ marginRight: 6 }} /> Connected Devices</h4>
            <p className="host-online">{onlineHosts.length}</p>
            <span className="stat-sub">of {hosts.length} total • {hosts.length - onlineHosts.length} disconnected</span>
          </div>
          <div className="stat-card">
            <h4><Shield size={16} style={{ marginRight: 6 }} /> Threats Detected</h4>
            <p style={{ color: totalAlerts > 0 ? "#ef4444" : "#22c55e" }}>
              {totalAlerts}
            </p>
            <span className="stat-sub">{totalAlerts === 0 ? "All clear" : "Review needed"}</span>
          </div>
        </div>

        {/* Active Devices */}
        <div className="panel">
          <h3><Monitor size={18} /> Active Devices</h3>
          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th>Device Name</th>
                  <th>IP Address</th>
                  <th>Connection</th>
                  <th>Last Seen</th>
                  <th>Threat Status</th>
                </tr>
              </thead>
              <tbody>
                {hosts.length > 0 ? hosts.map((h, i) => {
                  const online = isOnline(h.last_seen);
                  const isThreat = h.last_prediction && h.last_prediction !== "Normal" && h.last_prediction !== "Benign";
                  return (
                    <tr key={i}
                      className={`${isThreat ? "attack-row" : ""} ${!online ? "offline-row" : ""}`}
                      style={{ cursor: "pointer" }}
                      onClick={() => navigate(`/device/${h.host_name}`)}
                    >
                      <td><strong>{h.host_name}</strong></td>
                      <td>{h.ip || "N/A"}</td>
                      <td>
                        <span className={`status-badge ${online ? "online" : "offline"}`}>
                          {online ? "● Connected" : "○ Disconnected"}
                        </span>
                      </td>
                      <td>{h.last_seen ? new Date(h.last_seen).toLocaleTimeString() : "N/A"}</td>
                      <td>
                        {isThreat ? (
                          <span className="status-badge malicious">⚠ {h.last_prediction}</span>
                        ) : (
                          <span className="status-badge benign">✓ Secure</span>
                        )}
                      </td>
                    </tr>
                  );
                }) : (
                  <tr><td colSpan="5" className="empty-logs">No devices connected yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Recent Activity */}
        <div className="panel">
          <h3><Shield size={18} /> Recent Alerts</h3>
          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th>Device</th>
                  <th>Threat</th>
                  <th>Action Taken</th>
                  <th>Time</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length > 0 ? alerts.slice(0, 10).map((a, i) => (
                  <tr key={i} style={{ cursor: "pointer" }} onClick={() => navigate(`/device/${a.host_name}`)}>
                    <td><strong>{a.host_name}</strong></td>
                    <td style={{ color: "#ef4444", fontWeight: "bold" }}>{a.threat || a.prediction || "Unknown"}</td>
                    <td style={{ color: "#f97316" }}>{a.action || "Logged"}</td>
                    <td>{a.time ? new Date(a.time).toLocaleString() : a.timestamp ? new Date(a.timestamp).toLocaleString() : "N/A"}</td>
                  </tr>
                )) : (
                  <tr><td colSpan="4" className="empty-logs">No alerts — system is secure.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
