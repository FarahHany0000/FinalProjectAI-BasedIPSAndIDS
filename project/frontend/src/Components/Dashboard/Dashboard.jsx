import React, { useState, useEffect, useCallback, useRef, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { LayoutDashboard, Shield, Monitor, Wifi, WifiOff, AlertTriangle } from "lucide-react";

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [agentEvents, setAgentEvents] = useState([]);
  const debounceRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [statsRes, hostsRes, alertsRes, eventsRes] = await Promise.all([
        fetch(`${API_BASE}/api/dashboard/stats`),
        fetch(`${API_BASE}/api/hosts`),
        fetch(`${API_BASE}/api/alerts`),
        fetch(`${API_BASE}/api/agent/alert-events`),
      ]);
      const [statsData, hostsData, alertsData, eventsData] = await Promise.all([
        statsRes.json(), hostsRes.json(), alertsRes.json(), eventsRes.json(),
      ]);
      setStats(statsData);
      setHosts(hostsData);
      setAlerts(alertsData);
      if (Array.isArray(eventsData) && eventsData.length > 0) {
        setAgentEvents(prev => {
          const existing = new Set(prev.map(e => e.time));
          const merged = [...prev];
          for (const evt of eventsData) {
            if (!existing.has(evt.time)) merged.push(evt);
          }
          merged.sort((a, b) => (b.time || "").localeCompare(a.time || ""));
          return merged.slice(0, 50);
        });
      }
    } catch {
      // silent
    }
  }, []);

  const debouncedFetch = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(fetchData, 2000);
  }, [fetchData]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);

    socket.on("host_update", debouncedFetch);
    socket.on("new_alert", (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 100));
      if (alert.source_type === "network") {
        setStats(prev => prev ? { ...prev, network_alerts: (prev.network_alerts || 0) + 1 } : prev);
      }
    });
    socket.on("alert_status", (event) => {
      setAgentEvents(prev => [event, ...prev].slice(0, 50));
    });
    socket.on("prevention_reset", () => {
      setAgentEvents([]);
    });

    return () => {
      clearInterval(interval);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      socket.off("host_update");
      socket.off("new_alert");
      socket.off("alert_status");
      socket.off("prevention_reset");
    };
  }, [fetchData, debouncedFetch]);

  const isOnline = useCallback((lastSeen) => {
    if (!lastSeen) return false;
    return (new Date() - new Date(lastSeen)) / 1000 < 30;
  }, []);

  const onlineHosts = useMemo(() => hosts.filter(h => isOnline(h.last_seen)), [hosts, isOnline]);
  const offlineHosts = useMemo(() => hosts.filter(h => !isOnline(h.last_seen)), [hosts, isOnline]);
  const totalAlerts = stats?.total_alerts || 0;
  const hostAlerts = stats?.host_alerts || 0;
  const networkAlerts = stats?.network_alerts || 0;

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <style>{`
          @keyframes blink {
            0%, 100% { opacity: 1; transform: scale(1); }
            50% { opacity: 0.3; transform: scale(1.15); }
          }
        `}</style>

        <div className="icondesign">
          <div className="icons"><LayoutDashboard size={36} /></div>
          <h1>Dashboard</h1>
        </div>
        <p className="page-description">System overview — real-time monitoring of all connected devices.</p>

        {/* Stats Cards */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className="stat-card">
            <h4><Wifi size={16} style={{ marginRight: 6 }} /> Connected</h4>
            <p className="host-online">{onlineHosts.length}</p>
            <span className="stat-sub">devices online now</span>
          </div>
          <div className="stat-card">
            <h4><WifiOff size={16} style={{ marginRight: 6 }} /> Disconnected</h4>
            <p className="host-offline">{offlineHosts.length}</p>
            <span className="stat-sub">devices offline</span>
          </div>
          <div className="stat-card">
            <h4><Shield size={16} style={{ marginRight: 6 }} /> Host Threats</h4>
            {hostAlerts > 100 ? (
              <div style={{ 
                display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center",
                height: "60px", gap: "4px"
              }}>
                <AlertTriangle 
                  size={36} 
                  style={{ 
                    color: "#ef4444", 
                    animation: "blink 1s ease-in-out infinite",
                    filter: "drop-shadow(0 0 8px rgba(239,68,68,0.5))",
                  }} 
                />
                <span style={{ fontSize: "0.75rem", color: "#ef4444", fontWeight: 700, letterSpacing: "0.5px" }}>{hostAlerts}</span>
              </div>
            ) : (
              <p style={{ color: hostAlerts > 0 ? "#ef4444" : "#22c55e" }}>{hostAlerts}</p>
            )}
            <span className="stat-sub">{hostAlerts > 100 ? "⚠ Critical threat level!" : "from device agents"}</span>
          </div>
          <div className="stat-card">
            <h4><AlertTriangle size={16} style={{ marginRight: 6 }} /> Network Threats</h4>
            {networkAlerts > 100 ? (
              <div style={{ 
                display: "flex", flexDirection: "column", justifyContent: "center", alignItems: "center",
                height: "60px", gap: "4px"
              }}>
                <AlertTriangle 
                  size={36} 
                  style={{ 
                    color: "#ef4444", 
                    animation: "blink 1s ease-in-out infinite",
                    filter: "drop-shadow(0 0 8px rgba(239,68,68,0.5))",
                  }} 
                />
                <span style={{ fontSize: "0.75rem", color: "#ef4444", fontWeight: 700, letterSpacing: "0.5px" }}>{networkAlerts}</span>
              </div>
            ) : (
              <p style={{ color: networkAlerts > 0 ? "#ef4444" : "#22c55e" }}>{networkAlerts}</p>
            )}
            <span className="stat-sub">{networkAlerts > 100 ? "⚠ Critical threat level!" : "from network traffic"}</span>
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

        {/* Agent Alert Events — only visible when events exist */}
        {agentEvents.length > 0 && (
        <div className="panel" style={{ marginBottom: "20px", borderLeft: "3px solid #ef4444" }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "#ef4444", animation: "pulse 1.5s infinite" }}></span>
            Live Agent Events
          </h3>
          <div className="hide-scrollbar" style={{ maxHeight: "160px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px", padding: "6px 0", scrollbarWidth: "none", msOverflowStyle: "none" }}>
              {agentEvents.map((evt, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", gap: "10px",
                  padding: "8px 12px", background: "rgba(15, 23, 42, 0.5)",
                  borderRadius: "6px", fontSize: "12px"
                }}>
                  <span style={{ fontSize: "16px" }}>
                    {evt.event === "dialog_shown" ? "🔒" : evt.event === "password_failed" ? "❌" : evt.event === "password_success" ? "✅" : "🔓"}
                  </span>
                  <strong style={{ color: evt.event === "password_failed" ? "#ef4444" : evt.event === "password_success" ? "#22c55e" : "#f59e0b" }}>
                    {evt.host_name}
                  </strong>
                  <span style={{ color: "#94a3b8" }}>{evt.label}</span>
                  <span style={{ marginLeft: "auto", color: "#475569", fontSize: "11px" }}>
                    {evt.time ? new Date(evt.time).toLocaleTimeString() : ""}
                  </span>
                </div>
              ))}
          </div>
        </div>
        )}

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
