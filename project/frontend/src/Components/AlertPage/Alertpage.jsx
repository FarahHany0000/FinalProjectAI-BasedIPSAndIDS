import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";

export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [agentEvents, setAgentEvents] = useState([]);

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts`);
      const data = await res.json();
      setAlerts(data);
    } catch (err) {
      console.error("Alerts fetch error:", err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 5000);

    socket.on("new_alert", (alert) => {
      setAlerts(prev => [alert, ...prev].slice(0, 100));
    });

    socket.on("alert_status", (event) => {
      setAgentEvents(prev => [event, ...prev].slice(0, 50));
    });

    return () => {
      clearInterval(interval);
      socket.off("new_alert");
      socket.off("alert_status");
    };
  }, []);

  const getEventIcon = (event) => {
    switch (event) {
      case "dialog_shown": return "🔒";
      case "password_failed": return "❌";
      case "password_success": return "✅";
      case "dialog_dismissed": return "🔓";
      default: return "ℹ️";
    }
  };

  const getEventColor = (event) => {
    switch (event) {
      case "dialog_shown": return "#f59e0b";
      case "password_failed": return "#ef4444";
      case "password_success": return "#22c55e";
      case "dialog_dismissed": return "#3b82f6";
      default: return "#94a3b8";
    }
  };

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="currentColor" viewBox="0 0 16 16">
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>
          <h1>Alerts</h1>
        </div>

        {/* Stats */}
        <div className="alerts-stats">
          <div className="stat-card">
            <h4>Total Alerts</h4>
            <h2>{alerts.length}</h2>
          </div>
          <div className="stat-card">
            <h4>Agent Events</h4>
            <h2>{agentEvents.length}</h2>
          </div>
        </div>

        {/* Live Agent Events — real-time alert dialog status */}
        {agentEvents.length > 0 && (
          <div className="panel" style={{ marginBottom: "20px" }}>
            <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
              <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: "#ef4444", animation: "pulse 1.5s infinite" }}></span>
              Live Agent Events
            </h3>
            <div style={{
              maxHeight: "220px", overflowY: "auto",
              display: "flex", flexDirection: "column", gap: "6px",
              padding: "8px 0"
            }}>
              {agentEvents.map((evt, i) => (
                <div key={i} style={{
                  display: "flex", alignItems: "center", gap: "12px",
                  padding: "10px 14px",
                  background: "rgba(15, 23, 42, 0.6)",
                  borderRadius: "8px",
                  borderLeft: `3px solid ${getEventColor(evt.event)}`,
                  fontSize: "13px"
                }}>
                  <span style={{ fontSize: "18px" }}>{getEventIcon(evt.event)}</span>
                  <div style={{ flex: 1 }}>
                    <strong style={{ color: getEventColor(evt.event) }}>{evt.host_name}</strong>
                    <span style={{ color: "#94a3b8", marginLeft: "8px" }}>{evt.label}</span>
                  </div>
                  <span style={{ color: "#475569", fontSize: "11px", whiteSpace: "nowrap" }}>
                    {evt.time ? new Date(evt.time).toLocaleTimeString() : ""}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Alerts Table */}
        <div className="panel">
          <h3>Live Alerts</h3>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Host</th>
                <th>Threat</th>
                <th>Action Taken</th>
                <th>Time</th>
                <th>Details</th>
              </tr>
            </thead>
            <tbody>
              {alerts.length > 0 ? alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>ALT-{String(alert.id).padStart(4, '0')}</td>
                  <td>{alert.host_name}</td>
                  <td style={{ color: "#ef4444", fontWeight: "bold" }}>{alert.threat}</td>
                  <td style={{ color: "#f97316", fontWeight: "bold" }}>{alert.action}</td>
                  <td>{alert.time ? new Date(alert.time).toLocaleString() : "N/A"}</td>
                  <td>
                    <button className="view-logs-btn" onClick={() => navigate(`/host/${alert.host_name}`)}>
                      View
                    </button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="6" className="empty-logs">No alerts detected. System is secure.</td></tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
}
