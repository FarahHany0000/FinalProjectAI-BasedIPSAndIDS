import React, { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { ArrowLeft, AlertTriangle, Cpu } from "lucide-react";

export default function DeviceDetail() {
  const { host_name } = useParams();
  const navigate = useNavigate();
  const [detail, setDetail] = useState(null);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);
  const [agentEvents, setAgentEvents] = useState([]);

  const fetchData = useCallback(async () => {
    try {
      const [detailRes, alertsRes, eventsRes] = await Promise.all([
        fetch(`${API_BASE}/api/hosts/${host_name}/detail`),
        fetch(`${API_BASE}/api/alerts?host=${host_name}`),
        fetch(`${API_BASE}/api/agent/alert-events/${host_name}`),
      ]);
      setDetail(await detailRes.json());
      const alertsData = await alertsRes.json();
      setAlerts(Array.isArray(alertsData) ? alertsData : []);
      const eventsData = await eventsRes.json();
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
    } catch (err) {
      console.error("Host detail fetch error:", err);
    } finally {
      setLoading(false);
    }
  }, [host_name]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 15000);
    socket.on("host_update", (data) => {
      if (data.host_name === host_name) fetchData();
    });
    socket.on("alert_status", (event) => {
      if (event.host_name === host_name) {
        setAgentEvents(prev => [event, ...prev].slice(0, 50));
      }
    });
    socket.on("prevention_reset", (data) => {
      if (data.host_name === host_name) {
        setAgentEvents([]);
      }
    });
    return () => {
      clearInterval(interval);
      socket.off("host_update");
      socket.off("alert_status");
      socket.off("prevention_reset");
    };
  }, [host_name, fetchData]);

  if (loading) {
    return (
      <div className="dashboard">
        <Sidebar />
        <div className="main-content">
          <p style={{ textAlign: "center", padding: "60px", color: "#9ca3af" }}>Loading...</p>
        </div>
      </div>
    );
  }

  const host = detail?.host || {};
  const stats = detail?.stats || {};

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "24px" }}>
          <button onClick={() => navigate('/devices')} className="btn-back">
            <ArrowLeft size={20} /> Back
          </button>
          <div className="icondesign">
            <div className="icons"><Cpu size={36} /></div>
            <h1>{host_name}</h1>
          </div>
          <span className={`status-badge ${host.status === "Online" ? "online" : "offline"}`} style={{ marginLeft: "auto" }}>
            {host.status === "Online" ? "● Online" : "○ Offline"}
          </span>
        </div>

        {/* Device Info */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className="stat-card">
            <h4>IP Address</h4>
            <p style={{ fontSize: "0.95rem" }}>{host.ip || "N/A"}</p>
          </div>
          <div className="stat-card">
            <h4>Operating System</h4>
            <p style={{ fontSize: "0.95rem" }}>{host.os_info || "N/A"}</p>
          </div>
          <div className="stat-card">
            <h4>Total Alerts</h4>
            <p style={{ color: (stats.total_alerts || 0) > 0 ? "#ef4444" : "#22c55e" }}>{stats.total_alerts || 0}</p>
          </div>
          <div className="stat-card">
            <h4>Last Seen</h4>
            <p style={{ fontSize: "0.85rem" }}>{host.last_seen ? new Date(host.last_seen).toLocaleTimeString() : "N/A"}</p>
          </div>
        </div>

        {/* Live Agent Events — always visible */}
        <div className="panel" style={{ marginBottom: "20px", borderLeft: "3px solid #ef4444" }}>
          <h3 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <span style={{ display: "inline-block", width: "8px", height: "8px", borderRadius: "50%", background: agentEvents.length > 0 ? "#ef4444" : "#475569", animation: agentEvents.length > 0 ? "pulse 1.5s infinite" : "none" }}></span>
            Live Agent Events
            {agentEvents.length > 0 && <span style={{ fontSize: "12px", color: "#94a3b8", fontWeight: 400 }}>({agentEvents.length})</span>}
          </h3>
          {agentEvents.length > 0 ? (
            <div className="hide-scrollbar" style={{ maxHeight: "180px", overflowY: "auto", display: "flex", flexDirection: "column", gap: "4px", padding: "6px 0" }}>
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
          ) : (
            <p style={{ color: "#475569", fontSize: "12px", padding: "12px 0" }}>No events yet — events will appear here when the agent detects threats.</p>
          )}
        </div>

        {/* Alert History */}
        <div className="panel">
          <h3><AlertTriangle size={18} /> Alert History ({alerts.length})</h3>
          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Prediction</th>
                  <th>Probability</th>
                  <th>Details</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length > 0 ? alerts.slice(0, 50).map((alert, i) => (
                  <tr key={i}>
                    <td>{alert.time ? new Date(alert.time).toLocaleString() : "N/A"}</td>
                    <td>
                      <span className={`status-badge ${alert.threat && alert.threat !== "Normal" && alert.threat !== "Benign" ? "malicious" : "benign"}`}>
                        {alert.threat || "Normal"}
                      </span>
                    </td>
                    <td>{alert.confidence != null ? (alert.confidence * 100).toFixed(1) + "%" : "N/A"}</td>
                    <td style={{ maxWidth: "300px", overflow: "hidden", textOverflow: "ellipsis" }}>
                      {alert.details || "—"}
                    </td>
                  </tr>
                )) : (
                  <tr><td colSpan="4" className="empty-logs">No alerts for this device</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
