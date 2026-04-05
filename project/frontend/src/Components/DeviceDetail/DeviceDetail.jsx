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

  const fetchData = useCallback(async () => {
    try {
      const [detailRes, alertsRes] = await Promise.all([
        fetch(`${API_BASE}/api/hosts/${host_name}/detail`),
        fetch(`${API_BASE}/api/alerts?host=${host_name}`),
      ]);
      setDetail(await detailRes.json());
      const alertsData = await alertsRes.json();
      setAlerts(Array.isArray(alertsData) ? alertsData : []);
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
    return () => {
      clearInterval(interval);
      socket.off("host_update");
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
