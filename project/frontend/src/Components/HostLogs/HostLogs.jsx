import React, { useEffect, useState, useCallback } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { ArrowLeft, Activity, Shield, AlertTriangle, Cpu, BarChart3, Clock } from "lucide-react";

const FEATURE_LABELS = {
  cpu_percent: "CPU Usage %",
  memory_percent: "Memory Usage %",
  disk_read_bytes: "Disk Read (bytes)",
  disk_write_bytes: "Disk Write (bytes)",
  net_bytes_sent: "Net Bytes Sent",
  net_bytes_recv: "Net Bytes Recv",
  num_processes: "Running Processes",
  num_connections: "Network Connections",
  failed_logins: "Failed Logins",
  num_users: "Logged-in Users",
  privilege_escalation_attempts: "Privilege Escalations",
  unusual_process_count: "Unusual Processes",
  file_access_anomaly_score: "File Access Anomaly",
  registry_modification_count: "Registry Modifications",
  is_after_hours: "After Hours Activity",
};

function RiskGauge({ probability }) {
  const pct = Math.round((probability || 0) * 100);
  const angle = (pct / 100) * 180;
  const color = pct < 30 ? "#22c55e" : pct < 60 ? "#f97316" : "#ef4444";
  const level = pct < 30 ? "LOW" : pct < 60 ? "MEDIUM" : pct < 85 ? "HIGH" : "CRITICAL";

  return (
    <div className="risk-gauge-container">
      <svg viewBox="0 0 200 120" className="risk-gauge-svg">
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke="#1e293b" strokeWidth="16" strokeLinecap="round" />
        <path d="M 20 100 A 80 80 0 0 1 180 100" fill="none" stroke={color} strokeWidth="16" strokeLinecap="round"
          strokeDasharray={`${(angle / 180) * 251.2} 251.2`} />
        <text x="100" y="85" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold">{pct}%</text>
        <text x="100" y="110" textAnchor="middle" fill="#9ca3af" fontSize="12">{level}</text>
      </svg>
      <p className="risk-gauge-label">Current Threat Probability</p>
    </div>
  );
}

function ModelCompare({ xgb, rf }) {
  const xPct = Math.round((xgb?.probability || 0) * 100);
  const rPct = Math.round((rf?.probability || 0) * 100);
  const xColor = xPct < 30 ? "#22c55e" : xPct < 60 ? "#f97316" : "#ef4444";
  const rColor = rPct < 30 ? "#22c55e" : rPct < 60 ? "#f97316" : "#ef4444";

  return (
    <div className="model-compare">
      <div className="model-compare-row">
        <span className="model-name">XGBoost</span>
        <div className="model-bar-bg">
          <div className="model-bar-fill" style={{ width: `${xPct}%`, backgroundColor: xColor }} />
        </div>
        <span className="model-pct">{xPct}%</span>
        <span className={`model-verdict ${xgb?.prediction === "Malicious" ? "malicious" : "benign"}`}>
          {xgb?.prediction || "N/A"}
        </span>
      </div>
      <div className="model-compare-row">
        <span className="model-name">RandomForest</span>
        <div className="model-bar-bg">
          <div className="model-bar-fill" style={{ width: `${rPct}%`, backgroundColor: rColor }} />
        </div>
        <span className="model-pct">{rPct}%</span>
        <span className={`model-verdict ${rf?.prediction === "Malicious" ? "malicious" : "benign"}`}>
          {rf?.prediction || "N/A"}
        </span>
      </div>
    </div>
  );
}

function RiskTimeline({ data }) {
  if (!data || data.length === 0) {
    return <p style={{ color: "#6b7280", textAlign: "center", padding: "20px" }}>No prediction history yet</p>;
  }

  const maxProb = Math.max(...data.map(d => d.probability || 0), 0.01);
  const chartH = 160;
  const chartW = 100; // percentage width

  return (
    <div className="risk-timeline">
      <div className="risk-timeline-chart" style={{ height: `${chartH}px` }}>
        {/* Y-axis labels */}
        <div className="timeline-y-axis">
          <span>100%</span>
          <span>50%</span>
          <span>0%</span>
        </div>
        {/* Bars */}
        <div className="timeline-bars">
          {data.slice(-40).map((d, i) => {
            const pct = Math.round((d.probability || 0) * 100);
            const h = (pct / 100) * chartH;
            const color = pct < 30 ? "#22c55e" : pct < 60 ? "#f97316" : "#ef4444";
            const time = d.timestamp ? new Date(d.timestamp).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "";
            return (
              <div key={i} className="timeline-bar-wrapper" title={`${time}: ${pct}%`}>
                <div className="timeline-bar" style={{ height: `${h}px`, backgroundColor: color }} />
              </div>
            );
          })}
        </div>
      </div>
      <p className="timeline-label">Last {data.length} predictions • Updated in real-time</p>
    </div>
  );
}

export default function HostLogs() {
  const { host_name } = useParams();
  const navigate = useNavigate();
  const [detail, setDetail] = useState(null);
  const [timeline, setTimeline] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchData = useCallback(async () => {
    try {
      const [detailRes, timelineRes, alertsRes] = await Promise.all([
        fetch(`${API_BASE}/api/hosts/${host_name}/detail`),
        fetch(`${API_BASE}/api/hosts/${host_name}/predictions?minutes=30`),
        fetch(`${API_BASE}/api/alerts?host=${host_name}`),
      ]);
      const detailData = await detailRes.json();
      const timelineData = await timelineRes.json();
      const alertsData = await alertsRes.json();

      setDetail(detailData);
      setTimeline(Array.isArray(timelineData) ? timelineData : []);
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
      if (data.host_name === host_name) {
        fetchData();
      }
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
          <p style={{ textAlign: "center", padding: "60px", color: "#9ca3af", fontSize: "1.1rem" }}>Loading host details...</p>
        </div>
      </div>
    );
  }

  const host = detail?.host || {};
  const latest = detail?.latest_prediction || {};
  const stats = detail?.stats || {};
  const features = latest?.features || {};
  const modelsData = latest?.models_data || {};

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "24px" }}>
          <button onClick={() => navigate(-1)} className="btn-back">
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

        {/* Host Info Bar */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(5, 1fr)" }}>
          <div className="stat-card">
            <h4>IP Address</h4>
            <p style={{ fontSize: "0.95rem" }}>{host.ip || "N/A"}</p>
          </div>
          <div className="stat-card">
            <h4>OS</h4>
            <p style={{ fontSize: "0.95rem" }}>{host.os_info || "N/A"}</p>
          </div>
          <div className="stat-card">
            <h4>Total Alerts</h4>
            <p style={{ color: "#ef4444" }}>{stats.total_alerts || 0}</p>
          </div>
          <div className="stat-card">
            <h4>Malicious</h4>
            <p style={{ color: "#ef4444" }}>{stats.malicious_count || 0}</p>
          </div>
          <div className="stat-card">
            <h4>Last Seen</h4>
            <p style={{ fontSize: "0.85rem" }}>{host.last_seen ? new Date(host.last_seen).toLocaleTimeString() : "N/A"}</p>
          </div>
        </div>

        {/* Risk Gauge + Model Comparison */}
        <div className="host-detail-grid">
          <div className="panel">
            <h3><Activity size={18} /> Risk Assessment</h3>
            <RiskGauge probability={latest?.probability} />
          </div>
          <div className="panel">
            <h3><BarChart3 size={18} /> Model Comparison</h3>
            <ModelCompare
              xgb={{ prediction: modelsData.xgb_prediction, probability: modelsData.xgb_probability }}
              rf={{ prediction: modelsData.rf_prediction, probability: modelsData.rf_probability }}
            />
            {latest?.prevention_level && (
              <div className="prevention-level-badge" style={{
                marginTop: "16px",
                padding: "8px 16px",
                backgroundColor: latest.prevention_level === "CRITICAL" ? "rgba(239,68,68,0.2)" :
                  latest.prevention_level === "MEDIUM" ? "rgba(249,115,22,0.2)" : "rgba(34,197,94,0.2)",
                borderRadius: "8px",
                textAlign: "center",
                fontWeight: "bold",
                color: latest.prevention_level === "CRITICAL" ? "#ef4444" :
                  latest.prevention_level === "MEDIUM" ? "#f97316" : "#22c55e",
              }}>
                Prevention Level: {latest.prevention_level}
                {latest.prevention_action && ` — ${latest.prevention_action}`}
              </div>
            )}
          </div>
        </div>

        {/* Risk Timeline */}
        <div className="panel">
          <h3><Clock size={18} /> Risk Timeline (Last 30 min)</h3>
          <RiskTimeline data={timeline} />
        </div>

        {/* Feature Breakdown */}
        <div className="panel">
          <h3><Shield size={18} /> Feature Breakdown ({Object.keys(features).length} features)</h3>
          <div className="features-grid">
            {Object.entries(FEATURE_LABELS).map(([key, label]) => {
              const val = features[key];
              const numVal = typeof val === "number" ? val : parseFloat(val) || 0;
              const isHigh = key.includes("percent") && numVal > 80;
              const isAnomaly = (key === "failed_logins" && numVal > 0) ||
                (key === "privilege_escalation_attempts" && numVal > 0) ||
                (key === "file_access_anomaly_score" && numVal > 0.5);
              return (
                <div key={key} className={`feature-card ${isHigh || isAnomaly ? "feature-alert" : ""}`}>
                  <span className="feature-label">{label}</span>
                  <span className="feature-value">
                    {typeof val === "number" ? (val > 1000000 ? (val / 1048576).toFixed(1) + " MB" : val.toFixed(2)) : val ?? "N/A"}
                  </span>
                </div>
              );
            })}
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
                  <tr><td colSpan="4" className="empty-logs">No alerts for this host</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
