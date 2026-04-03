import React, { useMemo, useState, useEffect } from "react";
import Sidebar from "../Sidebar/Sidebar";
import { useNavigate } from "react-router-dom";
import API_BASE from "../../config";
import socket from "../../socket";

export default function Dashboard() {
  const navigate = useNavigate();
  const [stats, setStats] = useState(null);
  const [hosts, setHosts] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [preventionNotice, setPreventionNotice] = useState(null);
  const [preventionEvents, setPreventionEvents] = useState([]);
  const [preventionLogs, setPreventionLogs] = useState([]);
  const [thresholds, setThresholds] = useState({ low: "0.50", medium: "0.70", critical: "0.90" });
  const [thresholdStatus, setThresholdStatus] = useState("");
  const [thresholdError, setThresholdError] = useState("");
  const [activeTab, setActiveTab] = useState("overview");

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

      const logsRes = await fetch(`${API_BASE}/api/prevention/logs?limit=20`);
      if (logsRes.ok) {
        setPreventionLogs(await logsRes.json());
      }
    } catch (err) {
      console.error("Dashboard fetch error:", err);
    }
  };

  const fetchThresholds = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/prevention/thresholds`);
      if (!res.ok) {
        setThresholdError("Threshold API is not available on current backend.");
        return;
      }
      const data = await res.json();
      setThresholds({
        low: Number(data.low ?? 0.5).toFixed(2),
        medium: Number(data.medium ?? 0.7).toFixed(2),
        critical: Number(data.critical ?? 0.9).toFixed(2),
      });
      setThresholdError("");
    } catch (err) {
      setThresholdError("Cannot load thresholds from backend.");
      console.error("Threshold fetch error:", err);
    }
  };

  const saveThresholds = async () => {
    setThresholdStatus("");
    setThresholdError("");
    const payload = {
      low: Number(thresholds.low),
      medium: Number(thresholds.medium),
      critical: Number(thresholds.critical),
    };

    if (!(payload.low >= 0 && payload.low < payload.medium && payload.medium < payload.critical && payload.critical <= 1)) {
      setThresholdError("Invalid thresholds: must satisfy 0 <= low < medium < critical <= 1.");
      return;
    }

    try {
      const res = await fetch(`${API_BASE}/api/prevention/thresholds`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
      });
      const data = await res.json();
      if (!res.ok) {
        setThresholdError(data.error || "Failed to update thresholds.");
        return;
      }
      const updated = data.thresholds || payload;
      setThresholds({
        low: Number(updated.low).toFixed(2),
        medium: Number(updated.medium).toFixed(2),
        critical: Number(updated.critical).toFixed(2),
      });
      setThresholdStatus("Thresholds updated.");
    } catch (err) {
      setThresholdError("Cannot update thresholds.");
      console.error("Threshold update error:", err);
    }
  };

  useEffect(() => {
    fetchData();
    fetchThresholds();
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

    socket.on("prevention_action", (event) => {
      setPreventionEvents(prev => [event, ...prev].slice(0, 20));
      if (event?.popup) {
        setPreventionNotice(event.popup);
      }
    });

    return () => {
      clearInterval(interval);
      socket.off("host_update");
      socket.off("new_alert");
      socket.off("prevention_action");
    };
  }, []);

  const hostRiskLookup = useMemo(() => {
    const map = new Map();
    preventionEvents.forEach((event) => {
      const key = `${event.host_name}|${event.ip || ""}`;
      if (!map.has(key)) {
        map.set(key, event);
      }
    });
    return map;
  }, [preventionEvents]);

  const normalizedHosts = useMemo(() => {
    const map = new Map();
    hosts.forEach((host) => {
      const key = `${host.host_name}|${host.ip || ""}`;
      const prev = map.get(key);
      const prevTs = prev?.last_seen ? new Date(prev.last_seen).getTime() : 0;
      const curTs = host?.last_seen ? new Date(host.last_seen).getTime() : 0;
      if (!prev || curTs >= prevTs) {
        map.set(key, host);
      }
    });

    return Array.from(map.values()).sort((a, b) => {
      const aTs = a?.last_seen ? new Date(a.last_seen).getTime() : 0;
      const bTs = b?.last_seen ? new Date(b.last_seen).getTime() : 0;
      return bTs - aTs;
    });
  }, [hosts]);

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

        {preventionNotice && (
          <div className="prevention-popup" role="alert">
            <div className="prevention-popup-header">
              <strong>{preventionNotice.title}</strong>
              <button
                className="prevention-popup-close"
                onClick={() => setPreventionNotice(null)}
                aria-label="Close prevention alert"
              >
                ✕
              </button>
            </div>
            <p>{preventionNotice.message}</p>
          </div>
        )}

        <div className="tab-bar">
          <button
            className={`tab-btn ${activeTab === "overview" ? "active" : ""}`}
            onClick={() => setActiveTab("overview")}
          >
            Overview
          </button>
          <button
            className={`tab-btn ${activeTab === "prevention" ? "active" : ""}`}
            onClick={() => setActiveTab("prevention")}
          >
            Prevention Settings
          </button>
          <button
            className={`tab-btn ${activeTab === "ai" ? "active" : ""}`}
            onClick={() => setActiveTab("ai")}
          >
            AI Decisions
          </button>
        </div>

        {activeTab === "overview" && (
          <>
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

            <div className="panel">
              <h3>Hosts Overview</h3>
              <table className="hosts-table">
                <thead>
                  <tr>
                    <th>Host Name</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Last Seen</th>
                    <th>Last Risk</th>
                    <th>Action</th>
                    <th>Details</th>
                  </tr>
                </thead>
                <tbody>
                  {normalizedHosts.length > 0 ? normalizedHosts.map((host, idx) => {
                    const risk = hostRiskLookup.get(`${host.host_name}|${host.ip || ""}`);
                    return (
                      <tr key={idx} className={host.action && host.action !== "No Action" ? "attack-row" : ""}>
                        <td><strong>{host.host_name}</strong></td>
                        <td>{host.ip}</td>
                        <td>
                          <span className={`status-badge ${host.status === "Online" ? "online" : "offline"}`}>
                            {host.status === "Online" ? "● Online" : "○ Offline"}
                          </span>
                        </td>
                        <td>{host.last_seen ? new Date(host.last_seen).toLocaleTimeString() : "N/A"}</td>
                        <td>{typeof risk?.probability === "number" ? `${(risk.probability * 100).toFixed(1)}%` : "N/A"}</td>
                        <td>
                          <span
                            className={host.action && host.action !== "No Action" ? "action-pill danger" : "action-pill safe"}
                            title={host.action || "No Action"}
                          >
                            {host.action && host.action !== "No Action" ? host.action : "Secure"}
                          </span>
                        </td>
                        <td>
                          <button className="view-logs-btn" onClick={() => navigate(`/host/${host.host_name}`)}>
                            View Logs
                          </button>
                        </td>
                      </tr>
                    );
                  }) : (
                    <tr><td colSpan="7" className="empty-logs">No hosts detected yet. Start the host agent to begin monitoring.</td></tr>
                  )}
                </tbody>
              </table>
            </div>

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

            <div className="panel" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
              <span style={{ fontSize: "1.2rem" }}>
                {stats?.model_loaded ? "🟢" : "🔴"}
              </span>
              <span>
                AI Model: <strong>{stats?.model_loaded ? "XGBoost — Loaded & Active" : "Not Loaded"}</strong>
              </span>
            </div>
          </>
        )}

        {activeTab === "prevention" && (
          <>
            <div className="panel">
              <h3>Prevention Threshold Controls</h3>
              <div className="threshold-controls">
                <label>
                  Low
                  <input
                    type="number"
                    min="0"
                    max="1"
                    step="0.01"
                    value={thresholds.low}
                    onChange={(e) => setThresholds(prev => ({ ...prev, low: e.target.value }))}
                  />
                </label>
                <label>
                  Medium
                  <input
                    type="number"
                    min="0"
                    max="1"
                    step="0.01"
                    value={thresholds.medium}
                    onChange={(e) => setThresholds(prev => ({ ...prev, medium: e.target.value }))}
                  />
                </label>
                <label>
                  Critical
                  <input
                    type="number"
                    min="0"
                    max="1"
                    step="0.01"
                    value={thresholds.critical}
                    onChange={(e) => setThresholds(prev => ({ ...prev, critical: e.target.value }))}
                  />
                </label>
                <button className="view-logs-btn" onClick={saveThresholds}>Apply</button>
              </div>
              {thresholdError && <p className="error">{thresholdError}</p>}
              {thresholdStatus && <p className="success-text">{thresholdStatus}</p>}
            </div>

            <div className="panel">
              <h3>Recent Prevention Actions</h3>
              <table>
                <thead>
                  <tr>
                    <th>Host Name</th>
                    <th>Activity</th>
                    <th>Level</th>
                    <th>Action</th>
                    <th>Probability</th>
                  </tr>
                </thead>
                <tbody>
                  {preventionEvents.length > 0 ? preventionEvents.map((event, idx) => (
                    <tr key={idx}>
                      <td>{event.host_name || "N/A"}</td>
                      <td>{event.activity_type || "N/A"}</td>
                      <td>{event.level || "N/A"}</td>
                      <td>{event.action || "N/A"}</td>
                      <td>{typeof event.probability === "number" ? `${(event.probability * 100).toFixed(1)}%` : "N/A"}</td>
                    </tr>
                  )) : (
                    <tr><td colSpan="5" className="empty-logs">No prevention actions yet.</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </>
        )}

        {activeTab === "ai" && (
          <div className="panel">
            <h3>AI Decision Feed (Probability)</h3>
            <table>
              <thead>
                <tr>
                  <th>Time</th>
                  <th>Host</th>
                  <th>Prediction</th>
                  <th>Probability</th>
                  <th>Level</th>
                </tr>
              </thead>
              <tbody>
                {preventionLogs.length > 0 ? preventionLogs.map((item, idx) => (
                  <tr key={idx}>
                    <td>{item.time ? new Date(item.time).toLocaleTimeString() : "N/A"}</td>
                    <td>{item.host_name || "N/A"}</td>
                    <td>{item.prediction || "N/A"}</td>
                    <td>{typeof item.probability === "number" ? `${(item.probability * 100).toFixed(1)}%` : "N/A"}</td>
                    <td>{item.level || "NONE"}</td>
                  </tr>
                )) : (
                  <tr><td colSpan="5" className="empty-logs">No AI decision records yet.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        )}

      </div>
    </div>
  );
}
