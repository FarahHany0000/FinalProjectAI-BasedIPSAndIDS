import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";

export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ total: 0, critical: 0, high: 0, medium: 0, low: 0 });

  const fetchAlerts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts`);
      const data = await res.json();
      setAlerts(data);

      setStats({
        total: data.length,
        critical: data.filter(a => a.severity === "Critical").length,
        high: data.filter(a => a.severity === "High").length,
        medium: data.filter(a => a.severity === "Medium").length,
        low: data.filter(a => a.severity === "Low").length,
      });
    } catch (err) {
      console.error("Alerts fetch error:", err);
    }
  };

  useEffect(() => {
    fetchAlerts();
    const interval = setInterval(fetchAlerts, 3000);
    return () => clearInterval(interval);
  }, []);

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical": return "critical";
      case "High": return "high";
      case "Medium": return "medium";
      default: return "low";
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
            <h2>{stats.total}</h2>
          </div>
          <div className="stat-card critical">
            <h4>Critical</h4>
            <h2>{stats.critical}</h2>
          </div>
          <div className="stat-card high">
            <h4>High</h4>
            <h2>{stats.high}</h2>
          </div>
          <div className="stat-card medium">
            <h4>Medium</h4>
            <h2>{stats.medium}</h2>
          </div>
          <div className="stat-card low">
            <h4>Low</h4>
            <h2>{stats.low}</h2>
          </div>
        </div>

        {/* Alerts Table */}
        <div className="panel">
          <h3>Live Alerts</h3>
          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Host</th>
                <th>Threat</th>
                <th>Severity</th>
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
                  <td>{alert.threat}</td>
                  <td>
                    <span className={`badge ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>
                  <td style={{ color: "#ef4444", fontWeight: "bold" }}>{alert.action}</td>
                  <td>{alert.time ? new Date(alert.time).toLocaleString() : "N/A"}</td>
                  <td>
                    <button className="view-logs-btn" onClick={() => navigate(`/host/${alert.host_name}`)}>
                      View
                    </button>
                  </td>
                </tr>
              )) : (
                <tr><td colSpan="7" className="empty-logs">No alerts detected. System is secure.</td></tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
}
