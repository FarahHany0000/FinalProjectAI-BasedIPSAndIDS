import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import "./Alerts.css";

export default function AlertsPage() {
  const navigate = useNavigate();
  const [alerts, setAlerts] = useState([]);

  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0
  });

  // IPS Decision Engine
  const generateAction = (type, severity) => {
    if (severity === "Critical") return "Host Isolated";
    if (type === "DDoS Attack") return "Traffic Dropped";
    if (type === "Port Scan") return "IP Blacklisted";
    if (type === "Malware Detection") return "Traffic Dropped";
    if (type === "SQL Injection") return "Traffic Dropped";
    if (type === "Brute Force") return "Account Locked";
    return "Connection Reset";
  };

  const getSeverity = (type) => {
    switch (type) {
      case "DDoS Attack":
      case "Ransomware":
        return "Critical";
      case "Malware Detection":
      case "SQL Injection":
        return "High";
      case "Brute Force":
        return "Medium";
      default:
        return "Low";
    }
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case "Critical":
        return "critical";
      case "High":
        return "high";
      case "Medium":
        return "medium";
      default:
        return "low";
    }
  };

  // Fake alerts generator
  const generateRandomAlerts = () => {
    const types = [
      "DDoS Attack",
      "Port Scan",
      "Malware Detection",
      "SQL Injection",
      "Brute Force"
    ];

    return Array.from({ length: 5 }).map(() => {
      const type = types[Math.floor(Math.random() * types.length)];
      const severity = getSeverity(type);
      const connection = Math.random() > 0.5 ? "Online" : "Offline";

      return {
        id: `ALT-2026-${Math.floor(Math.random() * 900 + 100)}`,
        time: new Date().toLocaleTimeString(),
        type,
        severity,
        action: generateAction(type, severity),
        connection
      };
    });
  };

  // Load Alerts and Auto Update
  useEffect(() => {
    const updateAlerts = () => {
      const newAlerts = generateRandomAlerts();
      setAlerts(newAlerts);

      setStats({
        total: newAlerts.length,
        critical: newAlerts.filter(a => a.severity === "Critical").length,
        high: newAlerts.filter(a => a.severity === "High").length,
        medium: newAlerts.filter(a => a.severity === "Medium").length,
        low: newAlerts.filter(a => a.severity === "Low").length
      });
    };

    updateAlerts();
    const interval = setInterval(updateAlerts, 3000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard">
      <Sidebar />

      <div className="main-content">

        <div className="icondesign">
          <div className="icons">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="50"
              height="50"
              fill="currentColor"
              viewBox="0 0 16 16"
            >
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>

          <h1>Alerts</h1>
        </div>


        {/* Stats */}
        <div className="alerts-stats">

          <div className="stat-card">
            Total Alerts
            <h2>{stats.total}</h2>
          </div>

          <div className="stat-card critical">
            Critical Threats
            <h2>{stats.critical}</h2>
          </div>

          <div className="stat-card high">
            High Severity
            <h2>{stats.high}</h2>
          </div>

          <div className="stat-card medium">
            Medium Severity
            <h2>{stats.medium}</h2>
          </div>

          <div className="stat-card low">
            Low Severity
            <h2>{stats.low}</h2>
          </div>

        </div>


        {/* Alerts Table */}
        <div className="alerts-table">
          <h3>Live Traffic</h3>

          <table>
            <thead>
              <tr>
                <th>ID</th>
                <th>Time</th>
                <th>Attack Type</th>
                <th>Severity</th>
                <th>Action Taken</th>
                <th>Connection</th>
                <th>Details</th>
              </tr>
            </thead>

            <tbody>
              {alerts.map((alert) => (
                <tr key={alert.id}>
                  <td>{alert.id}</td>
                  <td>{alert.time}</td>
                  <td>{alert.type}</td>

                  <td>
                    <span className={`badge ${getSeverityColor(alert.severity)}`}>
                      {alert.severity}
                    </span>
                  </td>

                  <td>
                    <span style={{ color: "red", fontWeight: "bold" }}>
                      {alert.action}
                    </span>
                  </td>

                  <td>
                    <span style={{
                      color: alert.connection === "Online" ? "green" : "red"
                    }}>
                      {alert.connection}
                    </span>
                  </td>

                  <td>
                    <button
                      className="details-btn"
                      onClick={() => navigate(`/alert/attackdetail`)}
                    >
                      View
                    </button>
                  </td>

                </tr>
              ))}
            </tbody>

          </table>
        </div>


        <div style={{ marginTop: "20px", textAlign: "right" }}>
          <button
            className="logs-btn"
            onClick={() => navigate("/alert/logs")}
          >
            View Logs
          </button>
        </div>

      </div>
    </div>
  );
}