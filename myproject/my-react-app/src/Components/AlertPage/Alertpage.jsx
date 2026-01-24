import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import "./Alerts.css";
import StatesCard from "../StatesCard/StatesCard";
import Sidebar from "../Sidebar/Sidebar";
import RecentAlert from "../RecentAlert/RecentAlert";

export default function Alertpage() {
  const navigate = useNavigate();

  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({
    total: 0,
    critical: 0,
    blocked: 0,
  });

  // ===============================
  // CHECK TOKEN (FAKE – frontend only)
  // ===============================
  useEffect(() => {
    const token = localStorage.getItem("token");
    // هنا النفروض اغير اللينك
    
    if (!token) {
      navigate("/alert", {
        state: { msg: "Please login first" },
      });
      return;
    }

    fetchAlerts();
  }, [navigate]);

  // ===============================
  // FAKE API DATA
  // ===============================
  const fetchAlerts = () => {
    const fakeResponse = [
      {
        id: "ALT-2025-001",
        time: "2025-10-30 14:32:15",
        type: "DDoS Attack",
        source: "192.168.1.105",
        destination: "10.0.0.1",
        status: "Blocked",
        confidence: "98.5%",
      },
      {
        id: "ALT-2025-002",
        time: "2025-10-30 14:28:45",
        type: "Port Scan",
        source: "10.0.0.45",
        destination: "10.0.0.2",
        status: "Blocked",
        confidence: "95.2%",
      },
      {
        id: "ALT-2025-005",
        time: "2025-10-30 14:10:05",
        type: "Malware Detection",
        source: "PC-03",
        destination: "203.0.113.100",
        status: "Detected",
        confidence: "87.3%",
      },
    ];

    setAlerts(fakeResponse);

    setStats({
      total: fakeResponse.length,
      critical: 2,
      blocked: fakeResponse.filter(
        (a) => a.status === "Blocked"
      ).length,
    });
  };

  return (
    <>
    <div className="dashboard">
      <Sidebar />

      <div className="main-content">
        <div className='icondesign'>
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
         <h1>Alerts </h1>
        </div>
       
        <p>Real-time intrusion detection and prevention overview</p>

        
            <div className="alerts-page">
      {/* ===== TOP STATS ===== */}
      <div className="alerts-stats">
        <div className="stat-card">
          <p>Total Alerts</p>
          <h2>{stats.total}</h2>
        </div>

        <div className="stat-card warning">
          <p>Critical</p>
          <h2>{stats.critical}</h2>
        </div>

        <div className="stat-card success">
          <p>Blocked</p>
          <h2>{stats.blocked}</h2>
        </div>
      </div>

      {/* ===== ALERTS TABLE ===== */}
      <div className="alerts-table">
        <h3>Security Alerts</h3>

        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Time</th>
              <th>Type</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Status</th>
              <th>Confidence</th>
            </tr>
          </thead>

          <tbody>
            {alerts.map((alert, index) => (
              <tr key={index}>
                <td>{alert.id}</td>
                <td>{alert.time}</td>
                <td>{alert.type}</td>
                <td>{alert.source}</td>
                <td>{alert.destination}</td>
                <td>
                  <span
                    className={
                      alert.status === "Blocked"
                        ? "badge blocked"
                        : "badge detected"
                    }
                  >
                    {alert.status}
                  </span>
                </td>
                <td>{alert.confidence}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
        
      </div>
    </div>
    </>
   
  );
}
