import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import "./Host.css";

export default function Host() {
  const [hosts, setHosts] = useState([]);
  const navigate = useNavigate();

  const fetchHosts = async () => {
    try {
      const res = await fetch("http://localhost:5000/api/hosts");
      const data = await res.json();
      setHosts(data);
    } catch (err) {
      console.error("❌ Fetch Error:", err);
    }
  };

  useEffect(() => {
    fetchHosts();
    const interval = setInterval(fetchHosts, 2000); // تحديث كل ثانيتين
    return () => clearInterval(interval);
  }, []);

  // حالة Online/Offline بناء على آخر ظهور
  const checkOnlineStatus = (lastSeen) => {
    if (!lastSeen) return false;
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    return (now - lastSeenDate) / 1000 < 30; // لو أرسل خلال آخر 30 ثانية → Online
  };

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">
        <h1>🛡️ Hosts Real-time Monitoring</h1>
        <table className="host-table">
          <thead>
            <tr>
              <th>Host Name</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Action Taken</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => {
              const isOnline = checkOnlineStatus(h.last_seen);
              const currentHostName = h.host_name || "Unknown";

              // إذا الـ AI اتخذ إجراء
              const hasPrevention = h.action && h.action !== "No Action";

              return (
                <tr key={i} className={hasPrevention ? "attack-row" : (!isOnline ? "offline-row" : "")}>
                  <td><strong>{currentHostName}</strong></td>
                  <td>{h.ip}</td>
                  <td>
                    <span className={`status-badge ${isOnline ? "online" : "offline"}`}>
                      {isOnline ? "● Online" : "○ Offline"}
                    </span>
                  </td>
                  <td>{h.last_seen ? new Date(h.last_seen).toLocaleTimeString() : "N/A"}</td>
                  <td>
                    <span className={hasPrevention ? "prevention-active blink" : "prevention-none"}>
                      {hasPrevention ? h.action : "Secure"}
                    </span>
                  </td>
                  <td>
                    <button 
                      className="view-logs-btn" 
                      onClick={() => navigate(`/host/${currentHostName}`)}
                    >
                      View Logs
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}