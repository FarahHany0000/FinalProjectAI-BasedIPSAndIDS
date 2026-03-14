import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import "./Host.css";

export default function Host() {
  const [hosts, setHosts] = useState([]);
  const navigate = useNavigate();

  const fetchHosts = () => {
    fetch("http://localhost:5000/api/hosts")
      .then((res) => res.json())
      .then((data) => setHosts(data))
      .catch((err) => console.error("❌ Fetch Error:", err));
  };

  useEffect(() => {
    fetchHosts();
    const interval = setInterval(fetchHosts, 3000); 
    return () => clearInterval(interval);
  }, []);

  const checkOnlineStatus = (lastSeen) => {
    if (!lastSeen) return false;
    const lastSeenDate = new Date(lastSeen);
    const now = new Date();
    return (now - lastSeenDate) / 1000 < 30;
  };

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">
        <h1> Hosts Real-time Monitoring</h1>
        <table className="host-table">
          <thead>
            <tr>
              <th>Host Name</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Action Taken</th> {/* العمود الجديد */}
              <th>Details</th>      {/* عمود الزر فقط */}
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => {
              const isOnline = checkOnlineStatus(h.last_seen);
              const currentHostName = h.host_name || h.host; 
              
              // نتحقق إذا كان هناك إجراء حظر أو منع مسجل لهذا الجهاز
              const hasPrevention = h.action && h.action !== "No Action";

              return (
                <tr key={i} className={!isOnline ? "offline-row" : ""}>
                  <td><strong>{currentHostName}</strong></td>
                  <td>{h.ip}</td>
                  <td>
                    <span className={`status-badge ${isOnline ? "online" : "offline"}`}>
                      {isOnline ? "● Online" : "○ Offline"}
                    </span>
                  </td>
                  <td>{h.last_seen ? new Date(h.last_seen).toLocaleTimeString() : "N/A"}</td>
                  
                  {/* عرض حالة الإجراء الوقائي */}
                  <td>
                    <span className={hasPrevention ? "prevention-active" : "prevention-none"}>
                      {hasPrevention ? ` ${h.action}` : " No Threats"}
                    </span>
                  </td>

                  <td>
                    <button 
                      className="view-logs-btn" 
                      onClick={() => navigate(`/host/${currentHostName}`)}
                    >
                      View Details
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