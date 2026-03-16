import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";

export default function Host() {
  const [hosts, setHosts] = useState([]);
  const navigate = useNavigate();

  const fetchHosts = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/hosts`);
      const data = await res.json();
      setHosts(data);
    } catch (err) {
      console.error("Fetch Error:", err);
    }
  };

  useEffect(() => {
    fetchHosts();
    const interval = setInterval(fetchHosts, 5000);

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

    return () => {
      clearInterval(interval);
      socket.off("host_update");
    };
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
        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="currentColor" viewBox="0 0 16 16">
              <path d="M0 1.5A1.5 1.5 0 0 1 1.5 0h13A1.5 1.5 0 0 1 16 1.5v9a1.5 1.5 0 0 1-1.5 1.5h-13A1.5 1.5 0 0 1 0 10.5v-9zM1.5 1a.5.5 0 0 0-.5.5v9a.5.5 0 0 0 .5.5h13a.5.5 0 0 0 .5-.5v-9a.5.5 0 0 0-.5-.5h-13z"/>
              <path d="M2 13.5a.5.5 0 0 1 .5-.5h11a.5.5 0 0 1 0 1h-11a.5.5 0 0 1-.5-.5zM4 15.5a.5.5 0 0 1 .5-.5h7a.5.5 0 0 1 0 1h-7a.5.5 0 0 1-.5-.5z"/>
            </svg>
          </div>
          <h1>Hosts Real-time Monitoring</h1>
        </div>

        <table>
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
            {hosts.length > 0 ? hosts.map((h, i) => {
              const isOnline = checkOnlineStatus(h.last_seen);
              const hasPrevention = h.action && h.action !== "No Action";

              return (
                <tr key={i} className={hasPrevention ? "attack-row" : (!isOnline ? "offline-row" : "")}>
                  <td><strong>{h.host_name || "Unknown"}</strong></td>
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
                    <button className="view-logs-btn" onClick={() => navigate(`/host/${h.host_name || "Unknown"}`)}>
                      View Logs
                    </button>
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan="6" className="empty-logs">No hosts detected yet. Start the host agent to begin monitoring.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
