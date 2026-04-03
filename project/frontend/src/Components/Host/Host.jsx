import React, { useEffect, useMemo, useState } from "react";
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

        <table className="hosts-table hosts-overview-table">
          <thead>
            <tr>
              <th>Host Name</th>
              <th>IP Address</th>
              <th>Status</th>
              <th>Last Seen</th>
              <th>Action Taken</th>
            </tr>
          </thead>
          <tbody>
            {normalizedHosts.length > 0 ? normalizedHosts.map((h, i) => {
              const isOnline = checkOnlineStatus(h.last_seen);
              const hasPrevention = h.action && h.action !== "No Action";

              return (
                <tr
                  key={i}
                  className={`${hasPrevention ? "attack-row" : (!isOnline ? "offline-row" : "")} row-clickable`}
                  onClick={() => navigate(`/host/${h.host_name || "Unknown"}`)}
                  onKeyDown={(e) => {
                    if (e.key === "Enter" || e.key === " ") {
                      navigate(`/host/${h.host_name || "Unknown"}`);
                    }
                  }}
                  role="button"
                  tabIndex={0}
                >
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
                </tr>
              );
            }) : (
              <tr><td colSpan="5" className="empty-logs">No hosts detected yet. Start the host agent to begin monitoring.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
