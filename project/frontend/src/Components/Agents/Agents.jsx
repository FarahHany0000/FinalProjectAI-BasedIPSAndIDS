import React, { useEffect, useState } from "react";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";

export default function Agents() {
  const [agents, setAgents] = useState([]);

  const fetchAgents = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/agents`);
      const data = await res.json();
      setAgents(data);
    } catch (err) {
      console.error("Agents fetch error:", err);
    }
  };

  useEffect(() => {
    fetchAgents();
    const interval = setInterval(fetchAgents, 3000);
    return () => clearInterval(interval);
  }, []);

  const isOnline = (lastSeen) => {
    if (!lastSeen) return false;
    return (new Date() - new Date(lastSeen)) / 1000 < 30;
  };

  const onlineCount = agents.filter(a => isOnline(a.last_seen)).length;
  const offlineCount = agents.length - onlineCount;

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="currentColor" viewBox="0 0 16 16">
              <path d="M6 8a3 3 0 1 0 0-6 3 3 0 0 0 0 6zm-5 6s-1 0-1-1 1-4 6-4 6 3 6 4-1 1-1 1H1zM11 3.5a.5.5 0 0 1 .5-.5h4a.5.5 0 0 1 0 1h-4a.5.5 0 0 1-.5-.5zm.5 2.5a.5.5 0 0 0 0 1h4a.5.5 0 0 0 0-1h-4zm2 3a.5.5 0 0 0 0 1h2a.5.5 0 0 0 0-1h-2zm-1 2a.5.5 0 0 0 0 1h3a.5.5 0 0 0 0-1h-3z"/>
            </svg>
          </div>
          <h1>Registered Agents</h1>
        </div>

        {/* Stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
          <div className="stat-card">
            <h4>Total Agents</h4>
            <p>{agents.length}</p>
          </div>
          <div className="stat-card">
            <h4>Online</h4>
            <p className="host-online">{onlineCount}</p>
          </div>
          <div className="stat-card">
            <h4>Offline</h4>
            <p className="host-offline">{offlineCount}</p>
          </div>
        </div>

        {/* Agents Table */}
        <div className="panel">
          <h3>Agent Registry</h3>
          <table>
            <thead>
              <tr>
                <th>Agent ID</th>
                <th>Host Name</th>
                <th>IP Address</th>
                <th>OS</th>
                <th>Status</th>
                <th>Approved</th>
                <th>Registered At</th>
                <th>Last Heartbeat</th>
              </tr>
            </thead>
            <tbody>
              {agents.length > 0 ? agents.map((agent, i) => {
                const online = isOnline(agent.last_seen);
                return (
                  <tr key={i} className={!online ? "offline-row" : ""}>
                    <td style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                      {agent.agent_id ? agent.agent_id.substring(0, 12) + "..." : "N/A"}
                    </td>
                    <td><strong>{agent.host_name}</strong></td>
                    <td>{agent.ip}</td>
                    <td>{agent.os_info || "N/A"}</td>
                    <td>
                      <span className={`status-badge ${online ? "online" : "offline"}`}>
                        {online ? "● Online" : "○ Offline"}
                      </span>
                    </td>
                    <td>
                      <span style={{ color: agent.is_approved ? "#22c55e" : "#ef4444", fontWeight: "bold" }}>
                        {agent.is_approved ? "✓ Yes" : "✕ No"}
                      </span>
                    </td>
                    <td>{agent.registered_at ? new Date(agent.registered_at).toLocaleString() : "N/A"}</td>
                    <td>{agent.last_seen ? new Date(agent.last_seen).toLocaleTimeString() : "N/A"}</td>
                  </tr>
                );
              }) : (
                <tr><td colSpan="8" className="empty-logs">No agents registered yet. Deploy the host agent to get started.</td></tr>
              )}
            </tbody>
          </table>
        </div>

      </div>
    </div>
  );
}
