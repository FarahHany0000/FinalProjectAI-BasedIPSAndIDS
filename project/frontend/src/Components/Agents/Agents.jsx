import React, { useEffect, useMemo, useState } from "react";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { Users, CheckCircle, XCircle, Clock, Shield } from "lucide-react";

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
    const interval = setInterval(fetchAgents, 10000);

    socket.on("agent_update", (agent) => {
      setAgents(prev => {
        const idx = prev.findIndex(a => a.agent_id === agent.agent_id);
        if (idx >= 0) {
          const updated = [...prev];
          updated[idx] = agent;
          return updated;
        }
        return [...prev, agent];
      });
    });

    socket.on("agent_removed", (removed) => {
      setAgents(prev => prev.filter(a => a.agent_id !== removed.agent_id));
    });

    return () => {
      clearInterval(interval);
      socket.off("agent_update");
      socket.off("agent_removed");
    };
  }, []);

  const isOnline = (lastSeen) => {
    if (!lastSeen) return false;
    return (new Date() - new Date(lastSeen)) / 1000 < 30;
  };

  const normalizedAgents = useMemo(() => {
    const map = new Map();
    agents.forEach((agent) => {
      const key = `${agent.host_name}|${agent.ip || ""}`;
      const prev = map.get(key);
      const prevTs = prev?.last_seen ? new Date(prev.last_seen).getTime() : 0;
      const curTs = agent?.last_seen ? new Date(agent.last_seen).getTime() : 0;
      if (!prev || curTs >= prevTs) {
        map.set(key, agent);
      }
    });
    return Array.from(map.values()).sort((a, b) => {
      const aTs = a?.last_seen ? new Date(a.last_seen).getTime() : 0;
      const bTs = b?.last_seen ? new Date(b.last_seen).getTime() : 0;
      return bTs - aTs;
    });
  }, [agents]);

  const onlineCount = normalizedAgents.filter(a => isOnline(a.last_seen) && a.is_approved).length;
  const offlineCount = normalizedAgents.filter(a => !isOnline(a.last_seen) && a.is_approved).length;
  const pendingAgents = normalizedAgents.filter(a => !a.is_approved);

  const handleApprove = async (id) => {
    try {
      await fetch(`${API_BASE}/api/agents/${id}/approve`, { method: "POST" });
      fetchAgents();
    } catch (err) {
      console.error("Approve error:", err);
    }
  };

  const handleReject = async (id) => {
    if (!window.confirm("Reject and remove this device?")) return;
    try {
      await fetch(`${API_BASE}/api/agents/${id}/reject`, { method: "POST" });
      fetchAgents();
    } catch (err) {
      console.error("Reject error:", err);
    }
  };

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons"><Users size={36} /></div>
          <h1>Registered Agents</h1>
        </div>

        {/* Pending Devices Banner */}
        {pendingAgents.length > 0 && (
          <div className="pending-banner">
            <div className="pending-banner-header">
              <Clock size={20} />
              <strong>{pendingAgents.length} Device{pendingAgents.length > 1 ? "s" : ""} Pending Approval</strong>
            </div>
            <div className="pending-devices-list">
              {pendingAgents.map((agent) => (
                <div key={agent.id} className="pending-device-card">
                  <div className="pending-device-info">
                    <strong>{agent.host_name}</strong>
                    <span className="pending-device-meta">{agent.ip} • {agent.os_info || "Unknown OS"}</span>
                    {agent.hardware_id && (
                      <span className="pending-device-hw">HW: {agent.hardware_id.substring(0, 16)}...</span>
                    )}
                  </div>
                  <div className="pending-device-actions">
                    <button className="btn-approve" onClick={() => handleApprove(agent.id)}>
                      <CheckCircle size={16} /> Approve
                    </button>
                    <button className="btn-reject" onClick={() => handleReject(agent.id)}>
                      <XCircle size={16} /> Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className="stat-card">
            <h4>Total Agents</h4>
            <p>{normalizedAgents.length}</p>
          </div>
          <div className="stat-card">
            <h4>Online</h4>
            <p className="host-online">{onlineCount}</p>
          </div>
          <div className="stat-card">
            <h4>Offline</h4>
            <p className="host-offline">{offlineCount}</p>
          </div>
          <div className="stat-card">
            <h4>Pending</h4>
            <p style={{ color: pendingAgents.length > 0 ? "#f97316" : "#6b7280" }}>
              {pendingAgents.length}
            </p>
          </div>
        </div>

        {/* Agents Table */}
        <div className="panel">
          <h3>Agent Registry</h3>
          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th>Agent ID</th>
                  <th>Host Name</th>
                  <th>IP Address</th>
                  <th>OS</th>
                  <th>Status</th>
                  <th>Approved</th>
                  <th>Registered</th>
                  <th>Last Heartbeat</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {normalizedAgents.length > 0 ? normalizedAgents.map((agent, i) => {
                  const online = isOnline(agent.last_seen);
                  const pending = !agent.is_approved;
                  return (
                    <tr key={i} className={pending ? "pending-row" : (!online ? "offline-row" : "")}>
                      <td style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>
                        {agent.agent_id ? agent.agent_id.substring(0, 12) + "..." : "N/A"}
                      </td>
                      <td><strong>{agent.host_name}</strong></td>
                      <td>{agent.ip}</td>
                      <td>{agent.os_info || "N/A"}</td>
                      <td>
                        <span className={`status-badge ${pending ? "pending" : (online ? "online" : "offline")}`}>
                          {pending ? "⏳ Pending" : (online ? "● Online" : "○ Offline")}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: agent.is_approved ? "#22c55e" : "#f97316", fontWeight: "bold" }}>
                          {agent.is_approved ? "✓ Yes" : "✕ No"}
                        </span>
                      </td>
                      <td>{agent.registered_at ? new Date(agent.registered_at).toLocaleString() : "N/A"}</td>
                      <td>{agent.last_seen ? new Date(agent.last_seen).toLocaleTimeString() : "N/A"}</td>
                      <td>
                        {pending && (
                          <div style={{ display: "flex", gap: "6px" }}>
                            <button className="btn-approve-sm" onClick={() => handleApprove(agent.id)}>✓</button>
                            <button className="btn-reject-sm" onClick={() => handleReject(agent.id)}>✕</button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                }) : (
                  <tr><td colSpan="9" className="empty-logs">No agents registered yet. Deploy the host agent to get started.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Info */}
        <div className="panel" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <Shield size={20} color="#3b82f6" />
          <span style={{ fontSize: "0.85rem", color: "#9ca3af" }}>
            Agents are secured with hardware fingerprinting. Each device has a unique HMAC-SHA256
            hash of its hardware identifiers. Cloned agents are automatically rejected.
          </span>
        </div>

      </div>
    </div>
  );
}
