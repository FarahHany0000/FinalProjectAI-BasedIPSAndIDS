import React, { useEffect, useMemo, useState, useCallback, useRef } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";
import { Monitor, CheckCircle, XCircle, Clock, Wifi, WifiOff } from "lucide-react";

export default function Devices() {
  const navigate = useNavigate();
  const [hosts, setHosts] = useState([]);
  const [agents, setAgents] = useState([]);
  const debounceRef = useRef(null);

  const fetchData = useCallback(async () => {
    try {
      const [hostsRes, agentsRes] = await Promise.all([
        fetch(`${API_BASE}/api/hosts`),
        fetch(`${API_BASE}/api/agents`),
      ]);
      setHosts(await hostsRes.json());
      setAgents(await agentsRes.json());
    } catch {
      // silent
    }
  }, []);

  const debouncedFetch = useCallback(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(fetchData, 2000);
  }, [fetchData]);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);

    socket.on("host_update", debouncedFetch);
    socket.on("agent_update", debouncedFetch);

    return () => {
      clearInterval(interval);
      if (debounceRef.current) clearTimeout(debounceRef.current);
      socket.off("host_update");
      socket.off("agent_update");
    };
  }, [fetchData, debouncedFetch]);

  const isOnline = (lastSeen) => {
    if (!lastSeen) return false;
    return (new Date() - new Date(lastSeen)) / 1000 < 30;
  };

  // Merge hosts + agents into unified device list
  const devices = useMemo(() => {
    const deviceMap = new Map();

    // Start with hosts
    hosts.forEach((h) => {
      deviceMap.set(h.host_name, {
        host_name: h.host_name,
        ip: h.ip || "N/A",
        os: h.os_info || "N/A",
        status: isOnline(h.last_seen) ? "online" : "offline",
        last_seen: h.last_seen,
        threat: h.last_prediction || "Normal",
        probability: h.last_probability || 0,
        approved: true,
        agent_id: null,
      });
    });

    // Enrich with agent data
    agents.forEach((a) => {
      const existing = deviceMap.get(a.host_name);
      if (existing) {
        existing.os = a.os_info || existing.os;
        existing.approved = a.is_approved;
        existing.agent_id = a.agent_id;
        if (!existing.ip || existing.ip === "N/A") existing.ip = a.ip;
      } else {
        deviceMap.set(a.host_name, {
          host_name: a.host_name,
          ip: a.ip || "N/A",
          os: a.os_info || "N/A",
          status: isOnline(a.last_seen) ? "online" : "offline",
          last_seen: a.last_seen,
          threat: "Normal",
          probability: 0,
          approved: a.is_approved,
          agent_id: a.agent_id,
        });
      }
    });

    return Array.from(deviceMap.values()).sort((a, b) => {
      // Pending first, then online, then offline
      if (!a.approved && b.approved) return -1;
      if (a.approved && !b.approved) return 1;
      if (a.status === "online" && b.status !== "online") return -1;
      if (a.status !== "online" && b.status === "online") return 1;
      return 0;
    });
  }, [hosts, agents]);

  const onlineCount = devices.filter(d => d.status === "online" && d.approved).length;
  const pendingDevices = devices.filter(d => !d.approved);

  const handleApprove = async (hostName) => {
    const agent = agents.find(a => a.host_name === hostName);
    if (!agent) return;
    try {
      await fetch(`${API_BASE}/api/agents/${agent.id}/approve`, { method: "POST" });
      fetchData();
    } catch {
      // silent
    }
  };

  const handleReject = async (hostName) => {
    const agent = agents.find(a => a.host_name === hostName);
    if (!agent) return;
    if (!window.confirm("Reject this device? It will be removed.")) return;
    try {
      await fetch(`${API_BASE}/api/agents/${agent.id}/reject`, { method: "POST" });
      fetchData();
    } catch {
      // silent
    }
  };

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons"><Monitor size={36} /></div>
          <h1>Devices</h1>
        </div>
        <p className="page-description">All monitored devices on your network. Click any device to see details.</p>

        {/* Pending Approval Banner */}
        {pendingDevices.length > 0 && (
          <div className="pending-banner">
            <div className="pending-banner-header">
              <Clock size={20} />
              <strong>{pendingDevices.length} New Device{pendingDevices.length > 1 ? "s" : ""} — Approval Required</strong>
            </div>
            <p style={{ color: "#d4a574", fontSize: "0.85rem", margin: "6px 0 12px 0" }}>
              These devices were detected on the network but haven't been approved yet.
            </p>
            <div className="pending-devices-list">
              {pendingDevices.map((d) => (
                <div key={d.host_name} className="pending-device-card">
                  <div className="pending-device-info">
                    <strong>{d.host_name}</strong>
                    <span className="pending-device-meta">{d.ip} • {d.os}</span>
                  </div>
                  <div className="pending-device-actions">
                    <button className="btn-approve" onClick={() => handleApprove(d.host_name)}>
                      <CheckCircle size={16} /> Approve
                    </button>
                    <button className="btn-reject" onClick={() => handleReject(d.host_name)}>
                      <XCircle size={16} /> Reject
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
          <div className="stat-card">
            <h4>Total Devices</h4>
            <p>{devices.filter(d => d.approved).length}</p>
          </div>
          <div className="stat-card">
            <h4><Wifi size={14} style={{ marginRight: 4 }} /> Connected</h4>
            <p className="host-online">{onlineCount}</p>
          </div>
          <div className="stat-card">
            <h4><WifiOff size={14} style={{ marginRight: 4 }} /> Disconnected</h4>
            <p className="host-offline">{devices.filter(d => d.approved).length - onlineCount}</p>
          </div>
        </div>

        {/* Devices Table */}
        <div className="panel">
          <h3>Device List</h3>
          <div className="table-scroll-container">
            <table>
              <thead>
                <tr>
                  <th>Device Name</th>
                  <th>IP Address</th>
                  <th>Operating System</th>
                  <th>Connection</th>
                  <th>Last Seen</th>
                  <th>Threat Status</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {devices.length > 0 ? devices.map((d, i) => {
                  const pending = !d.approved;
                  const isThreat = d.threat !== "Normal" && d.threat !== "Benign";
                  return (
                    <tr key={i}
                      className={`${pending ? "pending-row" : ""} ${isThreat ? "attack-row" : ""} ${d.status === "offline" && d.approved ? "offline-row" : ""}`}
                      style={{ cursor: d.approved ? "pointer" : "default" }}
                      onClick={() => d.approved && navigate(`/device/${d.host_name}`)}
                    >
                      <td><strong>{d.host_name}</strong></td>
                      <td>{d.ip}</td>
                      <td>{d.os}</td>
                      <td>
                        {pending ? (
                          <span className="status-badge pending">⏳ Pending</span>
                        ) : d.status === "online" ? (
                          <span className="status-badge online">● Connected</span>
                        ) : (
                          <span className="status-badge offline">○ Disconnected</span>
                        )}
                      </td>
                      <td>{d.last_seen ? new Date(d.last_seen).toLocaleTimeString() : "Never"}</td>
                      <td>
                        {isThreat ? (
                          <span className="status-badge malicious">⚠ {d.threat}</span>
                        ) : (
                          <span className="status-badge benign">✓ Secure</span>
                        )}
                      </td>
                      <td onClick={(e) => e.stopPropagation()}>
                        {pending ? (
                          <div style={{ display: "flex", gap: "6px" }}>
                            <button className="btn-approve-sm" onClick={() => handleApprove(d.host_name)} title="Approve">✓</button>
                            <button className="btn-reject-sm" onClick={() => handleReject(d.host_name)} title="Reject">✕</button>
                          </div>
                        ) : (
                          <button className="btn-detail" onClick={() => navigate(`/device/${d.host_name}`)}>
                            Details →
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                }) : (
                  <tr><td colSpan="7" className="empty-logs">No devices detected yet. Start the Host Agent to begin monitoring.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
