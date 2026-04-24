import React, { useState, useEffect, useCallback } from "react";
import Sidebar from "../Sidebar/Sidebar";
import socket from "../../socket";
import API_BASE from "../../config";
import { Shield, Activity } from "lucide-react";

export default function Network() {
  const [alerts, setAlerts] = useState([]);
  const [stats, setStats] = useState({ total_alerts: 0, blocked_attacks: 0, by_type: {} });
  const [prevention, setPrevention] = useState({ enabled: false, blocked_ips: [] });
  const [displayMode, setDisplayMode] = useState("full");

  const fetchData = useCallback(async () => {
    try {
      const [alertsRes, statsRes, prevRes, threshRes] = await Promise.all([
        fetch(`${API_BASE}/api/network/alerts?limit=100`),
        fetch(`${API_BASE}/api/network/stats`),
        fetch(`${API_BASE}/api/network/prevention`),
        fetch(`${API_BASE}/api/network/threshold`),
      ]);
      if (alertsRes.ok) setAlerts(await alertsRes.json());
      if (statsRes.ok) setStats(await statsRes.json());
      if (prevRes.ok) setPrevention(await prevRes.json());
      if (threshRes.ok) {
        const t = await threshRes.json();
        if (t.display_mode) setDisplayMode(t.display_mode);
      }
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 30000);

    socket.on("new_alert", (alert) => {
      if (alert.source_type === "network") {
        setAlerts((prev) => [alert, ...prev].slice(0, 100));
        setStats((prev) => ({
          ...prev,
          total_alerts: prev.total_alerts + 1,
          blocked_attacks: alert.is_blocked ? prev.blocked_attacks + 1 : prev.blocked_attacks,
        }));
      }
    });

    socket.on("config_update", (config) => {
      if (config.prevention_enabled !== undefined || config.blocked_ips !== undefined) {
        setPrevention((prev) => ({ ...prev, ...config }));
      }
      if (config.display_mode) setDisplayMode(config.display_mode);
    });

    return () => {
      clearInterval(interval);
      socket.off("new_alert");
      socket.off("config_update");
    };
  }, [fetchData]);

  const attackTypes = Object.entries(stats.by_type || {}).sort((a, b) => b[1] - a[1]);
  const isBinaryMode = displayMode === "binary";

  return (
    <div className="dashboard">
      <Sidebar activePage="network" />
      <div className="main-content">

        {/* Header */}
        <div className="icondesign">
          <div className="icons"><Shield size={36} /></div>
          <div>
            <h1 style={{ margin: 0 }}>Network IDS/IPS Monitor</h1>
            {prevention.enabled && (
              <span style={{ color: "#22c55e", fontSize: "0.75rem", fontWeight: 600, display: "flex", alignItems: "center", gap: "6px", marginTop: "4px" }}>
                <span className="active-dot" /> IPS Active
                {prevention.blocked_ips.length > 0 && (
                  <span style={{ color: "#ef4444" }}> | {prevention.blocked_ips.length} blocked</span>
                )}
              </span>
            )}
          </div>
        </div>

        {/* Stats Row */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(3, 1fr)" }}>
          <div className="stat-card">
            <h4>Total Detections</h4>
            <p>{stats.total_alerts}</p>
          </div>
          <div className="stat-card">
            <h4>Blocked Attacks</h4>
            <p className="severity-critical">{stats.blocked_attacks}</p>
          </div>
          <div className="stat-card">
            <h4>Attack Types</h4>
            <p className="severity-high">{attackTypes.length}</p>
          </div>
        </div>

        {/* Blocked IPs (inline, compact) */}
        {prevention.blocked_ips.length > 0 && (
          <div className="panel" style={{ marginBottom: "20px" }}>
            <h3>Blocked IPs {prevention.enabled && <span style={{ color: "#22c55e", fontSize: "0.75rem" }}>(Auto-blocking active)</span>}</h3>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "8px" }}>
              {prevention.blocked_ips.map((ip) => (
                <span key={ip} style={{
                  background: "rgba(239,68,68,0.15)", color: "#ef4444", border: "1px solid rgba(239,68,68,0.3)",
                  borderRadius: "6px", padding: "4px 12px", fontSize: "0.85rem",
                }}>
                  {ip}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Attack Type Distribution */}
        {attackTypes.length > 0 && !isBinaryMode && (
          <div className="panel" style={{ marginBottom: "20px" }}>
            <h3>Attack Type Distribution</h3>
            <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginTop: "8px" }}>
              {attackTypes.map(([type, count]) => (
                <span key={type} style={{
                  background: "#2a2a2a", borderRadius: "6px", padding: "6px 14px",
                  fontSize: "0.85rem", display: "flex", alignItems: "center", gap: "8px",
                  border: "1px solid #444",
                }}>
                  <strong>{type}</strong>
                  <span style={{ color: "#9ca3af" }}>{count}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Mode Indicator */}
        <div style={{ display: "flex", alignItems: "center", gap: "6px", marginBottom: "12px" }}>
          <Activity size={14} color={isBinaryMode ? "#f97316" : "#3b82f6"} />
          <span style={{ fontSize: "0.75rem", color: "#6b7280" }}>
            Mode: {isBinaryMode ? "Binary Only (Attack / Normal)" : "Full (Binary + Classification)"}
          </span>
        </div>

        {/* Live Network Alerts Table */}
        <div className="panel">
          <h3>Live Network Detections</h3>
          <div className="table-scroll-container">
            <table>
              <thead style={{ position: "sticky", top: 0, zIndex: 1 }}>
                <tr>
                  <th>Time</th>
                  {isBinaryMode ? (
                    <th>Detection</th>
                  ) : (
                    <th>Attack Type</th>
                  )}
                  <th>Source IP</th>
                  <th>Dest IP</th>
                  <th>Port</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {alerts.length > 0 ? (
                  alerts.map((a, idx) => (
                    <tr key={a.id || idx}>
                      <td>{a.time ? new Date(a.time).toLocaleTimeString() : "N/A"}</td>
                      {isBinaryMode ? (
                        <td><strong style={{ color: "#ef4444" }}>Attack Detected</strong></td>
                      ) : (
                        <td><strong>{a.threat}</strong></td>
                      )}
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.src_ip || "-"}</td>
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.dst_ip || "-"}</td>
                      <td>{a.dst_port || "-"}</td>
                      <td>
                        <span className="badge" style={{
                          background: a.is_blocked ? "rgba(34,197,94,0.2)" : "rgba(239,68,68,0.2)",
                          color: a.is_blocked ? "#22c55e" : "#ef4444",
                        }}>
                          {a.action || "Alert"}
                        </span>
                      </td>
                    </tr>
                  ))
                ) : (
                  <tr>
                    <td colSpan={6} className="empty-logs">
                      No network attacks detected yet. Network sensor monitoring traffic...
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

      </div>
    </div>
  );
}
