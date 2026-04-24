import React, { useState, useEffect, useCallback } from "react";
import Sidebar from "../Sidebar/Sidebar";
import socket from "../../socket";
import API_BASE from "../../config";
import {
  ShieldCheck,
  ShieldOff,
  Trash2,
  Archive,
  ChevronDown,
  ChevronUp,
  Eye,
  EyeOff,
  Activity,
  Settings,
  Monitor,
  AlertTriangle,
} from "lucide-react";

export default function Controls() {

  /* ── State ── */
  const [threshold, setThreshold] = useState(0.7);
  const [classThreshold, setClassThreshold] = useState(0.5);
  const [prevention, setPrevention] = useState({ enabled: false, blocked_ips: [] });
  const [displayMode, setDisplayMode] = useState("full");
  const [archives, setArchives] = useState([]);
  const [showArchives, setShowArchives] = useState(false);
  const [archiveData, setArchiveData] = useState(null);
  const [archiveFilename, setArchiveFilename] = useState("");
  const [showQuickActions, setShowQuickActions] = useState(false);
  const [showHostQuickActions, setShowHostQuickActions] = useState(false);
  const [confirmModal, setConfirmModal] = useState({ show: false, title: "", message: "", onConfirm: null });
  const [toast, setToast] = useState({ show: false, message: "" });

  // Host Prevention State
  const [hostPrevention, setHostPrevention] = useState(null);
  const [hostLogs, setHostLogs] = useState([]);

  // Host Archives State
  const [hostArchives, setHostArchives] = useState([]);
  const [showHostArchives, setShowHostArchives] = useState(false);
  const [hostArchiveData, setHostArchiveData] = useState(null);
  const [hostArchiveFilename, setHostArchiveFilename] = useState("");

  /* ── Fetch ── */
  const fetchData = useCallback(async () => {
    try {
      const [threshRes, prevRes, hostPrevRes, hostLogsRes] = await Promise.all([
        fetch(`${API_BASE}/api/network/threshold`),
        fetch(`${API_BASE}/api/network/prevention`),
        fetch(`${API_BASE}/api/prevention/status`),
        fetch(`${API_BASE}/api/prevention/logs?limit=10`),
      ]);
      if (threshRes.ok) {
        const t = await threshRes.json();
        setThreshold(t.threshold);
        if (t.classification_threshold !== undefined) {
          setClassThreshold(t.classification_threshold);
        }
        if (t.display_mode) setDisplayMode(t.display_mode);
      }
      if (prevRes.ok) setPrevention(await prevRes.json());
      if (hostPrevRes.ok) {
        const hp = await hostPrevRes.json();
        setHostPrevention(hp);
      }
      if (hostLogsRes.ok) {
        const logs = await hostLogsRes.json();
        setHostLogs(logs.filter(l => l.decision_level && l.decision_level !== "NONE"));
      }
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    fetchData();
    socket.on("config_update", (config) => {
      if (config.threshold !== undefined) {
        setThreshold(config.threshold);
      }
      if (config.classification_threshold !== undefined) {
        setClassThreshold(config.classification_threshold);
      }
      if (config.prevention_enabled !== undefined || config.blocked_ips !== undefined) {
        setPrevention((prev) => ({ ...prev, ...config }));
      }
      if (config.display_mode) setDisplayMode(config.display_mode);
    });
    return () => socket.off("config_update");
  }, [fetchData]);

  /* ── Actions ── */
  const showConfirm = (title, message, onConfirm) => {
    setConfirmModal({ show: true, title, message, onConfirm });
  };
  const closeConfirm = () => setConfirmModal({ show: false, title: "", message: "", onConfirm: null });
  const showToast = (message) => {
    setToast({ show: true, message });
    setTimeout(() => setToast({ show: false, message: "" }), 3000);
  };

  const togglePrevention = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/network/prevention`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !prevention.enabled }),
      });
      if (res.ok) setPrevention(await res.json());
    } catch {
    }
  };

  const unblockIp = async (ip) => {
    try {
      const res = await fetch(`${API_BASE}/api/network/prevention/unblock`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip }),
      });
      if (res.ok) fetchData();
    } catch {
    }
  };

  const resetPrevention = () => {
    showConfirm("Reset Network Prevention", "Remove ALL firewall rules and disable IPS? This will unblock all IPs.", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/network/prevention/reset`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
        });
        if (res.ok) fetchData();
      } catch { /* silent */ }
      closeConfirm();
    });
  };

  const archiveAlerts = () => {
    showConfirm("Archive Alerts", "Archive all current alerts and start fresh?", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/alerts/archive`, { method: "POST" });
        if (res.ok) {
          const data = await res.json();
          showToast(`✅ Archived ${data.archived} alerts`);
          fetchArchives();
        }
      } catch { /* silent */ }
      closeConfirm();
    });
  };

  const fetchArchives = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/archives`);
      if (res.ok) setArchives(await res.json());
    } catch {
    }
  };

  const loadArchive = async (filename) => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/archives/${filename}`);
      if (res.ok) {
        setArchiveData(await res.json());
        setArchiveFilename(filename);
      }
    } catch {
    }
  };

  const archiveHostLogs = () => {
    showConfirm("Archive Host Logs", "Archive all host prediction logs and agent events, then clear them?", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/host-alerts/archive`, { method: "POST" });
        if (res.ok) {
          const data = await res.json();
          showToast(`✅ Archived ${data.predictions_archived} predictions + ${data.events_archived} agent events`);
          fetchHostArchives();
          fetchData();
        }
      } catch { /* silent */ }
      closeConfirm();
    });
  };

  const clearHostLogs = () => {
    showConfirm("Clear Host Logs", "Delete ALL host prediction logs and agent events? This cannot be undone.", async () => {
      try {
        const res = await fetch(`${API_BASE}/api/host-alerts/clear`, { method: "POST" });
        if (res.ok) {
          showToast("✅ All host logs cleared");
          fetchData();
        }
      } catch { /* silent */ }
      closeConfirm();
    });
  };

  const fetchHostArchives = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/host-alerts/archives`);
      if (res.ok) setHostArchives(await res.json());
    } catch {
    }
  };

  const loadHostArchive = async (filename) => {
    try {
      const res = await fetch(`${API_BASE}/api/host-alerts/archives/${filename}`);
      if (res.ok) {
        setHostArchiveData(await res.json());
        setHostArchiveFilename(filename);
      }
    } catch {
    }
  };

  const deleteHostArchive = (filename) => {
    showConfirm("Delete Archive", `Delete archive ${filename}?`, async () => {
      try {
        const res = await fetch(`${API_BASE}/api/host-alerts/archives/${filename}`, { method: "DELETE" });
        if (res.ok) fetchHostArchives();
      } catch { /* silent */ }
      closeConfirm();
    });
  };

  /* ── Render ── */
  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <style>{`
          @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
          @keyframes scaleIn { from { opacity: 0; transform: scale(0.9); } to { opacity: 1; transform: scale(1); } }
          @keyframes fadeSlideIn { from { opacity: 0; transform: translateY(-10px); } to { opacity: 1; transform: translateY(0); } }
          .ctrl-action-btn { transition: all 0.2s ease; }
          .ctrl-action-btn:hover { transform: translateY(-1px); filter: brightness(1.2); }
          .ctrl-action-btn:active { transform: translateY(0); filter: brightness(0.9); }
        `}</style>

        {/* Header */}
        <div className="icondesign">
          <div className="icons"><Settings size={36} /></div>
          <h1>Controls</h1>
        </div>
        <p className="page-description">Configure detection, prevention, and display settings for Network and Host systems.</p>

        {/* ═══════════════════════ NETWORK SECTION ═══════════════════════ */}
        <div className="ctrl-section-divider">
          <ShieldCheck size={18} /> Network Protection (NIPS)
        </div>

        <div className="ctrl-grid">
          {/* Network Intrusion Prevention Toggle */}
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              {prevention.enabled ? <ShieldCheck size={20} color="#22c55e" /> : <ShieldOff size={20} color="#ef4444" />}
              <h3>Network Intrusion Prevention (NIPS)</h3>
            </div>
            <p className="ctrl-desc">
              {prevention.enabled
                ? "Enabled — IPs triggering 5+ alerts in 60s are auto-blocked via Windows Firewall."
                : "Disabled — Attacks are detected but not blocked."}
            </p>
            <button
              className={`ctrl-mode-btn ${prevention.enabled ? "selected" : ""}`}
              style={{ marginTop: "8px", cursor: "pointer" }}
              onClick={togglePrevention}
            >
              {prevention.enabled ? <><ShieldCheck size={14} /> Enabled</> : <><ShieldOff size={14} /> Disabled</>}
            </button>
          </div>

          {/* Alert Display Mode */}
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              {displayMode === "full" ? <Eye size={20} color="#3b82f6" /> : <EyeOff size={20} color="#f97316" />}
              <h3>Alert Display Mode</h3>
            </div>
            <p className="ctrl-desc">
              {displayMode === "full"
                ? "Showing alerts from both models (Binary gate + Classification type)."
                : "Showing alerts from Binary model only (attack detected, type not shown)."}
            </p>
            <div className="ctrl-mode-switch">
              <button
                className={`ctrl-mode-btn ${displayMode === "full" ? "selected" : ""}`}
                onClick={() => setDisplayMode("full")}
              >
                <Eye size={14} /> Full (Binary + Type)
              </button>
              <button
                className={`ctrl-mode-btn ${displayMode === "binary" ? "selected" : ""}`}
                onClick={() => setDisplayMode("binary")}
              >
                <Activity size={14} /> Binary Only
              </button>
            </div>
          </div>
        </div>

        {/* Network Maintenance Actions */}
        <button className="ctrl-advanced-toggle" onClick={() => setShowQuickActions(!showQuickActions)}>
          <Trash2 size={14} />
          Network Maintenance
          {showQuickActions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showQuickActions && (
          <div className="ctrl-actions" style={{ marginBottom: "16px", animation: "fadeSlideIn 0.3s ease" }}>
            <button className="ctrl-action-btn danger" onClick={resetPrevention}>
              <Trash2 size={14} /> Reset All Rules
            </button>
            <button className="ctrl-action-btn archive" onClick={archiveAlerts}>
              <Archive size={14} /> Archive Alerts
            </button>
            <button
              className="ctrl-action-btn neutral"
              onClick={() => { setShowArchives(!showArchives); if (!showArchives) fetchArchives(); }}
            >
              <Archive size={14} /> {showArchives ? "Hide" : "View"} Archives
            </button>
          </div>
        )}

        {/* ── Blocked IPs ── */}
        {prevention.blocked_ips.length > 0 && (
          <div className="ctrl-section">
            <div className="ctrl-section-header">
              <ShieldCheck size={20} color="#ef4444" />
              <h2>Blocked IPs ({prevention.blocked_ips.length})</h2>
            </div>
            <div className="ctrl-ip-list">
              {prevention.blocked_ips.map((ip) => (
                <div key={ip} className="ctrl-ip-chip">
                  <span className="ctrl-ip-text">{ip}</span>
                  <button className="ctrl-ip-remove" onClick={() => unblockIp(ip)}>x</button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Archives ── */}
        {showArchives && (
          <div className="ctrl-section">
            <div className="ctrl-section-header">
              <Archive size={20} color="#f97316" />
              <h2>Alert Archives</h2>
            </div>
            {archives.length > 0 ? (
              <div className="archive-scroll-list">
              <table>
                <thead><tr><th>File</th><th>Size</th><th>Action</th></tr></thead>
                <tbody>
                  {archives.map((a) => (
                    <tr key={a.filename}>
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.filename}</td>
                      <td>{a.size_kb} KB</td>
                      <td><button className="view-logs-btn" onClick={() => loadArchive(a.filename)}>Load</button></td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            ) : (
              <p style={{ color: "#6b7280", fontStyle: "italic" }}>No archives yet</p>
            )}
          </div>
        )}

        {/* ── Archive Data Viewer ── */}
        {archiveData && (
          <div className="ctrl-section">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>Archive: {archiveFilename} ({archiveData.length} alerts)</h3>
              <button onClick={() => { setArchiveData(null); setArchiveFilename(""); }} className="back-btn">Close</button>
            </div>
            <div className="table-scroll-container">
              <table>
                <thead><tr><th>Time</th><th>Attack</th><th>Confidence</th><th>Src IP</th><th>Dst IP</th><th>Port</th></tr></thead>
                <tbody>
                  {archiveData.slice(0, 50).map((a, i) => (
                    <tr key={i}>
                      <td>{a.time ? new Date(a.time).toLocaleString() : "N/A"}</td>
                      <td><strong>{a.threat}</strong></td>
                      <td>{((a.confidence || 0) * 100).toFixed(1)}%</td>
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.src_ip || "-"}</td>
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.dst_ip || "-"}</td>
                      <td>{a.dst_port || "-"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ═══════════════════════ HOST SECTION ═══════════════════════ */}
        <div className="ctrl-section-divider">
          <Monitor size={18} /> Host Protection (HIPS)
        </div>

        <div className="ctrl-grid">
          {/* Host Intrusion Prevention Toggle */}
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              {hostPrevention?.test_mode === false ? <ShieldCheck size={20} color="#22c55e" /> : <ShieldOff size={20} color="#ef4444" />}
              <h3>Host Intrusion Prevention (HIPS)</h3>
            </div>
            <p className="ctrl-desc">
              {hostPrevention?.test_mode === false
                ? "Enabled (Live Mode) — Suspicious host activity triggers real OS-level prevention actions."
                : "Disabled (Test Mode) — Suspicious activity is logged but no real actions are taken."}
            </p>
            <button
              className={`ctrl-mode-btn ${hostPrevention?.test_mode === false ? "selected" : ""}`}
              style={{ marginTop: "8px", cursor: "pointer" }}
              onClick={() => {
                if (hostPrevention?.test_mode === false) {
                  fetch(`${API_BASE}/api/prevention/mode`, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ test_mode: true }),
                  }).then(() => fetchData()).catch(() => {});
                } else {
                  showConfirm("Enable Host IPS (Live Mode)", "⚠️ Enable LIVE mode? This will execute real prevention actions on host devices.", async () => {
                    try {
                      await fetch(`${API_BASE}/api/prevention/mode`, {
                        method: "POST",
                        headers: { "Content-Type": "application/json" },
                        body: JSON.stringify({ test_mode: false }),
                      });
                      fetchData();
                    } catch { /* silent */ }
                    closeConfirm();
                  });
                }
              }}
            >
              {hostPrevention?.test_mode === false ? <><ShieldCheck size={14} /> Enabled</> : <><ShieldOff size={14} /> Disabled</>}
            </button>
          </div>
        </div>

        {/* Host Maintenance Actions */}
        <button className="ctrl-advanced-toggle" onClick={() => setShowHostQuickActions(!showHostQuickActions)}>
          <Trash2 size={14} />
          Host Maintenance
          {showHostQuickActions ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
        </button>

        {showHostQuickActions && (
          <div className="ctrl-actions" style={{ marginBottom: "16px", animation: "fadeSlideIn 0.3s ease" }}>
            <button className="ctrl-action-btn danger" onClick={clearHostLogs}>
              <Trash2 size={14} /> Clear All Logs
            </button>
            <button className="ctrl-action-btn archive" onClick={archiveHostLogs}>
              <Archive size={14} /> Archive Logs
            </button>
            <button
              className="ctrl-action-btn neutral"
              onClick={() => { setShowHostArchives(!showHostArchives); if (!showHostArchives) fetchHostArchives(); }}
            >
              <Archive size={14} /> {showHostArchives ? "Hide" : "View"} Archives
            </button>
          </div>
        )}

        {/* Host Archives */}
        {showHostArchives && (
          <div className="ctrl-section">
            <div className="ctrl-section-header">
              <Archive size={20} color="#8b5cf6" />
              <h2>Host Archives</h2>
            </div>
            {hostArchives.length > 0 ? (
              <div className="archive-scroll-list">
              <table>
                <thead><tr><th>File</th><th>Type</th><th>Size</th><th>Actions</th></tr></thead>
                <tbody>
                  {hostArchives.map((a) => (
                    <tr key={a.filename}>
                      <td style={{ fontFamily: "monospace", fontSize: "0.8rem" }}>{a.filename}</td>
                      <td>
                        <span style={{
                          background: a.type === "predictions" ? "rgba(139,92,246,0.15)" : "rgba(249,115,22,0.15)",
                          color: a.type === "predictions" ? "#8b5cf6" : "#f97316",
                          padding: "2px 8px", borderRadius: "4px", fontSize: "0.75rem"
                        }}>
                          {a.type === "predictions" ? "Predictions" : "Agent Events"}
                        </span>
                      </td>
                      <td>{a.size_kb} KB</td>
                      <td style={{ display: "flex", gap: "6px" }}>
                        <button className="view-logs-btn" onClick={() => loadHostArchive(a.filename)}>Load</button>
                        <button className="view-logs-btn" style={{ background: "rgba(239,68,68,0.15)", color: "#ef4444" }} onClick={() => deleteHostArchive(a.filename)}>Delete</button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
              </div>
            ) : (
              <p style={{ color: "#6b7280", fontStyle: "italic" }}>No host archives yet</p>
            )}
          </div>
        )}

        {/* Host Archive Data Viewer */}
        {hostArchiveData && (
          <div className="ctrl-section">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <h3>Archive: {hostArchiveFilename} ({Array.isArray(hostArchiveData) ? hostArchiveData.length : 0} entries)</h3>
              <button onClick={() => { setHostArchiveData(null); setHostArchiveFilename(""); }} className="back-btn">Close</button>
            </div>
            <div className="table-scroll-container">
              {hostArchiveFilename.startsWith("host_predictions") ? (
                <table>
                  <thead><tr><th>Time</th><th>Device</th><th>Prediction</th><th>Probability</th><th>XGBoost</th><th>RF</th><th>Level</th></tr></thead>
                  <tbody>
                    {(hostArchiveData || []).slice(0, 100).map((a, i) => (
                      <tr key={i}>
                        <td>{a.time ? new Date(a.time).toLocaleString() : "N/A"}</td>
                        <td>{a.host_name || "-"}</td>
                        <td><strong style={{ color: a.prediction === "Attack" ? "#ef4444" : "#22c55e" }}>{a.prediction}</strong></td>
                        <td>{((a.probability || 0) * 100).toFixed(1)}%</td>
                        <td>{a.xgb_prediction} ({((a.xgb_probability || 0) * 100).toFixed(1)}%)</td>
                        <td>{a.rf_prediction} ({((a.rf_probability || 0) * 100).toFixed(1)}%)</td>
                        <td><span className={`ctrl-level-badge ${(a.prevention_level || "").toLowerCase()}`}>{a.prevention_level || "-"}</span></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <table>
                  <thead><tr><th>Time</th><th>Device</th><th>Event</th><th>Details</th></tr></thead>
                  <tbody>
                    {(hostArchiveData || []).slice(0, 100).map((a, i) => (
                      <tr key={i}>
                        <td>{a.time ? new Date(a.time).toLocaleString() : "N/A"}</td>
                        <td>{a.host_name || "-"}</td>
                        <td><strong>{a.event}</strong></td>
                        <td>{a.label || "-"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* Recent Host Prevention Logs */}
        {hostLogs.length > 0 && (
          <div className="ctrl-section">
            <div className="ctrl-section-header">
              <Activity size={20} color="#8b5cf6" />
              <h2>Recent Host Prevention Actions</h2>
            </div>
            <div className="table-scroll-container">
              <table>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Device</th>
                    <th>Risk Level</th>
                    <th>Activity</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {hostLogs.map((log, i) => (
                    <tr key={i}>
                      <td>{log.timestamp ? new Date(log.timestamp).toLocaleString() : "—"}</td>
                      <td>{log.host_name || log.agent_id || "—"}</td>
                      <td>
                        <span className={`ctrl-level-badge ${(log.decision_level || "").toLowerCase()}`}>
                          {log.decision_level || "—"}
                        </span>
                      </td>
                      <td>{log.activity_type || "—"}</td>
                      <td style={{ fontSize: "0.8rem" }}>{log.action_taken || "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Custom Confirmation Modal */}
        {confirmModal.show && (
          <div style={{
            position: "fixed", inset: 0, zIndex: 9999,
            background: "rgba(0,0,0,0.7)", backdropFilter: "blur(4px)",
            display: "flex", justifyContent: "center", alignItems: "center",
            animation: "fadeIn 0.2s ease",
          }}>
            <div style={{
              background: "#1a1a2e", border: "1px solid rgba(239,68,68,0.3)",
              borderRadius: "16px", padding: "32px", maxWidth: "440px", width: "90%",
              boxShadow: "0 20px 60px rgba(0,0,0,0.5), 0 0 40px rgba(239,68,68,0.1)",
              animation: "scaleIn 0.25s ease",
            }}>
              <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "16px" }}>
                <div style={{
                  width: "40px", height: "40px", borderRadius: "12px",
                  background: "rgba(239,68,68,0.15)", display: "flex",
                  alignItems: "center", justifyContent: "center",
                }}>
                  <AlertTriangle size={22} color="#ef4444" />
                </div>
                <h3 style={{ margin: 0, fontSize: "1.1rem", color: "#f8fafc" }}>{confirmModal.title}</h3>
              </div>
              <p style={{ color: "#94a3b8", fontSize: "0.9rem", lineHeight: 1.6, marginBottom: "24px" }}>
                {confirmModal.message}
              </p>
              <div style={{ display: "flex", gap: "12px", justifyContent: "flex-end" }}>
                <button onClick={closeConfirm} style={{
                  padding: "10px 20px", borderRadius: "8px", border: "1px solid #334155",
                  background: "transparent", color: "#94a3b8", cursor: "pointer",
                  fontSize: "0.85rem", transition: "all 0.2s",
                }}>Cancel</button>
                <button onClick={confirmModal.onConfirm} style={{
                  padding: "10px 20px", borderRadius: "8px", border: "none",
                  background: "linear-gradient(135deg, #ef4444, #dc2626)", color: "#fff",
                  cursor: "pointer", fontSize: "0.85rem", fontWeight: 600,
                  transition: "all 0.2s", boxShadow: "0 4px 12px rgba(239,68,68,0.3)",
                }}>Confirm</button>
              </div>
            </div>
          </div>
        )}

        {/* Toast Notification */}
        {toast.show && (
          <div style={{
            position: "fixed", bottom: "24px", right: "24px", zIndex: 10000,
            background: "#1a1a2e", border: "1px solid rgba(34,197,94,0.3)",
            borderRadius: "12px", padding: "14px 24px",
            boxShadow: "0 8px 32px rgba(0,0,0,0.4)",
            color: "#e2e8f0", fontSize: "0.9rem", fontWeight: 500,
            animation: "fadeSlideIn 0.3s ease",
          }}>
            {toast.message}
          </div>
        )}

      </div>
    </div>
  );
}
