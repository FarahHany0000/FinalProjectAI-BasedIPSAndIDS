import React, { useState, useEffect, useCallback } from "react";
import Sidebar from "../Sidebar/Sidebar";
import socket from "../../socket";
import API_BASE from "../../config";
import {
  SlidersHorizontal,
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
} from "lucide-react";

export default function Controls() {

  /* ── State ── */
  const [threshold, setThreshold] = useState(0.7);
  const [thresholdInput, setThresholdInput] = useState("0.70");
  const [classThreshold, setClassThreshold] = useState(0.5);
  const [classThresholdInput, setClassThresholdInput] = useState("0.50");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [prevention, setPrevention] = useState({ enabled: false, blocked_ips: [] });
  const [displayMode, setDisplayMode] = useState("full");
  const [archives, setArchives] = useState([]);
  const [showArchives, setShowArchives] = useState(false);
  const [archiveData, setArchiveData] = useState(null);
  const [archiveFilename, setArchiveFilename] = useState("");
  const [saving, setSaving] = useState(false);

  // Host Prevention State
  const [hostPrevention, setHostPrevention] = useState(null);
  const [hostThresholds, setHostThresholds] = useState({ low: "0.50", medium: "0.70", critical: "0.90" });
  const [hostSaving, setHostSaving] = useState(false);
  const [hostLogs, setHostLogs] = useState([]);

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
        setThresholdInput(t.threshold.toFixed(2));
        if (t.classification_threshold !== undefined) {
          setClassThreshold(t.classification_threshold);
          setClassThresholdInput(t.classification_threshold.toFixed(2));
        }
        if (t.display_mode) setDisplayMode(t.display_mode);
      }
      if (prevRes.ok) setPrevention(await prevRes.json());
      if (hostPrevRes.ok) {
        const hp = await hostPrevRes.json();
        setHostPrevention(hp);
        if (hp.thresholds) {
          setHostThresholds({
            low: hp.thresholds.low?.toFixed(2) || "0.50",
            medium: hp.thresholds.medium?.toFixed(2) || "0.70",
            critical: hp.thresholds.critical?.toFixed(2) || "0.90",
          });
        }
      }
      if (hostLogsRes.ok) setHostLogs(await hostLogsRes.json());
    } catch (err) {
      console.error("Controls fetch error:", err);
    }
  }, []);

  useEffect(() => {
    fetchData();
    socket.on("config_update", (config) => {
      if (config.threshold !== undefined) {
        setThreshold(config.threshold);
        setThresholdInput(config.threshold.toFixed(2));
      }
      if (config.classification_threshold !== undefined) {
        setClassThreshold(config.classification_threshold);
        setClassThresholdInput(config.classification_threshold.toFixed(2));
      }
      if (config.prevention_enabled !== undefined || config.blocked_ips !== undefined) {
        setPrevention((prev) => ({ ...prev, ...config }));
      }
      if (config.display_mode) setDisplayMode(config.display_mode);
    });
    return () => socket.off("config_update");
  }, [fetchData]);

  /* ── Actions ── */
  const applyThresholds = async () => {
    const val1 = parseFloat(thresholdInput);
    const val2 = parseFloat(classThresholdInput);
    if (isNaN(val1) || val1 < 0 || val1 > 1) return;
    if (isNaN(val2) || val2 < 0 || val2 > 1) return;
    setSaving(true);
    try {
      await fetch(`${API_BASE}/api/network/threshold`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          threshold: val1,
          classification_threshold: val2,
          display_mode: displayMode,
        }),
      });
      setThreshold(val1);
      setClassThreshold(val2);
    } catch (err) {
      console.error("Threshold error:", err);
    }
    setTimeout(() => setSaving(false), 600);
  };

  const togglePrevention = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/network/prevention`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ enabled: !prevention.enabled }),
      });
      if (res.ok) setPrevention(await res.json());
    } catch (err) {
      console.error("Prevention error:", err);
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
    } catch (err) {
      console.error("Unblock error:", err);
    }
  };

  const resetPrevention = async () => {
    if (!window.confirm("Remove ALL firewall rules and disable IPS?")) return;
    try {
      const res = await fetch(`${API_BASE}/api/network/prevention/reset`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });
      if (res.ok) fetchData();
    } catch (err) {
      console.error("Reset error:", err);
    }
  };

  const archiveAlerts = async () => {
    if (!window.confirm("Archive all current alerts and start fresh?")) return;
    try {
      const res = await fetch(`${API_BASE}/api/alerts/archive`, { method: "POST" });
      if (res.ok) {
        const data = await res.json();
        alert(`Archived ${data.archived} alerts`);
        fetchArchives();
      }
    } catch (err) {
      console.error("Archive error:", err);
    }
  };

  const fetchArchives = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/archives`);
      if (res.ok) setArchives(await res.json());
    } catch (err) {
      console.error("Archives error:", err);
    }
  };

  const loadArchive = async (filename) => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/archives/${filename}`);
      if (res.ok) {
        setArchiveData(await res.json());
        setArchiveFilename(filename);
      }
    } catch (err) {
      console.error("Load archive error:", err);
    }
  };

  const applyHostThresholds = async () => {
    const low = parseFloat(hostThresholds.low);
    const medium = parseFloat(hostThresholds.medium);
    const critical = parseFloat(hostThresholds.critical);
    if (isNaN(low) || isNaN(medium) || isNaN(critical)) return;
    if (!(0 <= low && low < medium && medium < critical && critical <= 1)) {
      alert("Thresholds must be: 0 ≤ Low < Medium < Critical ≤ 1");
      return;
    }
    setHostSaving(true);
    try {
      await fetch(`${API_BASE}/api/prevention/thresholds`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ low, medium, critical }),
      });
      fetchData();
    } catch (err) {
      console.error("Host threshold error:", err);
    }
    setTimeout(() => setHostSaving(false), 600);
  };

  /* ── Render ── */
  return (
    <div className="dashboard">
      <Sidebar prevention={prevention} />
      <div className="main-content">

        {/* Header */}
        <div className="icondesign">
          <div className="icons"><Settings size={36} /></div>
          <h1>Controls</h1>
        </div>
        <p className="page-description">Configure detection, prevention, and display settings for both Network and Host systems.</p>

        {/* ═══ NETWORK SECTION ═══ */}
        <div className="ctrl-section-divider">
          <ShieldCheck size={18} /> Network Protection (IPS)
        </div>

        {/* ── Cards Grid ── */}
        <div className="ctrl-grid">

          {/* Card 1: IPS Prevention */}
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              {prevention.enabled ? <ShieldCheck size={20} color="#22c55e" /> : <ShieldOff size={20} color="#6b7280" />}
              <h3>Intrusion Prevention (IPS)</h3>
            </div>
            <p className="ctrl-desc">
              {prevention.enabled
                ? "IPS is active. IPs triggering 5+ alerts in 60s are auto-blocked via Windows Firewall."
                : "IPS is disabled. Attacks are detected but not blocked."}
            </p>
            <button
              className={`ctrl-toggle-btn ${prevention.enabled ? "active" : ""}`}
              onClick={togglePrevention}
            >
              <span className={`ctrl-toggle-dot ${prevention.enabled ? "on" : ""}`} />
              {prevention.enabled ? "Enabled" : "Disabled"}
            </button>
          </div>

          {/* Card 2: Display Mode */}
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

          {/* Card 3: Quick Actions */}
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              <Trash2 size={20} color="#9ca3af" />
              <h3>Quick Actions</h3>
            </div>
            <div className="ctrl-actions">
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
          </div>
        </div>

        {/* ── Detection Thresholds ── */}
        <div className="ctrl-section">
          <div className="ctrl-section-header">
            <SlidersHorizontal size={20} color="#3b82f6" />
            <h2>Detection Thresholds</h2>
          </div>

          {/* Stage 1 */}
          <div className="ctrl-slider-group">
            <div className="ctrl-slider-label">
              <span>Stage 1 — Attack Detection (Binary Model)</span>
              <span className="ctrl-slider-value" style={{ color: "#3b82f6" }}>
                {threshold.toFixed(2)}
              </span>
            </div>
            <div className="ctrl-slider-row">
              <input type="range" min="0.1" max="1.0" step="0.05"
                value={thresholdInput}
                onChange={(e) => setThresholdInput(e.target.value)}
                className="ctrl-range blue"
              />
              <input type="number" min="0.1" max="1.0" step="0.05"
                value={thresholdInput}
                onChange={(e) => setThresholdInput(e.target.value)}
                className="ctrl-number-input"
              />
            </div>
            <p className="ctrl-hint">Minimum confidence to classify traffic as an attack. Higher = fewer false positives.</p>
          </div>

          {/* Advanced Toggle */}
          <button className="ctrl-advanced-toggle" onClick={() => setShowAdvanced(!showAdvanced)}>
            <Settings size={14} />
            Advanced Settings
            {showAdvanced ? <ChevronUp size={14} /> : <ChevronDown size={14} />}
          </button>

          {/* Stage 2 */}
          {showAdvanced && (
            <div className="ctrl-slider-group advanced">
              <div className="ctrl-slider-label">
                <span>Stage 2 — Attack Type Confidence (Classification Model)</span>
                <span className="ctrl-slider-value" style={{ color: "#f97316" }}>
                  {classThreshold.toFixed(2)}
                </span>
              </div>
              <div className="ctrl-slider-row">
                <input type="range" min="0.1" max="1.0" step="0.05"
                  value={classThresholdInput}
                  onChange={(e) => setClassThresholdInput(e.target.value)}
                  className="ctrl-range orange"
                />
                <input type="number" min="0.1" max="1.0" step="0.05"
                  value={classThresholdInput}
                  onChange={(e) => setClassThresholdInput(e.target.value)}
                  className="ctrl-number-input"
                />
              </div>
              <p className="ctrl-hint">Minimum confidence for attack type classification. Below this threshold, the attack is labeled as detected but type is unknown.</p>
            </div>
          )}

          {/* Apply Button */}
          <button className={`ctrl-apply-btn ${saving ? "saved" : ""}`} onClick={applyThresholds}>
            {saving ? "Saved" : "Apply Settings"}
          </button>
        </div>

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

        {/* ═══ HOST SECTION ═══ */}
        <div className="ctrl-section-divider">
          <Monitor size={18} /> Host Protection (Insider Threat)
        </div>

        {/* Host Prevention Toggle + Status */}
        <div className="ctrl-grid">
          <div className="ctrl-card">
            <div className="ctrl-card-header">
              {hostPrevention?.test_mode === false
                ? <ShieldCheck size={20} color="#22c55e" />
                : <ShieldOff size={20} color="#6b7280" />}
              <h3>Host Prevention Mode</h3>
            </div>
            <p className="ctrl-desc">
              {hostPrevention?.test_mode === false
                ? "LIVE MODE — Suspicious activity on host devices will trigger real OS-level actions (process kill, file lock, etc.)"
                : "TEST MODE — Suspicious activity is logged but no real actions are taken. Safe for testing."}
            </p>
            <div className="ctrl-mode-switch">
              <button
                className={`ctrl-mode-btn ${hostPrevention?.test_mode !== false ? "selected" : ""}`}
                onClick={async () => {
                  try {
                    await fetch(`${API_BASE}/api/prevention/thresholds`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ test_mode: true }),
                    });
                    fetchData();
                  } catch (e) { console.error(e); }
                }}
              >
                <EyeOff size={14} /> Test Mode
              </button>
              <button
                className={`ctrl-mode-btn ${hostPrevention?.test_mode === false ? "selected" : ""}`}
                onClick={async () => {
                  if (!window.confirm("⚠️ Enable LIVE mode? This will execute real prevention actions on host devices.")) return;
                  try {
                    await fetch(`${API_BASE}/api/prevention/thresholds`, {
                      method: "POST",
                      headers: { "Content-Type": "application/json" },
                      body: JSON.stringify({ test_mode: false }),
                    });
                    fetchData();
                  } catch (e) { console.error(e); }
                }}
              >
                <ShieldCheck size={14} /> Live Mode
              </button>
            </div>
          </div>

          <div className="ctrl-card">
            <div className="ctrl-card-header">
              <Activity size={20} color="#3b82f6" />
              <h3>Host Prevention Status</h3>
            </div>
            <div className="ctrl-host-stats">
              <div className="ctrl-host-stat">
                <span className="ctrl-host-stat-num">{hostPrevention?.total_actions || 0}</span>
                <span className="ctrl-host-stat-label">Total Actions</span>
              </div>
              <div className="ctrl-host-stat">
                <span className="ctrl-host-stat-num" style={{ color: "#f59e0b" }}>{hostPrevention?.active_blocks || 0}</span>
                <span className="ctrl-host-stat-label">Active Blocks</span>
              </div>
            </div>
          </div>
        </div>

        {/* Host Threat Thresholds */}
        <div className="ctrl-section">
          <div className="ctrl-section-header">
            <SlidersHorizontal size={20} color="#8b5cf6" />
            <h2>Host Threat Thresholds</h2>
          </div>
          <p className="ctrl-hint" style={{ marginBottom: 16 }}>
            When a device's risk score crosses these levels, different prevention actions are triggered.
          </p>

          <div className="ctrl-slider-group">
            <div className="ctrl-slider-label">
              <span>🟡 Low Risk — Log & Monitor</span>
              <span className="ctrl-slider-value" style={{ color: "#f59e0b" }}>{hostThresholds.low}</span>
            </div>
            <div className="ctrl-slider-row">
              <input type="range" min="0.1" max="0.6" step="0.05"
                value={hostThresholds.low}
                onChange={(e) => setHostThresholds(t => ({ ...t, low: e.target.value }))}
                className="ctrl-range yellow" />
              <input type="number" min="0.1" max="0.6" step="0.05"
                value={hostThresholds.low}
                onChange={(e) => setHostThresholds(t => ({ ...t, low: e.target.value }))}
                className="ctrl-number-input" />
            </div>
          </div>

          <div className="ctrl-slider-group">
            <div className="ctrl-slider-label">
              <span>🟠 Medium Risk — Restrict Access</span>
              <span className="ctrl-slider-value" style={{ color: "#f97316" }}>{hostThresholds.medium}</span>
            </div>
            <div className="ctrl-slider-row">
              <input type="range" min="0.4" max="0.85" step="0.05"
                value={hostThresholds.medium}
                onChange={(e) => setHostThresholds(t => ({ ...t, medium: e.target.value }))}
                className="ctrl-range orange" />
              <input type="number" min="0.4" max="0.85" step="0.05"
                value={hostThresholds.medium}
                onChange={(e) => setHostThresholds(t => ({ ...t, medium: e.target.value }))}
                className="ctrl-number-input" />
            </div>
          </div>

          <div className="ctrl-slider-group">
            <div className="ctrl-slider-label">
              <span>🔴 Critical Risk — Block & Isolate</span>
              <span className="ctrl-slider-value" style={{ color: "#ef4444" }}>{hostThresholds.critical}</span>
            </div>
            <div className="ctrl-slider-row">
              <input type="range" min="0.7" max="1.0" step="0.05"
                value={hostThresholds.critical}
                onChange={(e) => setHostThresholds(t => ({ ...t, critical: e.target.value }))}
                className="ctrl-range red" />
              <input type="number" min="0.7" max="1.0" step="0.05"
                value={hostThresholds.critical}
                onChange={(e) => setHostThresholds(t => ({ ...t, critical: e.target.value }))}
                className="ctrl-number-input" />
            </div>
          </div>

          <button className={`ctrl-apply-btn ${hostSaving ? "saved" : ""}`} onClick={applyHostThresholds}>
            {hostSaving ? "Saved" : "Apply Host Thresholds"}
          </button>
        </div>

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

      </div>
    </div>
  );
}
