import React, { useState, useEffect, useCallback } from "react";
import { useNavigate } from "react-router-dom";
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
  ArrowLeft,
} from "lucide-react";

export default function Controls() {
  const navigate = useNavigate();

  /* ── State ── */
  const [threshold, setThreshold] = useState(0.7);
  const [thresholdInput, setThresholdInput] = useState("0.70");
  const [classThreshold, setClassThreshold] = useState(0.5);
  const [classThresholdInput, setClassThresholdInput] = useState("0.50");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [prevention, setPrevention] = useState({ enabled: false, blocked_ips: [] });
  const [displayMode, setDisplayMode] = useState("full"); // "binary" | "full"
  const [archives, setArchives] = useState([]);
  const [showArchives, setShowArchives] = useState(false);
  const [archiveData, setArchiveData] = useState(null);
  const [archiveFilename, setArchiveFilename] = useState("");
  const [saving, setSaving] = useState(false);

  /* ── Fetch ── */
  const fetchData = useCallback(async () => {
    try {
      const [threshRes, prevRes] = await Promise.all([
        fetch(`${API_BASE}/api/network/threshold`),
        fetch(`${API_BASE}/api/network/prevention`),
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

  /* ── Render ── */
  return (
    <div className="dashboard">
      <Sidebar activePage="controls" prevention={prevention} />
      <div className="main-content">

        {/* Header */}
        <div style={{ display: "flex", alignItems: "center", gap: "12px", marginBottom: "28px" }}>
          <button onClick={() => navigate("/network")} className="ctrl-back-btn">
            <ArrowLeft size={16} />
          </button>
          <Settings size={32} color="#3b82f6" />
          <div>
            <h1 style={{ margin: 0, fontSize: "1.4rem" }}>IDS/IPS Controls</h1>
            <p style={{ margin: 0, color: "#6b7280", fontSize: "0.8rem" }}>
              Configure detection thresholds, prevention and display settings
            </p>
          </div>
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

      </div>
    </div>
  );
}
