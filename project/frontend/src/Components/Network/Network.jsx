import React from "react";
import Sidebar from "../Sidebar/Sidebar";

export default function Network() {
  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">

        <div className="icondesign">
          <div className="icons">
            <svg xmlns="http://www.w3.org/2000/svg" width="36" height="36" fill="currentColor" viewBox="0 0 16 16">
              <path d="M6.5 9.5a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm-5 0a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm10 0a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0zm5 0a1.5 1.5 0 1 1-3 0 1.5 1.5 0 0 1 3 0z"/>
              <path d="M5 9.5a.5.5 0 0 1 .5-.5h5a.5.5 0 0 1 0 1h-5a.5.5 0 0 1-.5-.5zM1.5 9.5a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1H2a.5.5 0 0 1-.5-.5zm10 0a.5.5 0 0 1 .5-.5h2a.5.5 0 0 1 0 1h-2a.5.5 0 0 1-.5-.5z"/>
            </svg>
          </div>
          <h1>Network Monitoring</h1>
        </div>

        {/* Placeholder Stats */}
        <div className="stats-grid" style={{ gridTemplateColumns: "repeat(4, 1fr)" }}>
          <div className="stat-card">
            <h4>Total Packets</h4>
            <p>0</p>
          </div>
          <div className="stat-card">
            <h4>Active Flows</h4>
            <p>0</p>
          </div>
          <div className="stat-card">
            <h4>Network Alerts</h4>
            <p className="severity-high">0</p>
          </div>
          <div className="stat-card">
            <h4>Blocked IPs</h4>
            <p className="severity-critical">0</p>
          </div>
        </div>

        {/* Placeholder Table */}
        <div className="panel">
          <h3>Network Traffic</h3>
          <table>
            <thead>
              <tr>
                <th>Source IP</th>
                <th>Destination IP</th>
                <th>Protocol</th>
                <th>Flow Duration</th>
                <th>Packets</th>
                <th>Threat</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td colSpan="7" className="empty-logs">
                  Network sensor not active. Deploy the network sensor on the gateway to start monitoring traffic.
                </td>
              </tr>
            </tbody>
          </table>
        </div>

        <div className="panel" style={{ display: "flex", alignItems: "center", gap: "12px" }}>
          <span style={{ fontSize: "1.2rem" }}>⏳</span>
          <span>
            Network IDS (XGBoost): <strong>Coming soon</strong> — Awaiting network sensor deployment
          </span>
        </div>

      </div>
    </div>
  );
}
