import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import "./host.css";

export default function Host() {
  const [hosts, setHosts] = useState([]);
  const [selectedHost, setSelectedHost] = useState(null);
  const navigate = useNavigate();

  useEffect(() => {
    const interval = setInterval(() => {
      fetch("http://localhost:5000/api/hosts")
        .then(res => res.ok ? res.json() : [])
        .then(data => setHosts(Array.isArray(data) ? data : []))
        .catch(err => console.error(err));
    }, 3000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div className="dashboard" style={{ display: "flex" }}>
      <Sidebar/>
      <div className="main-content">
        <h1> Host Monitoring</h1>

        <table className="host-table">
          <thead>
            <tr>
              <th>Name</th>
              <th>IP</th>
              <th>Status</th>
              <th>Current Threat</th>
              
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            {hosts.map((h, i) => (
              <tr key={i} className={h.threats !== "None" ? "attack-row" : ""}>
                <td>{h.host_name}</td>
                <td>{h.ip}</td>
                <td className={h.status === "Online" ? "host-online" : "host-offline"}>
                   {h.status}
                </td>
                <td className={h.threats !== "None" ? "attack" : "safe"}>{h.threats}</td>
                <td className={h.action?.includes("Blocked") ? "badge-blocked" : "badge-safe"}>
                  {h.action || "No Action"}
                </td>
               
              </tr>
            ))}
          </tbody>
        </table>

        <button className="logs-btn" style={{ marginTop: "20px" }}
          onClick={() => navigate("/logs")}>
          Go to Attack Logs
        </button>

        {/* Modal for selected host */}
        {selectedHost && (
          <div className="modal">
            <h2> Attack Analysis: {selectedHost.host_name}</h2>
            <hr />
            <p><strong>Threat Type:</strong> {selectedHost.threats}</p>
            <p><strong>Action Taken:</strong> {selectedHost.action || "No Action"}</p>
            <p><strong>CPU:</strong> {selectedHost.cpu}% | <strong>RAM:</strong> {selectedHost.memory}%</p>
            <p><strong>Additional Info:</strong> {selectedHost.info || "N/A"}</p>
            <button onClick={() => setSelectedHost(null)}>Close</button>
          </div>
        )}
      </div>
    </div>
  );
}