import React, { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom"; // useParams للحصول على host_id أو host_name
import Sidebar from "../Components/Sidebar/Sidebar";
import "../Components/Host/Host.css";

export default function HostLogs() {
  const [logs, setLogs] = useState([]);
  const [selectedLog, setSelectedLog] = useState(null);
  const navigate = useNavigate();
  const { hostName } = useParams(); // host_name أو host_id يتم تمريره من Host page

  useEffect(() => {
    fetch(`http://localhost:5000/api/hosts/logs/${hostName}`) // backend route: get all attacks for this host
      .then(res => res.json())
      .then(data => {
        const hostLogs = data.filter(log => log.threats !== "None");
        setLogs(hostLogs);
      })
      .catch(err => console.error(err));
  }, [hostName]);

  return (
    <div className="dashboard" style={{ display: "flex" }}>
      <Sidebar />
      <div className="main-content">
        <h1>📜 Attack Logs for {hostName}</h1>
        <p>All attacks detected on this host in the last 24h.</p>

        <button 
          className="logs-btn" 
          style={{ marginBottom: "20px" }} 
          onClick={() => navigate("/host")} 
        >
          ⬅ Back to Hosts
        </button>

        <table className="host-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Timestamp</th>
              <th>IP Address</th>
              <th>Attack Type</th>
              <th>Action Taken</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            {logs.map((log, i) => (
              <tr key={i} className="attack-row">
                <td>{log.id || i+1}</td>
                <td>{new Date(log.timestamp).toLocaleString()}</td>
                <td>{log.ip}</td>
                <td>{log.threats}</td>
                <td className={log.action?.includes("Blocked") ? "badge-blocked" : "badge-safe"}>
                  {log.action || "No Action"}
                </td>
                <td>
                  <button onClick={() => setSelectedLog(log)}>Attack Details</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {logs.length === 0 && (
          <p style={{ textAlign: "center", marginTop: "20px" }}>
            No attacks detected for this host in last 24h.
          </p>
        )}

        {/* Modal for log details */}
        {selectedLog && (
          <div className="modal">
            <h2>⚠️ Attack Details: {selectedLog.host_name}</h2>
            <hr />
            <p><strong>ID:</strong> {selectedLog.id || "N/A"}</p>
            <p><strong>Timestamp:</strong> {new Date(selectedLog.timestamp).toLocaleString()}</p>
            <p><strong>Attack Type:</strong> {selectedLog.threats}</p>
            <p><strong>Action Taken:</strong> {selectedLog.action || "No Action"}</p>
            <p><strong>CPU Usage:</strong> {selectedLog.cpu}%</p>
            <p><strong>RAM Usage:</strong> {selectedLog.memory}%</p>
            <p><strong>Disk Usage:</strong> {selectedLog.disk}%</p>
            <p><strong>Connections:</strong> {selectedLog.connections}</p>
            <p><strong>Additional Info:</strong> {selectedLog.info || "N/A"}</p>
            <button onClick={() => setSelectedLog(null)}>Close</button>
          </div>
        )}
      </div>
    </div>
  );
}