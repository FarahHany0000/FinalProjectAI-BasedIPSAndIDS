import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Sidebar from "../Sidebar/Sidebar";
import API_BASE from "../../config";
import socket from "../../socket";

export default function HostLogs() {
  const { host_name } = useParams();
  const [logs, setLogs] = useState([]);
  const navigate = useNavigate();

  const fetchLogs = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/alerts/${host_name}`);
      if (!res.ok) throw new Error("Server error");
      const data = await res.json();
      setLogs(data);
    } catch (err) {
      console.error("Logs Fetch Error:", err);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);

    socket.on("new_alert", (alert) => {
      if (alert.host_name === host_name) {
        setLogs(prev => [alert, ...prev]);
      }
    });

    return () => {
      clearInterval(interval);
      socket.off("new_alert");
    };
  }, [host_name]);

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">
        <div className="header-area">
          <h2>Security Analysis: <span className="highlight">{host_name}</span></h2>
          <button className="back-btn" onClick={() => navigate(-1)}>← Back</button>
        </div>

        <table>
          <thead>
            <tr>
              <th>Detected Threat</th>
              <th>Action Taken</th>
              <th>Detection Time</th>
            </tr>
          </thead>
          <tbody>
            {logs.length > 0 ? (
              logs.map((log, i) => (
                <tr key={i}>
                  <td style={{ color: "#ef4444", fontWeight: "bold" }}>{log.threat}</td>
                  <td style={{ color: "#f97316", fontWeight: "bold" }}>{log.action}</td>
                  <td>{log.time ? new Date(log.time).toLocaleString() : "N/A"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="3" className="empty-logs">
                  No threats detected for this host. System is secure.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
