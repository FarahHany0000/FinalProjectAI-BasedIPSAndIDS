import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import Sidebar from "../Components/Sidebar/Sidebar"
import "../Components/Host/host.css"; 

export default function HostLogs() {
  const { host_name } = useParams();
  const [logs, setLogs] = useState([]);
  const navigate = useNavigate();

  const fetchLogs = async () => {
    try {
      // تعديل الرابط للمسار الصحيح في الباك إند
      const res = await fetch(`http://127.0.0.1:5000/api/alerts/${host_name}`);
      if (!res.ok) throw new Error("Server error");
      const data = await res.json();
      setLogs(data);
    } catch (err) {
      console.error("❌ Logs Fetch Error:", err);
    }
  };

  useEffect(() => {
    fetchLogs();
    const interval = setInterval(fetchLogs, 5000); 
    return () => clearInterval(interval);
  }, [host_name]);

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">
        <div className="header-area">
          <h2>🛡️ Security Analysis: <span className="highlight">{host_name}</span></h2>
          <button className="back-btn" onClick={() => navigate(-1)}>← Back</button>
        </div>

        <table className="host-table">
          <thead>
            <tr>
              <th>Detected Threat</th>
              <th>Severity</th>
              <th>Action Taken</th>
              <th>Detection Time</th>
            </tr>
          </thead>
          <tbody>
            {logs.length > 0 ? (
              logs.map((log, i) => (
                <tr key={i} className={`severity-row ${log.severity?.toLowerCase()}`}>
                  <td>{log.threat}</td>
                  <td>
                    <span className={`status-badge ${log.severity?.toLowerCase()}`}>
                      {log.severity}
                    </span>
                  </td>
                  <td>{log.action}</td>
                  <td>{log.time ? new Date(log.time).toLocaleString() : "N/A"}</td>
                </tr>
              ))
            ) : (
              <tr>
                <td colSpan="4" className="empty-logs">
                  ✅ No threats detected for this host. System is secure.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}