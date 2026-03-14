import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import "../Components/Host/Host.css"; 

export default function HostLogs() {
  const { host_name } = useParams(); // يقرأ الاسم من الـ URL
  const [logs, setLogs] = useState([]);
  const navigate = useNavigate();

  useEffect(() => {
    const fetchLogs = () => {
      fetch(`http://localhost:5000/api/alerts`)
        .then((res) => res.json())
        .then((data) => {
          // فلترة التهديدات بناءً على اسم الجهاز المختار فقط
          const filtered = data.filter(
            (log) => (log.host === host_name || log.host_name === host_name)
          );
          setLogs(filtered);
        })
        .catch((err) => console.error("❌ Logs Fetch Error:", err));
    };

    fetchLogs();
    const interval = setInterval(fetchLogs, 5000);
    return () => clearInterval(interval);
  }, [host_name]);

  return (
    <div className="logs-page">
      <div className="header-area">
        <h2>🛡️ Security Logs for: <span className="highlight">{host_name}</span></h2>
        <button className="back-btn" onClick={() => navigate(-1)}>
          ← Back to Monitor
        </button>
      </div>

      <table className="logs-table">
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
                <td className="threat-name">{log.threat || log.threat_type}</td>
                <td>
                  <span className={`sev-tag ${log.severity?.toLowerCase()}`}>
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
                No threats detected for this host. System is secure. ✅
              </td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  );
}