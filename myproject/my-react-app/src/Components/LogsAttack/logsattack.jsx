import React from 'react';
import Sidebar from "../Sidebar/Sidebar";
import { useNavigate } from 'react-router-dom';

export default function Logsattack() {
  const navigate = useNavigate();

  // Mock logs with full details
  const fakeLogs = [
    {
      id: "LOG-001",
      type: "DDoS Attack",
      time: "2026-03-04 14:32:15",
      source: "192.168.1.105",
      destination: "10.0.0.1",
      connection: "Online",
      action: "Traffic Dropped",
      status: "Blocked"
    },
    {
      id: "LOG-002",
      type: "Malware Detection",
      time: "2026-03-04 13:45:10",
      source: "PC-03",
      destination: "203.0.113.100",
      connection: "Offline",
      action: "Connection Reset",
      status: "Detected"
    },
    {
      id: "LOG-003",
      type: "Port Scan",
      time: "2026-03-04 12:22:50",
      source: "10.0.0.45",
      destination: "10.0.0.2",
      connection: "Online",
      action: "IP Blacklisted",
      status: "Blocked"
    },
  ];

  return (
    <div className="dashboard">
      <Sidebar />
      <div className="main-content">
        <div className="icondesign">
          <div className="icons">
            <svg
              xmlns="http://www.w3.org/2000/svg"
              width="50"
              height="50"
              fill="currentColor"
              viewBox="0 0 16 16"
            >
              <path d="M5.338 1.59a61.44 61.44 0 0 0-2.837.856.481.481 0 0 0-.328.39c-.554 4.157.726 7.19 2.253 9.188a10.73 10.73 0 0 0 2.287 2.233c.346.244.652.42.893.533.12.057.218.095.293.118a.55.55 0 0 0 .101.025.55.55 0 0 0 .1-.025c.076-.023.174-.061.294-.118.24-.113.547-.29.893-.533a10.726 10.726 0 0 0 2.287-2.233c1.527-1.997 2.807-5.031 2.253-9.188a.48.48 0 0 0-.328-.39c-.651-.213-1.75-.56-2.837-.856C9.552 1.29 8.531 1.067 8 1.067c-.53 0-1.552.223-2.662.524z"/>
              <path d="M8 5.993c1.664 0 3.007 1.343 3.007 3.007S9.664 12.007 8 12.007 4.993 10.664 4.993 9 6.336 5.993 8 5.993z"/>
            </svg>
          </div>
          <h1>Logs</h1>
        </div>
        

        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Date/Time</th>
              <th>Attack Type</th>
              <th>Source</th>
              <th>Destination</th>
              <th>Connection</th>
              <th>Action Taken</th>
              <th>Status</th>
            </tr>
          </thead>
          <tbody>
            {fakeLogs.map((log) => (
              <tr key={log.id}>
                <td>{log.id}</td>
                <td>{log.time}</td>
                <td>{log.type}</td>
                <td>{log.source}</td>
                <td>{log.destination}</td>
                <td style={{ color: log.connection === "Online" ? "green" : "gray" }}>
                  {log.connection}
                </td>
                <td style={{ color: "red", fontWeight: "bold" }}>{log.action}</td>
                <td>{log.status}</td>
              </tr>
            ))}
          </tbody>
        </table>

        <button className='buttonback' onClick={() => navigate(-1)}>Back</button>
      </div>
    </div>
  );
}